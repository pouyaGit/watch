#!/usr/bin/env python3
"""Incremental DNS resolution selection for the Watch NS step (EPIC10).

WHY THIS MODULE EXISTS
======================
The NS step (`ns/watch_ns_all.py`) resolves *every* name collected for a scope on
*every* run. That is correct but not sustainable: the `indeed.net` scope reached
206,080 names on 2026-09-24 (+~40,000/day, 201,074 of them daily brute-force),
which needs ~5h of dnsx wall time per night -- and it grows forever. EPIC10 makes
the nightly run resolve only the names that are *eligible*, while guaranteeing
that no new, changed, unresolved or retry-eligible name is ever silently lost.

WHERE THE SELECTION HOOKS IN
============================
`ns/watch_ns_all.py` is pinned read-only by `aec/readonly_manifest.json`, so the
selection cannot live in the caller. It lives in the **unpinned** helper that the
caller already routes every DNS query through: `utils/common.py`
(`_dnsx_chunk_commands` / `run_command_in_zsh_ns`), which sees the bulk
`dnsx -l <file>` command *before* it is chunked and executed. That gives the
required order exactly (EPIC10 SS9):

    all discovered candidates            (the list file the caller wrote)
          -> eligibility filter          (this module)
          -> deduplicate
          -> chunk <= NS_DNSX_CHUNK_SIZE (utils/common.py, unchanged)
          -> dnsx

The pinned caller, its print format, its wildcard filtering and its persistence
(`upsert_lives`) are untouched: the selector only decides *which names are put in
front of dnsx*.

ELIGIBILITY STATES (deterministic, precedence high -> low)
==========================================================
INVALID         the name cannot be a DNS name (empty, whitespace, `*`, no dot,
                bad label, >253 chars, non-lowercase). Never queried, never
                marked resolved, always reported with a reason.
FORCE           policy.force is set: every valid name is selected regardless of
                freshness/retry state. Still chunked, still wildcard-filtered,
                still timeout-bounded.
NEW             no successful resolution on record (`LiveSubdomains` row absent)
                and no previous attempt. Eligible -- this is the discovery
                guarantee of EPIC10 SS4.
CHANGED         a successful resolution exists, but the discovery record changed
                after it (`Subdomains.last_update > LiveSubdomains.last_update`),
                i.e. a new provider/source was merged for that name. Eligible.
RETRY_ELIGIBLE  no successful resolution, at least one previous attempt, and the
                retry backoff for the current failure streak has elapsed.
RETRY_BACKOFF   no successful resolution, previous attempt(s), backoff not yet
                elapsed. Deferred, NOT suppressed: reported with the next retry
                time. (Extension to the SS2 vocabulary -- the mission lists the
                categories "at minimum".)
STALE           a successful resolution exists, unchanged, and is at least
                `freshness_hours` old. Eligible for revalidation.
FRESH           a successful resolution exists, unchanged, and is younger than
                `freshness_hours`. Intentionally not queried this run.

FRESH is not "deleted" and not "unresolved": the `LiveSubdomains` row (IPs, CDN,
timestamps) is left exactly as it is, so every downstream stage -- the HTTP stage
reads `LiveSubdomains.objects(scope=..., cdn__ne="Internal")` -- keeps seeing the
name as live. Only the DNS *query* is skipped.

CONFIGURATION (environment, all optional; no .env change required)
=================================================================
DNS_RESOLUTION_ENABLED          default "true"; "false" restores pre-EPIC10
                                behavior (resolve everything, no state reads).
DNS_RESOLUTION_FRESHNESS_HOURS  default 12 (see below).
DNS_RETRY_BACKOFF_HOURS         default 12 (single rung). Comma-separated ladder,
                                e.g. "12,72,168" -> 12h, then 3d, then 7d.
DNS_RESOLUTION_FORCE            default "false"; "true" = full re-resolution.
DNS_RESOLUTION_STATE_FILE       default ai_data/dns/incremental_state.json.

DEFAULT POLICY AND WHY (EPIC10 SS3/SS7 allow "preserve current behavior as the
safe default" when no reduction default can be justified; these defaults do not
invent a hidden policy):
  * freshness 12h -- derived from the project's existing 12h recency convention
    (`app.py` treats `last_update >= now-12h` as "recently updated"). The nightly
    runs are ~24h apart, so a name resolved in last night's run is >= 12h old at
    tonight's run and is revalidated as STALE: **nightly coverage is unchanged**.
    What the window does buy is duplicate-run protection -- a second pipeline run
    (manual, retried, or a lock miss) inside 12h does not redo the whole scope.
    Reduction ladders (24/48/72h) are documented with measured projections.
  * retry ladder 12h -- same reasoning: a name that failed tonight is retried on
    tomorrow's run (>= 12h later), so nightly retry coverage is unchanged, while a
    duplicate run within 12h does not hammer resolvers with the failing names.
    Longer ladders are the documented lever for real work reduction.

FAIL-CLOSED (EPIC10 SS11)
=========================
Any failure while *reading* prior state -- unreadable/corrupt state file, Mongo
unavailable, bad policy -- raises `DnsSelectionError` and aborts the DNS step.
There is deliberately **no** fallback to "all names eligible": a selector error
must never turn into another full-scope 206k run. The caller's `finally` blocks
still clean up temp files, existing `LiveSubdomains` data is untouched, and the
step exits non-zero, which `run-pipeline.sh` turns into a failed pipeline run.
Failure to *write* post-run bookkeeping is different: it cannot make the current
run's results wrong (the results are already returned), so it is reported and
skipped, and the affected names simply stay NEW/retry-eligible next run.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# --------------------------------------------------------------------------
# Categories
# --------------------------------------------------------------------------

class DnsCategory:
    """The closed eligibility vocabulary. Every candidate gets exactly one."""

    INVALID = "INVALID"
    FORCE = "FORCE"
    NEW = "NEW"
    CHANGED = "CHANGED"
    RETRY_ELIGIBLE = "RETRY_ELIGIBLE"
    RETRY_BACKOFF = "RETRY_BACKOFF"
    STALE = "STALE"
    FRESH = "FRESH"


#: categories that put a name in front of dnsx
ELIGIBLE_CATEGORIES = frozenset({
    DnsCategory.NEW,
    DnsCategory.CHANGED,
    DnsCategory.RETRY_ELIGIBLE,
    DnsCategory.STALE,
    DnsCategory.FORCE,
})

#: categories that keep a name out of this run's dnsx invocation
SKIPPED_CATEGORIES = frozenset({
    DnsCategory.FRESH,
    DnsCategory.RETRY_BACKOFF,
    DnsCategory.INVALID,
})

#: report order (stable output, matches the mission's example block)
CATEGORY_ORDER = (
    DnsCategory.NEW,
    DnsCategory.CHANGED,
    DnsCategory.RETRY_ELIGIBLE,
    DnsCategory.RETRY_BACKOFF,
    DnsCategory.STALE,
    DnsCategory.FRESH,
    DnsCategory.FORCE,
    DnsCategory.INVALID,
)


class DnsSelectionError(Exception):
    """Raised when eligibility cannot be determined. Always fails the DNS step."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

#: A successful resolution younger than this is FRESH (not queried this run).
#: 12h = the project's existing recency convention; the nightly gap is ~24h so
#: nightly coverage is unchanged (see module docstring).
DEFAULT_FRESHNESS_HOURS = 12.0

#: Retry ladder for names that never resolved: after the n-th consecutive
#: unresolved attempt, wait ladder[min(n, len(ladder)) - 1] hours. 12h keeps the
#: nightly retry cadence (runs are ~24h apart) and blocks duplicate-run hammering.
DEFAULT_RETRY_BACKOFF_HOURS: Tuple[float, ...] = (12.0,)

#: Hard bound on recorded attempt entries; oldest entries are evicted first and
#: simply become NEW again (a safe direction: they are re-queried).
MAX_STATE_ENTRIES = 2_000_000

#: Attempt entries for names that are no longer candidates are dropped after this
#: many days (bounds the state file; a dropped entry = NEW = eligible).
STATE_PRUNE_DAYS = 30

STATE_VERSION = 1

#: hostnames per prior-state lookup query. Keeps each Mongo `$in` well inside the
#: 16MB BSON limit and the response bounded (a 206k-name scope is 11 batches).
LOOKUP_BATCH_SIZE = 20000

ENV_ENABLED = "DNS_RESOLUTION_ENABLED"
ENV_FRESHNESS = "DNS_RESOLUTION_FRESHNESS_HOURS"
ENV_RETRY = "DNS_RETRY_BACKOFF_HOURS"
ENV_FORCE = "DNS_RESOLUTION_FORCE"
ENV_STATE_FILE = "DNS_RESOLUTION_STATE_FILE"

DEFAULT_STATE_FILE = os.path.join("ai_data", "dns", "incremental_state.json")

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f", ""}


def env_bool(name: str, default: bool, env: Optional[Mapping[str, str]] = None) -> bool:
    """Parse a boolean environment flag; an unrecognised value is an error."""
    env = os.environ if env is None else env
    raw = env.get(name)
    if raw is None:
        return default
    value = str(raw).strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise DnsSelectionError(
        f"{name} must be a boolean (true/false), got {raw!r}")


def parse_hours_ladder(raw: Optional[str]) -> Tuple[float, ...]:
    """Parse a comma-separated hours ladder ("12,72,168").

    Empty/absent -> the default ladder. A single ``0`` (or an empty item) means
    "no backoff": every unresolved name is retry-eligible on every run, which is
    the pre-EPIC10 behavior and is a supported, explicit configuration.
    """
    if raw is None or str(raw).strip() == "":
        return DEFAULT_RETRY_BACKOFF_HOURS
    rungs: List[float] = []
    for item in str(raw).split(","):
        item = item.strip()
        if not item:
            continue
        try:
            hours = float(item)
        except ValueError:
            raise DnsSelectionError(
                f"{ENV_RETRY} entries must be numbers of hours, got {item!r}")
        if hours < 0:
            raise DnsSelectionError(
                f"{ENV_RETRY} entries must be >= 0, got {item!r}")
        rungs.append(hours)
    if not rungs:
        return DEFAULT_RETRY_BACKOFF_HOURS
    return tuple(rungs)


def parse_hours(raw: Optional[str], default: float, env_name: str) -> float:
    """Parse a non-negative number of hours; absent -> default."""
    if raw is None or str(raw).strip() == "":
        return default
    try:
        hours = float(str(raw).strip())
    except ValueError:
        raise DnsSelectionError(
            f"{env_name} must be a number of hours, got {raw!r}")
    if hours < 0:
        raise DnsSelectionError(f"{env_name} must be >= 0, got {raw!r}")
    return hours


@dataclass(frozen=True)
class DnsResolutionPolicy:
    """Everything that decides eligibility for one run. Deterministic."""

    enabled: bool = True
    freshness_hours: float = DEFAULT_FRESHNESS_HOURS
    retry_backoff_hours: Tuple[float, ...] = DEFAULT_RETRY_BACKOFF_HOURS
    force: bool = False
    state_file: str = DEFAULT_STATE_FILE

    def __post_init__(self):
        # Accept a scalar ("retry_backoff_hours=12") as a one-rung ladder: a
        # malformed policy must never crash mid-classification with a bare
        # TypeError that hides the real fail-closed reason.
        ladder = self.retry_backoff_hours
        if isinstance(ladder, (int, float)):
            object.__setattr__(self, "retry_backoff_hours", (float(ladder),))
        else:
            object.__setattr__(
                self, "retry_backoff_hours",
                tuple(float(h) for h in ladder))

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "DnsResolutionPolicy":
        """Build the policy from the environment (production entry point).

        Raises DnsSelectionError on a malformed value -- a bad policy must fail
        the step, never be silently replaced by a guess.
        """
        env = os.environ if env is None else env
        return cls(
            enabled=env_bool(ENV_ENABLED, True, env),
            freshness_hours=parse_hours(env.get(ENV_FRESHNESS),
                                        DEFAULT_FRESHNESS_HOURS, ENV_FRESHNESS),
            retry_backoff_hours=parse_hours_ladder(env.get(ENV_RETRY)),
            force=env_bool(ENV_FORCE, False, env),
            state_file=(env.get(ENV_STATE_FILE) or DEFAULT_STATE_FILE),
        )

    def backoff_for_streak(self, streak: int) -> float:
        """Hours to wait after ``streak`` consecutive unresolved attempts."""
        if streak <= 0:
            return 0.0
        ladder = self.retry_backoff_hours or (0.0,)
        index = min(streak, len(ladder)) - 1
        return float(ladder[index])

    def describe(self) -> str:
        ladder = ",".join(
            ("%g" % h) for h in self.retry_backoff_hours) or "none"
        return (
            f"enabled={self.enabled} freshness={self.freshness_hours:g}h "
            f"retry_backoff={ladder}h force={self.force}"
        )


# --------------------------------------------------------------------------
# Name validation (INVALID)
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_NAME_LEN = 253


def validate_dns_name(name: object) -> Tuple[bool, str]:
    """Return ``(is_valid, reason)``. Deterministic, no I/O, no DNS.

    Deliberately strict: anything that cannot be a resolvable DNS name is
    INVALID, is never handed to dnsx, and is reported with the exact reason. It
    is never counted as resolved and never removed from the collection.
    """
    if not isinstance(name, str):
        return False, "not_a_string"
    if name == "":
        return False, "empty"
    if name != name.strip():
        return False, "surrounding_whitespace"
    if "*" in name:
        return False, "wildcard"
    if len(name) > _MAX_NAME_LEN:
        return False, "too_long"
    if "." not in name:
        return False, "no_dot"
    if name.lower() != name:
        return False, "not_lowercase"
    for label in name.split("."):
        if not _LABEL_RE.match(label):
            return False, "invalid_label"
    return True, "ok"


# --------------------------------------------------------------------------
# Prior state inputs
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PriorResolution:
    """What the collections know about a name's last successful resolution."""

    last_resolved: Optional[datetime] = None
    source_changed: bool = False
    #: scope the name belongs to; used for the run report only, never for the
    #: verdict (classification is a function of resolution state alone)
    scope: Optional[str] = None

    @property
    def resolved(self) -> bool:
        return self.last_resolved is not None


@dataclass(frozen=True)
class AttemptState:
    """Recorded dnsx attempts for a name that has not resolved (yet)."""

    attempts: int = 0
    streak: int = 0
    last_attempt: Optional[datetime] = None
    last_answer: Optional[datetime] = None


@dataclass(frozen=True)
class Decision:
    """One candidate's verdict. ``reason`` is a closed, loggable vocabulary."""

    name: str
    category: str
    eligible: bool
    reason: str
    age_hours: Optional[float] = None
    next_retry_at: Optional[datetime] = None


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

def classify_dns_candidate(
    name: str,
    *,
    prior: Optional[PriorResolution] = None,
    attempts: Optional[AttemptState] = None,
    policy: DnsResolutionPolicy,
    now: Optional[datetime] = None,
) -> Decision:
    """Classify one candidate. Pure function: same inputs -> same verdict.

    Precedence: INVALID > FORCE > NEW > CHANGED > RETRY_* > STALE > FRESH.
    """
    now = now or datetime.now()
    valid, reason = validate_dns_name(name)
    if not valid:
        return Decision(name, DnsCategory.INVALID, False, f"invalid_{reason}")

    if policy.force:
        return Decision(name, DnsCategory.FORCE, True, "forced")

    prior = prior or PriorResolution()
    attempts = attempts or AttemptState()

    if not prior.resolved:
        if attempts.attempts <= 0:
            return Decision(name, DnsCategory.NEW, True, "never_resolved")
        if attempts.last_attempt is not None:
            wait = policy.backoff_for_streak(attempts.streak)
            next_retry_at = attempts.last_attempt + timedelta(hours=wait)
            if now < next_retry_at:
                return Decision(
                    name, DnsCategory.RETRY_BACKOFF, False,
                    f"retry_backoff_streak_{attempts.streak}",
                    next_retry_at=next_retry_at)
        return Decision(name, DnsCategory.RETRY_ELIGIBLE, True,
                        f"retry_due_streak_{attempts.streak}")

    age_hours = (now - prior.last_resolved).total_seconds() / 3600.0
    if prior.source_changed:
        return Decision(name, DnsCategory.CHANGED, True, "source_changed",
                        age_hours=age_hours)
    if age_hours >= policy.freshness_hours:
        return Decision(name, DnsCategory.STALE, True, "stale_result",
                        age_hours=age_hours)
    return Decision(name, DnsCategory.FRESH, False, "fresh_result",
                    age_hours=age_hours)


# --------------------------------------------------------------------------
# Attempt store (retry bookkeeping)
# --------------------------------------------------------------------------

class DnsAttemptStore:
    """JSON-file store of dnsx attempts for names that have not resolved.

    A file is used because the two collections that hold DNS state
    (`Subdomains`, `LiveSubdomains`) are pinned read-only models and carry no
    attempt history: nothing in the project records "we asked dnsx about this
    name and got nothing", so the retry policy of EPIC10 SS6 has no other home.

    * atomic writes (temp file + ``os.replace``)
    * corrupt/unreadable file -> DnsSelectionError -> the DNS step fails closed
    * missing file -> empty state (every unresolved name is NEW, exactly the
      pre-EPIC10 behavior on a fresh install)
    * bounded: entries for names no longer seen are pruned after
      STATE_PRUNE_DAYS, and the file is capped at MAX_STATE_ENTRIES (oldest
      evicted first -- evicted names simply become NEW again)
    """

    def __init__(self, path: str):
        self.path = path

    # -- io ---------------------------------------------------------------
    def load(self) -> Dict[str, AttemptState]:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError) as exc:
            raise DnsSelectionError(
                f"unreadable DNS attempt state {self.path}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("version") != STATE_VERSION:
            raise DnsSelectionError(
                f"unsupported DNS attempt state schema in {self.path} "
                f"(version={raw.get('version') if isinstance(raw, dict) else None!r}, "
                f"expected {STATE_VERSION})")
        entries = raw.get("attempts")
        if not isinstance(entries, dict):
            raise DnsSelectionError(
                f"DNS attempt state {self.path} has no 'attempts' mapping")
        out: Dict[str, AttemptState] = {}
        for name, item in entries.items():
            if not isinstance(item, dict):
                raise DnsSelectionError(
                    f"DNS attempt state {self.path} entry {name!r} is not a mapping")
            try:
                out[name] = AttemptState(
                    attempts=int(item.get("attempts", 0)),
                    streak=int(item.get("streak", 0)),
                    last_attempt=_parse_iso(item.get("last_attempt")),
                    last_answer=_parse_iso(item.get("last_answer")),
                )
            except (TypeError, ValueError) as exc:
                raise DnsSelectionError(
                    f"DNS attempt state {self.path} entry {name!r} is malformed: "
                    f"{exc}") from exc
        return out

    def save(self, attempts: Mapping[str, AttemptState],
             known_names: Optional[Iterable[str]] = None,
             now: Optional[datetime] = None) -> None:
        """Write the store atomically, pruned and bounded."""
        now = now or datetime.now()
        known = set(known_names) if known_names is not None else None
        cutoff = now - timedelta(days=STATE_PRUNE_DAYS)

        kept: List[Tuple[datetime, str, AttemptState]] = []
        for name, state in attempts.items():
            if state.attempts <= 0:
                continue
            if known is not None and name not in known:
                if state.last_attempt is None or state.last_attempt < cutoff:
                    continue
            stamp = state.last_attempt or now
            kept.append((stamp, name, state))
        kept.sort(key=lambda item: item[0], reverse=True)
        kept = kept[:MAX_STATE_ENTRIES]

        payload = {
            "version": STATE_VERSION,
            "updated_at": now.isoformat(),
            "attempts": {
                name: {
                    "attempts": state.attempts,
                    "streak": state.streak,
                    "last_attempt": _iso(state.last_attempt),
                    "last_answer": _iso(state.last_answer),
                }
                for _, name, state in kept
            },
        }
        directory = os.path.dirname(os.path.abspath(self.path))
        try:
            os.makedirs(directory, exist_ok=True)
            temp_path = f"{self.path}.tmp.{os.getpid()}"
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
            os.replace(temp_path, self.path)
        except OSError as exc:
            raise DnsSelectionError(
                f"cannot write DNS attempt state {self.path}: {exc}") from exc

    # -- bookkeeping ------------------------------------------------------
    def apply_outcomes(
        self,
        queried: Sequence[str],
        answered: Iterable[str],
        previous: Mapping[str, AttemptState],
        now: Optional[datetime] = None,
    ) -> Dict[str, AttemptState]:
        """Return the new attempt map after a run.

        ``answered`` = names dnsx returned a record for. A name that answered is
        no longer "failing" (streak reset); a name that was queried and did not
        answer gets its streak incremented. Names that were not queried keep
        their state untouched -- skipping is never recorded as failure.
        """
        now = now or datetime.now()
        answered_set = set(answered)
        updated: Dict[str, AttemptState] = dict(previous)
        for name in queried:
            old = updated.get(name, AttemptState())
            if name in answered_set:
                updated[name] = AttemptState(
                    attempts=old.attempts + 1,
                    streak=0,
                    last_attempt=now,
                    last_answer=now)
            else:
                updated[name] = AttemptState(
                    attempts=old.attempts + 1,
                    streak=old.streak + 1,
                    last_attempt=now,
                    last_answer=old.last_answer)
        return updated


def _batched(items: Sequence[str], size: int):
    """Yield ``items`` in fixed-size slices (deterministic order preserved)."""
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _parse_iso(value: object) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise TypeError(f"expected ISO timestamp, got {type(value).__name__}")
    return datetime.fromisoformat(value)


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------

@dataclass
class SelectionResult:
    """What the selector decided, plus the numbers the run report needs."""

    candidates: int = 0
    duplicates: int = 0
    invalid: int = 0
    selected: List[str] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    decisions: List[Decision] = field(default_factory=list)
    scope: Optional[str] = None
    selection_seconds: float = 0.0
    skipped_reasons: Dict[str, int] = field(default_factory=dict)
    policy_description: str = ""
    #: non-reporting state needed to record the run's outcome afterwards
    store: Optional["DnsAttemptStore"] = field(default=None, repr=False)
    policy: Optional[DnsResolutionPolicy] = field(default=None, repr=False)
    attempts: Dict[str, "AttemptState"] = field(default_factory=dict, repr=False)

    @property
    def skipped(self) -> int:
        """Every candidate not handed to dnsx (FRESH + RETRY_BACKOFF + INVALID)."""
        return sum(self.counts.get(c, 0) for c in SKIPPED_CATEGORIES)

    @property
    def deferred(self) -> int:
        """Valid candidates deliberately not queried this run.

        Excludes INVALID (which was never a resolvable name): this is the count
        that makes "no valid name was lost" checkable as
        ``len(selected) + deferred == valid_candidates``.
        """
        return sum(self.counts.get(c, 0)
                   for c in SKIPPED_CATEGORIES if c != DnsCategory.INVALID)

    def report_lines(self) -> List[str]:
        lines = ["DNS Resolution (incremental selection)",
                 "-------------------------",
                 f"Candidates:       {self.candidates:>9,}"]
        if self.scope:
            lines.append(f"Scope:            {self.scope}")
        if self.duplicates:
            lines.append(f"Duplicates:       {self.duplicates:>9,}")
        for category in CATEGORY_ORDER:
            count = self.counts.get(category, 0)
            if category == DnsCategory.INVALID and not count:
                continue
            if category in (DnsCategory.RETRY_BACKOFF, DnsCategory.FORCE,
                            DnsCategory.CHANGED) and not count:
                continue
            lines.append(f"{category.title():<17} {count:>9,}")
        lines.append(f"Selected:         {len(self.selected):>9,}")
        lines.append(f"Skipped:          {self.skipped:>9,}")
        if self.skipped_reasons:
            top = sorted(self.skipped_reasons.items(), key=lambda kv: -kv[1])[:6]
            lines.append("Skip reasons:     "
                         + ", ".join(f"{k}={v:,}" for k, v in top))
        lines.append(f"Policy:           {self.policy_description}")
        lines.append(f"Selection time:   {self.selection_seconds:.3f}s")
        return lines


def select_dns_candidates(
    names: Sequence[str],
    *,
    policy: DnsResolutionPolicy,
    prior_lookup: Optional[Callable[[Sequence[str]], Mapping[str, PriorResolution]]] = None,
    store: Optional[DnsAttemptStore] = None,
    now: Optional[datetime] = None,
    reporter: Optional[Callable[[str], None]] = None,
) -> SelectionResult:
    """Decide which of ``names`` go to dnsx this run.

    FAIL-CLOSED: this function never catches an error and never degrades to
    "everything is eligible". A missing prior-state provider, an unreadable
    state file or a Mongo failure raises ``DnsSelectionError``.
    """
    import time

    started = time.monotonic()
    now = now or datetime.now()
    if not policy.enabled:
        raise DnsSelectionError(
            "select_dns_candidates called with selection disabled")

    lookup = prior_lookup or default_prior_lookup()
    attempt_store = store if store is not None else DnsAttemptStore(policy.state_file)

    # 1) candidates -> validated, de-duplicated list (order preserving)
    seen = set()
    unique: List[str] = []
    duplicates = 0
    for name in names:
        key = name.strip() if isinstance(name, str) else name
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(key)

    # 2) prior state (fail-closed: no provider / no DB -> raise)
    try:
        prior_map = dict(lookup(unique)) if unique else {}
    except DnsSelectionError:
        raise
    except Exception as exc:  # noqa: BLE001 - re-raised as the fail-closed error
        raise DnsSelectionError(
            f"prior-resolution lookup failed ({type(exc).__name__}: {exc})") from exc

    attempts_map = attempt_store.load()

    # 3) classify
    result = SelectionResult(
        candidates=len(names),
        duplicates=duplicates,
        policy_description=policy.describe(),
    )
    selected: List[str] = []
    for name in unique:
        decision = classify_dns_candidate(
            name,
            prior=prior_map.get(name),
            attempts=attempts_map.get(name),
            policy=policy,
            now=now,
        )
        result.decisions.append(decision)
        result.counts[decision.category] = result.counts.get(decision.category, 0) + 1
        if decision.category == DnsCategory.INVALID:
            result.invalid += 1
        if decision.eligible:
            selected.append(name)
        else:
            key = decision.category
            result.skipped_reasons[key] = result.skipped_reasons.get(key, 0) + 1

    result.selected = selected
    result.store = attempt_store
    result.policy = policy
    result.attempts = dict(attempts_map)
    for prior in prior_map.values():
        if getattr(prior, "scope", None):
            result.scope = prior.scope
            break
    result.selection_seconds = time.monotonic() - started
    if reporter is not None:
        for line in result.report_lines():
            reporter(line)
    return result


# --------------------------------------------------------------------------
# Production prior-state provider (Mongo)
# --------------------------------------------------------------------------

def mongo_prior_lookup(names: Sequence[str]) -> Dict[str, PriorResolution]:
    """Read prior resolution state for ``names`` from the Watch collections.

    * ``LiveSubdomains.last_update`` = when DNS last answered for the name
      (``upsert_lives`` always refreshes it, so it is the resolution timestamp).
    * ``Subdomains.last_update``     = when the discovery record last changed
      (``upsert_subdomain`` bumps it only when a *new provider* is merged for an
      existing name), so ``Subdomains.last_update > LiveSubdomains.last_update``
      is a real "the input changed after we resolved it" signal -- not an
      unrelated timestamp.

    Raises on any failure; the caller turns that into a fail-closed abort.
    """
    from database.db import LiveSubdomains, Subdomains  # local import: keeps the
    # module importable (and unit-testable) without a live Mongo connection.

    wanted = [n for n in names if isinstance(n, str) and n]
    out: Dict[str, PriorResolution] = {}
    if not wanted:
        return out

    sub_last: Dict[str, datetime] = {}
    sub_scope: Dict[str, str] = {}
    live_last: Dict[str, datetime] = {}
    # Bounded batches: a single `$in` over 206k hostnames is a multi-megabyte
    # query document (Mongo's BSON limit is 16MB) and pins one giant response.
    for batch in _batched(wanted, LOOKUP_BATCH_SIZE):
        for row in (Subdomains.objects(subdomain__in=batch)
                    .only("subdomain", "last_update", "scope")
                    .no_dereference()
                    .timeout(False)):
            current = sub_last.get(row.subdomain)
            if current is None or (row.last_update and row.last_update > current):
                sub_last[row.subdomain] = row.last_update
            if row.scope and row.subdomain not in sub_scope:
                sub_scope[row.subdomain] = row.scope
        for row in (LiveSubdomains.objects(subdomain__in=batch)
                    .only("subdomain", "last_update")
                    .no_dereference()
                    .timeout(False)):
            current = live_last.get(row.subdomain)
            if current is None or (row.last_update and row.last_update > current):
                live_last[row.subdomain] = row.last_update

    for name in wanted:
        resolved_at = live_last.get(name)
        changed = False
        if resolved_at is not None:
            source_at = sub_last.get(name)
            changed = bool(source_at and source_at > resolved_at)
        out[name] = PriorResolution(
            last_resolved=resolved_at,
            source_changed=changed,
            scope=sub_scope.get(name),
        )
    return out


# --------------------------------------------------------------------------
# Injectable providers (production default = Mongo; tests inject fakes)
# --------------------------------------------------------------------------

_prior_lookup_provider: Optional[
    Callable[[Sequence[str]], Mapping[str, PriorResolution]]] = None


def default_prior_lookup() -> Callable[[Sequence[str]], Mapping[str, PriorResolution]]:
    """The provider used when the caller does not inject one (Mongo in prod)."""
    if _prior_lookup_provider is not None:
        return _prior_lookup_provider
    return mongo_prior_lookup


def set_prior_lookup_provider(provider) -> None:
    """Install a prior-state provider (test hook / alternative backends)."""
    global _prior_lookup_provider
    _prior_lookup_provider = provider


def reset_prior_lookup_provider() -> None:
    """Restore the production (Mongo) provider."""
    global _prior_lookup_provider
    _prior_lookup_provider = None


# --------------------------------------------------------------------------
# Hook used by utils/common.py (the unpinned DNS execution path)
# --------------------------------------------------------------------------

@dataclass
class NsRunPlan:
    """Commands to execute for one NS invocation, plus what was selected."""

    commands: List[str] = field(default_factory=list)
    temp_paths: List[str] = field(default_factory=list)
    selection: Optional[SelectionResult] = None
    names: List[str] = field(default_factory=list)
    #: how many invocations actually completed (for the run report)
    chunks_done: int = 0


def selection_for_command(
    names: Sequence[str],
    *,
    policy: Optional[DnsResolutionPolicy] = None,
    prior_lookup: Optional[Callable[[Sequence[str]], Mapping[str, PriorResolution]]] = None,
    store: Optional[DnsAttemptStore] = None,
    now: Optional[datetime] = None,
    reporter: Optional[Callable[[str], None]] = None,
) -> Optional[SelectionResult]:
    """Select candidates for a bulk dnsx invocation.

    Returns ``None`` when incremental selection is switched off
    (``DNS_RESOLUTION_ENABLED=false``), which restores pre-EPIC10 behavior:
    every candidate is queried and no state is read or written.

    Any failure raises ``DnsSelectionError`` -- there is no "assume everything is
    eligible" path (EPIC10 SS11).
    """
    policy = policy or DnsResolutionPolicy.from_env()
    if not policy.enabled:
        return None
    return select_dns_candidates(
        names,
        policy=policy,
        prior_lookup=prior_lookup,
        store=store,
        now=now,
        # the pipeline log is the operator's only view of "why these names and
        # not those" (EPIC10 SS10/SS18), so the production path reports by
        # default; library callers can pass their own reporter.
        reporter=print if reporter is None else reporter,
    )


def answered_hosts(lines: Iterable[str]) -> set:
    """Hostnames dnsx returned a record for (same parse as the pinned caller)."""
    hosts = set()
    for line in lines:
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        host = obj.get("host") or obj.get("hostname")
        if isinstance(host, str) and host:
            hosts.add(host.strip())
    return hosts


def record_run_outcome(
    selection: Optional[SelectionResult],
    lines: Sequence[str],
    *,
    chunks_total: int = 0,
    chunks_done: int = 0,
    dns_seconds: float = 0.0,
    error: Optional[BaseException] = None,
    now: Optional[datetime] = None,
    reporter: Optional[Callable[[str], None]] = None,
) -> None:
    """Record the run's attempt outcomes and print the run report.

    Bookkeeping is deliberately *not* fatal: by the time this runs the DNS
    results already exist and are returned to the caller, so a state-write
    failure cannot make this run's results wrong. It is reported, and the
    affected names simply stay NEW/retry-eligible on the next run (the safe
    direction). Selection-time failures, by contrast, are fail-closed.
    """
    reporter = reporter or print
    if selection is None:
        return
    try:
        _record_run_outcome_inner(
            selection, lines, chunks_total=chunks_total, chunks_done=chunks_done,
            dns_seconds=dns_seconds, error=error, now=now, reporter=reporter)
    except Exception as exc:  # noqa: BLE001
        # Never let bookkeeping/reporting replace the real DNS outcome: this
        # runs in a finally block, so raising here would mask ToolError or
        # ToolTimeout from the run itself.
        try:
            reporter(f"DNS Resolution report unavailable: "
                     f"{type(exc).__name__}: {exc}")
        except Exception:
            pass


def _record_run_outcome_inner(selection, lines, *, chunks_total, chunks_done,
                              dns_seconds, error, now, reporter):
    now = now or datetime.now()
    answered = answered_hosts(lines)
    queried = selection.selected

    try:
        store = selection.store or DnsAttemptStore(
            (selection.policy or DnsResolutionPolicy()).state_file)
        if queried:
            updated = store.apply_outcomes(queried, answered, selection.attempts,
                                           now=now)
            # prune against every candidate seen this run (not just the queried
            # subset) so a deferred name's retry state is never dropped
            store.save(updated,
                       known_names=[d.name for d in selection.decisions],
                       now=now)
            bookkeeping = "ok"
        else:
            # nothing was queried: leave the store exactly as it was (no empty
            # file, no truncation of retry state for deferred names)
            bookkeeping = "unchanged (nothing queried)"
    except Exception as exc:  # noqa: BLE001 - warn, never fail the DNS step here
        bookkeeping = f"FAILED ({type(exc).__name__}: {exc})"

    answered_selected = len(answered & set(queried))
    unresolved = len(queried) - answered_selected
    for line in (
        "DNS Resolution results",
        "-------------------------",
        f"Queried:          {len(queried):>9,}",
        f"Resolved:         {answered_selected:>9,}",
        f"Unresolved:       {unresolved:>9,}",
        f"Chunks:           {chunks_done}/{chunks_total} ok"
        + (f"  FAILED: {error}" if error else ""),
        f"DNS time:         {dns_seconds:.1f}s",
        f"Attempt state:    {bookkeeping}",
    ):
        reporter(line)


