#!/usr/bin/env python3
"""
watch_dns_dynamic.py -- dynamic (pattern-based) DNS bruteforce

Uses AlterX (ProjectDiscovery -- faster than dnsgen/altdns, same tool
family as dnsx/httpx already in use) to generate permutations from
already-known subdomains, resolves with puredns, then filters wildcards
with the same multi-level WildcardDetector used by watch_ns.py and
watch_dns_static.py (cascading per-level checks: *.sub.domain, *.domain,
etc.) -- NOT the single-level TTL+HTTP-hash check this used to have.

That single-level check was swapped out after it produced confirmed false
positives: a nested wildcard on *.ext-apply.qa.indeed.net (a level below
the domain root) wasn't caught by a root-only test, so a completely fake
subdomain resolved and returned the same 403 as the "discovered" ones.

NOTE: verify AlterX's exact flags with `alterx -h` on your server before
trusting this blindly -- CLI flags can differ between versions, same as we
found with x8 and fallparams earlier.

Resumable: --max-minutes stops cleanly, next run picks up the
least-recently-run domain first (DnsBruteStatus.last_dynamic_run).

Robustness (candidate-explosion hardening):
  - known input is validated, de-duplicated, and deterministically capped at
    DYNAMIC_MAX_INPUT_LINES (derived from alterx's own in-memory dedupe
    threshold) so generation cannot explode into the disk-backed regime.
  - alterx runs with stdin=DEVNULL, -silent/-duc, an output -limit, and is
    killed as a process group on timeout; partial output is always discarded.
  - candidate output is streamed (never fully buffered) into the puredns input.
  - per-domain fail-soft: a FAILED/TIMEOUT domain is reported and the run
    continues; the final exit status is non-zero if any domain failed.
  - DNS semantics (patterns, puredns flags, wildcard filtering, persistence)
    are unchanged.

Usage:
  python3 watch_dns_dynamic.py --max-minutes 180
  python3 watch_dns_dynamic.py --filter dell.com --max-minutes 20
"""

import sys
import os
import argparse
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import Subdomains, upsert_subdomain, upsert_lives, upsert_http, mark_dynamic_run, get_feasible_domains_ordered
from utils.common import detect_cdn, normalize_ips
from wildcard_detector import WildcardDetector
from dns_brute_common import (
    log, send_telegram, run_puredns, run_httpx_quick, WORKDIR,
    estimate_minutes, count_lines, require_tool, require_tools, tool_env,
    ToolError, ToolTimeout,
    DYNAMIC_MAX_INPUT_LINES, DYNAMIC_MAX_CANDIDATES,
    bounded_deterministic_sample, is_valid_hostname, stream_valid_candidates,
)

START_TIME = time.time()

# Per-domain alterx ceiling. Unchanged from the original 1800s: this task does
# not lift the timeout, it makes the work fit inside it.
ALTERX_TIMEOUT = 1800


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def _cleanup(*paths):
    """Best-effort removal of transient work files (never raises)."""
    for p in paths:
        try:
            Path(p).unlink(missing_ok=True)
        except Exception as e:
            log(f"Could not remove {p}: {e}")


def _terminate_process_group(proc):
    """SIGTERM then SIGKILL the alterx process group so no orphan keeps writing.

    alterx is spawned with start_new_session=True, so its pid is the group
    leader; killing the group also covers any children it may spawn.
    """
    pgid = None
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, TypeError, OSError):
        pgid = None

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except OSError:
            pass
    try:
        proc.wait(timeout=10)
        return
    except Exception:
        pass

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.wait()
    except Exception:
        pass


def build_known_file(domain, known_file, max_input_lines):
    """Build a deduplicated, validated alterx input file for one domain.

    - streams the Subdomains cursor (no second full copy of the list)
    - drops empty / malformed hostnames (never silently keeps garbage)
    - removes exact duplicate lines while preserving content (no case changes)
    - deterministically caps the input at max_input_lines using an evenly-spaced
      sample of the sorted unique set when the domain is pathologically large

    Returns stats plus the full set of valid known names (used later for the
    new-vs-existing diff, so a capped input never re-reports existing hosts).
    """
    unique = set()
    total = 0
    malformed = 0

    for doc in Subdomains.objects(scope=domain).only("subdomain"):
        total += 1
        name = (doc.subdomain or "").strip()
        if not name or not is_valid_hostname(name):
            malformed += 1
            continue
        unique.add(name)

    ordered = sorted(unique)
    selected = bounded_deterministic_sample(ordered, max_input_lines)
    known_file.write_text("\n".join(selected))

    return {
        "total": total,
        "unique": len(unique),
        "malformed": malformed,
        "duplicates": total - malformed - len(unique),
        "selected": len(selected),
        "truncated": len(unique) > len(selected),
        "names": unique,
    }


def run_alterx(known_subs_file, raw_out_file, candidates_file,
               max_candidates=DYNAMIC_MAX_CANDIDATES, timeout=ALTERX_TIMEOUT):
    """Generate permutations with alterx, then stream a bounded candidate file.

    Contract:
      - input must exist and be non-empty                      -> ToolError
      - alterx killed as a process group on timeout; partial
        raw output + candidate file removed                    -> ToolTimeout
      - non-zero exit discards output                          -> ToolError
      - success streams raw output -> candidates_file (bounded,
        ordered, validated) without reading it all into RAM    -> int count
    """
    alterx_bin = require_tool("alterx")

    known_path = Path(known_subs_file)
    if not known_path.exists() or known_path.stat().st_size == 0:
        raise ToolError(f"alterx input missing or empty: {known_subs_file}")

    known_bytes = known_path.stat().st_size
    known_lines = count_lines(known_subs_file)

    raw_out_path = Path(raw_out_file)
    _cleanup(raw_out_file, candidates_file)

    argv = [
        alterx_bin, "-l", str(known_subs_file), "-o", str(raw_out_file),
        "-silent", "-duc", "-limit", str(max_candidates),
    ]
    log(f"$ {' '.join(argv)}")

    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=tool_env(),
            start_new_session=True,
        )
    except OSError as exc:
        _cleanup(raw_out_file, candidates_file)
        raise ToolError(
            f"alterx execution failed on {known_subs_file}: {exc}"
        ) from exc
    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(proc)
        _cleanup(raw_out_file, candidates_file)
        raise ToolTimeout(
            f"alterx timed out on {known_subs_file} after {timeout}s "
            f"(elapsed {time.monotonic() - started:.1f}s, input {known_bytes} "
            f"bytes / {known_lines} lines); partial output discarded"
        ) from exc

    if proc.returncode != 0:
        _cleanup(raw_out_file, candidates_file)
        tail = (stderr or "").strip().splitlines()
        tail = tail[-1][:300] if tail else "no stderr"
        raise ToolError(
            f"alterx failed on {known_subs_file} "
            f"(exit {proc.returncode}): {tail}"
        )

    if not raw_out_path.exists():
        raise ToolError(
            f"alterx exited 0 on {known_subs_file} but produced no output "
            f"file: {raw_out_file}"
        )

    try:
        count = stream_valid_candidates(raw_out_file, candidates_file, max_candidates)
    except OSError as exc:
        _cleanup(raw_out_file, candidates_file)
        raise ToolError(
            f"failed to write dynamic candidates for {known_subs_file}: {exc}"
        ) from exc
    _cleanup(raw_out_file)
    return count


def resolve_ip_and_store(program_name, domain, new_names):
    """dnsx for IP, then multi-level WildcardDetector (same one watch_ns.py
    and watch_dns_static.py use), then store."""
    import json

    if not new_names:
        return []

    detector = WildcardDetector(domain)
    tmp = WORKDIR / f"dyn_resolve_{domain}_{int(time.time())}.txt"
    tmp.write_text("\n".join(new_names))

    cmd = (
        f'dnsx -l "{tmp}" -silent -a -resp -json -t 10 -rl 30 '
        "-r 8.8.8.8,1.1.1.1,9.9.9.9,208.67.222.222"
    )
    # dnsx confirmation is required: a failed dnsx run must fail the domain,
    # never silently confirm 0 live hosts.
    proc = subprocess.run(["zsh", "-c", cmd], capture_output=True, text=True, env=tool_env())
    tmp.unlink(missing_ok=True)
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()
        tail = tail[-1][:300] if tail else "no stderr"
        raise ToolError(
            f"dnsx resolve failed for {domain} (exit {proc.returncode}): {tail}"
        )

    confirmed = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = obj.get("host") or obj.get("hostname")
        ips = normalize_ips(obj.get("a"))
        ips_set = set(ips)
        if not host or not ips:
            continue

        if detector.is_wildcard(host, ips_set, preserve_private=True):
            log(f"  filtered as wildcard: {host}")
            continue

        upsert_lives({"subdomain": host, "domain": domain, "ips": ips, "cdn": detect_cdn(ips)})
        confirmed.append(host)

    return confirmed


def process_domain(program_name, domain):
    log(f"--- Dynamic bruteforce: {domain} ---")

    known_file = WORKDIR / f"{domain}.known.txt"
    alterx_out = WORKDIR / f"{domain}.alterx.txt"
    candidates_file = WORKDIR / f"{domain}.dynamic.candidates.txt"
    resolved_file = WORKDIR / f"{domain}.dynamic.resolved.txt"

    stats = build_known_file(domain, known_file, DYNAMIC_MAX_INPUT_LINES)
    log(
        f"{domain}: known input total={stats['total']} unique={stats['unique']} "
        f"duplicates={stats['duplicates']} malformed={stats['malformed']} "
        f"selected={stats['selected']}"
        + (" (truncated to safety limit)" if stats["truncated"] else "")
    )

    if stats["selected"] == 0:
        log(f"{domain}: no valid known subdomains yet, skipping (need enum first)")
        _cleanup(known_file)
        return None

    try:
        candidate_count = run_alterx(known_file, alterx_out, candidates_file)
    except Exception:
        _cleanup(known_file, alterx_out, candidates_file)
        raise

    log(f"{domain}: alterx generated {candidate_count} candidates")
    if candidate_count == 0:
        _cleanup(known_file, candidates_file)
        mark_dynamic_run(domain)
        return 0

    eta = estimate_minutes(candidate_count)
    send_telegram(
        f"Now bruteforcing {program_name} ({domain}) [dynamicBF]\n"
        f"Candidates: {candidate_count:,} | ETA: ~{eta} min"
    )

    try:
        resolved_names = run_puredns(candidates_file, resolved_file)
    except Exception:
        _cleanup(known_file, candidates_file, resolved_file)
        raise
    log(f"{domain}: puredns resolved {len(resolved_names)} names")

    # Transient files are large; remove them as soon as they have been read.
    _cleanup(known_file, alterx_out, candidates_file, resolved_file)

    existing = stats["names"]
    new_names = [n for n in resolved_names if n not in existing]
    log(f"{domain}: {len(new_names)} genuinely new subdomains")

    if not new_names:
        mark_dynamic_run(domain)
        send_telegram(
            f"Result -- {program_name} ({domain}) [dynamicBF]\n"
            f"Tested: {candidate_count:,} | Resolved: {len(resolved_names):,} | New: 0"
        )
        return 0

    for name in new_names:
        upsert_subdomain(program_name, name, "dynamicBF")

    confirmed_live = resolve_ip_and_store(program_name, domain, new_names)
    mark_dynamic_run(domain)

    result_lines = [
        f"Result -- {program_name} ({domain}) [dynamicBF]",
        f"Tested: {candidate_count:,} | Resolved: {len(resolved_names):,} | "
        f"New: {len(new_names)} | Confirmed live (post-wildcard-filter): {len(confirmed_live)}",
    ]

    if not confirmed_live:
        send_telegram("\n".join(result_lines))
        return 0

    httpx_results = run_httpx_quick(confirmed_live)
    for r in httpx_results:
        upsert_http({
            "subdomain": r.get("host") or r.get("input"),
            "scope": domain,
            "ips": r.get("a", []),
            "tech": r.get("tech", []),
            "title": r.get("title"),
            "status_code": r.get("status_code"),
            "headers": r.get("header", {}),
            "url": r.get("url"),
            "final_url": r.get("final_url", r.get("url")),
            "favicon": r.get("favicon_md5") or r.get("favicon"),
        })
        result_lines.append(f"  - {r.get('url')} [{r.get('status_code')}] {r.get('title', '')}")

    send_telegram("\n".join(result_lines))
    return len(confirmed_live)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None)
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    domains = get_feasible_domains_ordered("last_dynamic_run")
    if args.filter:
        domains = [(p, d) for p, d in domains if args.filter.lower() in d.lower()]

    log(f"=== Dynamic DNS Bruteforce | {len(domains)} feasible domains | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    if domains:
        domain_list = "\n".join(f"  - {p} -> {d}" for p, d in domains)
        send_telegram(
            f"Starting dynamicBF run\n"
            f"Time budget: {args.max_minutes or 'unlimited'} min\n"
            f"Queued domains ({len(domains)}):\n{domain_list}"
        )
    else:
        send_telegram("dynamicBF run: no feasible domains queued (run watch_dns_precheck.py first)")
        return 0

    # Preflight BEFORE expensive work: alterx, puredns and dnsx are all
    # required for this job. A missing binary aborts the whole run
    # (non-zero exit) instead of misreporting domains as processed.
    require_tools(["alterx", "puredns", "dnsx"])

    outcomes = {"SUCCESS": [], "FAILED": [], "TIMEOUT": [], "SKIPPED": []}
    total_new = 0
    processed = 0

    for index, (program_name, domain) in enumerate(domains):
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            log(f"Time budget hit after {processed} domains -- rest next run")
            outcomes["SKIPPED"].extend(d for _, d in domains[index:])
            break

        # Per-domain fail-soft: one bad domain is marked and the run continues.
        try:
            new_live = process_domain(program_name, domain)
        except ToolTimeout as exc:
            log(f"{domain}: TIMEOUT -- {exc}")
            outcomes["TIMEOUT"].append(domain)
            send_telegram(f"dynamicBF TIMEOUT {program_name} ({domain}): {exc}")
        except Exception as exc:
            log(f"{domain}: FAILED -- {exc}")
            outcomes["FAILED"].append(domain)
            send_telegram(f"dynamicBF FAILED {program_name} ({domain}): {exc}")
        else:
            if new_live is None:
                outcomes["SKIPPED"].append(domain)
            else:
                outcomes["SUCCESS"].append(domain)
                total_new += new_live
        processed += 1

    remaining = len(domains) - processed
    failures = outcomes["FAILED"] + outcomes["TIMEOUT"]
    summary = (
        f"dynamicBF run finished\n"
        f"Domains processed: {processed}/{len(domains)}\n"
        f"Success: {len(outcomes['SUCCESS'])} | Failed: {len(outcomes['FAILED'])} | "
        f"Timeout: {len(outcomes['TIMEOUT'])} | Skipped: {len(outcomes['SKIPPED'])}\n"
        f"New live subdomains: {total_new}\n"
        f"Elapsed: {elapsed_minutes():.1f} min"
    )
    if remaining:
        summary += f"\n{remaining} domains left for next scheduled run"
    if failures:
        summary += "\nFailed/timeout domains: " + ", ".join(failures)

    log(summary)
    send_telegram(summary)
    return len(failures)


if __name__ == "__main__":
    from backend.task_report import mark_finished
    try:
        failures = main()
    except Exception as exc:
        try:
            send_telegram(f"dynamicBF run FAILED: {exc}")
        except Exception:
            pass
        mark_finished("failed", 1)
        raise
    if failures:
        # Fail-soft per domain, but a run with failures must still be visible
        # to systemd/telemetry as a failure (never a green "0 candidates" run).
        mark_finished("failed", 1)
        sys.exit(1)
    mark_finished("success", 0)