#!/usr/bin/env python3
"""Real-time Certificate Transparency ingestion (passive).

Reads a certstream-compatible websocket and writes in-scope hostnames from
freshly issued certificates to Subdomains with provider "ctstream".

Environment:
  CT_STREAM_URL          websocket source (default wss://certstream.calidog.io/)
  SCOPE_REFRESH_SECONDS  scope hot-reload interval (default 60)
  STATS_EVERY_SECONDS    stats log cadence (default 60)
  CT_STREAM_NOTIFY       1 = Telegram per new subdomain (default 0). Not wired:
                         database.notifications has no per-subdomain helper.
  CT_DEDUP_TTL_SECONDS   in-memory dedup window (default 21600)

Usage:
  python enum/watch_ct_stream.py              run the daemon
  python enum/watch_ct_stream.py --once-test  scope/matcher self-check, no websocket
"""
import sys, os, time, json, threading, signal, argparse
from collections import OrderedDict
from dataclasses import dataclass

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import websocket
from database.db import Programs, upsert_subdomain
from utils.common import current_time, colors

CT_STREAM_URL = os.getenv("CT_STREAM_URL", "wss://certstream.calidog.io/")
SCOPE_REFRESH_SECONDS = int(os.getenv("SCOPE_REFRESH_SECONDS", "60"))
STATS_EVERY_SECONDS = int(os.getenv("STATS_EVERY_SECONDS", "60"))
CT_DEDUP_TTL_SECONDS = int(os.getenv("CT_DEDUP_TTL_SECONDS", "21600"))

DEDUP_MAX_KEYS = 100_000
BACKOFF_MIN = 1
BACKOFF_MAX = 60
FIXTURE = ["x.dell.com", "dell.com", "evil.com", "a.b.delltechnologies.com", "console.dell.com"]

_stats = {"certs_seen": 0, "domains_seen": 0, "in_scope_hits": 0, "ingested": 0, "reconnects": 0}
_stats_lock = threading.Lock()

_index = None
_index_lock = threading.Lock()


def log(message, color=""):
    reset = colors.RESET if color else ""
    print(f"{color}[{current_time()}] {message}{reset}", flush=True)


def _bump(name, amount=1):
    with _stats_lock:
        _stats[name] += amount


def _stats_line(prefix):
    with _stats_lock:
        snapshot = dict(_stats)
    fields = " ".join(f"{key}={value}" for key, value in snapshot.items())
    log(f"{prefix} {fields}", colors.GRAY)


@dataclass(frozen=True)
class ScopeIndex:
    apex_to_program: dict
    ooscope_set: frozenset
    program_count: int


def normalize(name):
    return name.strip().lower().rstrip(".").lstrip("*.")


def build_scope_index():
    apex_to_program = {}
    ooscopes = set()
    programs = list(Programs.objects.order_by("program_name").only("program_name", "scopes", "ooscopes"))
    for program in programs:
        for raw in program.scopes or []:
            apex = normalize(raw)
            if not apex:
                continue
            owner = apex_to_program.get(apex)
            if owner and owner != program.program_name:
                log(f"apex {apex} claimed by {owner} and {program.program_name}; keeping {owner}", colors.YELLOW)
                continue
            apex_to_program[apex] = program.program_name
        for raw in program.ooscopes or []:
            oo = normalize(raw)
            if oo:
                ooscopes.add(oo)
    return ScopeIndex(apex_to_program, frozenset(ooscopes), len(programs))


def _current_index():
    with _index_lock:
        return _index


def _set_index(new_index):
    global _index
    with _index_lock:
        _index = new_index


def _suffixes(name):
    labels = name.split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


def decide(hostname, index):
    """Return (reason, program_name, normalized_name); program_name is set only for reason 'match'."""
    name = normalize(hostname)
    if not name or "." not in name or any(not label for label in name.split(".")):
        return "invalid", None, name
    for suffix in _suffixes(name):
        if suffix in index.ooscope_set:
            return "ooscope", None, name
    if name in index.apex_to_program:
        return "apex", None, name
    for suffix in _suffixes(name):
        program = index.apex_to_program.get(suffix)
        if program:
            return "match", program, name
    return "no-scope", None, name


def match(hostname):
    """Return (program_name, normalized_sub) if in scope & not out-of-scope, else None."""
    reason, program, name = decide(hostname, _current_index())
    return (program, name) if reason == "match" else None


def extract_hostnames(msg):
    leaf = (msg.get("data") or {}).get("leaf_cert") or {}
    domains = leaf.get("all_domains")
    if isinstance(domains, list):
        return [d for d in domains if isinstance(d, str)]
    names = []
    cn = (leaf.get("subject") or {}).get("CN")
    if isinstance(cn, str):
        names.append(cn)
    san = (leaf.get("extensions") or {}).get("subjectAltName")
    if isinstance(san, str):
        for part in san.split(","):
            part = part.strip()
            if part.startswith("DNS:"):
                names.append(part[4:])
    return names


class RecentKeys:
    def __init__(self, ttl, max_keys):
        self._ttl = ttl
        self._max = max_keys
        self._seen = OrderedDict()

    def _prune(self, now):
        cutoff = now - self._ttl
        while self._seen and next(iter(self._seen.values())) < cutoff:
            self._seen.popitem(last=False)

    def is_recent(self, key, now):
        self._prune(now)
        return key in self._seen

    def remember(self, key, now):
        self._seen[key] = now
        self._seen.move_to_end(key)
        while len(self._seen) > self._max:
            self._seen.popitem(last=False)


class CTStream:
    def __init__(self, stop):
        self.stop = stop
        self.recent = RecentKeys(CT_DEDUP_TTL_SECONDS, DEDUP_MAX_KEYS)
        self.backoff = BACKOFF_MIN
        self.ws = None

    def handle(self, _ws, raw):
        if not raw:
            return
        try:
            msg = json.loads(raw)
            if msg.get("message_type") != "certificate_update":
                return
            _bump("certs_seen")
            for hostname in extract_hostnames(msg):
                _bump("domains_seen")
                hit = match(hostname)
                if hit is None:
                    continue
                _bump("in_scope_hits")
                program, sub = hit
                key = (program, sub)
                now = time.monotonic()
                if self.recent.is_recent(key, now):
                    continue
                upsert_subdomain(program, sub, "ctstream")
                self.recent.remember(key, now)
                _bump("ingested")
            self.backoff = BACKOFF_MIN
        except Exception as exc:
            log(f"message error: {exc}", colors.RED)

    def on_error(self, _ws, err):
        log(f"websocket error: {err}", colors.YELLOW)

    def on_open(self, _ws):
        log(f"connected: {CT_STREAM_URL}", colors.GREEN)

    def run(self):
        while not self.stop.is_set():
            try:
                self.ws = websocket.WebSocketApp(
                    CT_STREAM_URL,
                    on_open=self.on_open,
                    on_message=self.handle,
                    on_error=self.on_error,
                )
                self.ws.run_forever(ping_interval=20, ping_timeout=10)
            except Exception as exc:
                log(f"stream loop error: {exc}", colors.RED)
            if self.stop.is_set():
                break
            _bump("reconnects")
            log(f"stream closed; reconnecting in {self.backoff}s", colors.YELLOW)
            self.stop.wait(self.backoff)
            self.backoff = min(self.backoff * 2, BACKOFF_MAX)

    def close(self):
        self.stop.set()
        ws = self.ws
        if ws is not None:
            ws.close()


def _refresh_loop(stop):
    while not stop.wait(SCOPE_REFRESH_SECONDS):
        try:
            new_index = build_scope_index()
        except Exception as exc:
            log(f"scope refresh failed, keeping previous index: {exc}", colors.YELLOW)
            continue
        if new_index != _current_index():
            _set_index(new_index)
            log(f"scope index refreshed: programs={new_index.program_count} "
                f"apexes={len(new_index.apex_to_program)} ooscopes={len(new_index.ooscope_set)}", colors.GREEN)


def _stats_loop(stop):
    while not stop.wait(STATS_EVERY_SECONDS):
        _stats_line("[stats]")


def once_test():
    index = build_scope_index()
    log(f"scope loaded: programs={index.program_count} apexes={len(index.apex_to_program)} "
        f"ooscopes={len(index.ooscope_set)}")
    labels = {"match": "match", "apex": "skip(apex)", "no-scope": "skip(no scope)",
              "ooscope": "skip(ooscope)", "invalid": "skip(invalid)"}
    for hostname in FIXTURE:
        reason, program, name = decide(hostname, index)
        detail = program if reason == "match" else labels[reason]
        log(f"{name} -> {detail}")
    return 0


def run_daemon():
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    _set_index(build_scope_index())
    index = _current_index()
    log(f"scope loaded: programs={index.program_count} apexes={len(index.apex_to_program)} "
        f"ooscopes={len(index.ooscope_set)}", colors.GREEN)

    stream = CTStream(stop)
    workers = [
        threading.Thread(target=stream.run, name="ct-stream", daemon=True),
        threading.Thread(target=_refresh_loop, args=(stop,), name="scope-refresh", daemon=True),
        threading.Thread(target=_stats_loop, args=(stop,), name="stats", daemon=True),
    ]
    for worker in workers:
        worker.start()

    while not stop.is_set():
        time.sleep(0.5)

    stream.close()
    workers[0].join(timeout=10)
    _stats_line("[final]")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Real-time CT subdomain ingestion (passive)")
    parser.add_argument("--once-test", action="store_true",
                        help="build scope index, run matcher on fixtures, exit without a websocket")
    args = parser.parse_args()
    return once_test() if args.once_test else run_daemon()


if __name__ == "__main__":
    sys.exit(main())
