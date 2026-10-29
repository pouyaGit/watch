"""Starter Scope Guard — exact-match validation. Copy and adapt per deployment."""
import re
TARGETS = [
    ("dell", "*.dell.com", [("wildcard", "dell.com")]),
    ("trello-api", "api.trello.com", [("exact", "api.trello.com")]),
]
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)
def normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    return h.split("/")[0].split("@")[-1].split(":")[0]
def check(host: str):
    h = normalize_host(host)
    if not h or not _HOST_RE.match(h):
        return "UNKNOWN", None
    for tdir, _label, entries in TARGETS:
        for kind, base in entries:
            if kind == "exact" and h == base:
                return "IN_SCOPE", tdir
            if kind == "wildcard" and h != base and h.endswith("." + base):
                return "IN_SCOPE", tdir
    return "OUT_OF_SCOPE", None
