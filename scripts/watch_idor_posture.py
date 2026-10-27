#!/usr/bin/env python3
"""watch_idor_posture.py -- unauthenticated auth-posture test on ID-shaped URLs.

Per hunt-idor: without two accounts the only decidable question is
"does this endpoint serve record data to a caller with no session?"

Three fetches per target, and a 200 only counts if it is record-shaped AND
differs from BOTH controls:
  1. the recorded URL
  2. differential control: same URL, every id value replaced with zq999999999999
  3. catch-all control: a path that cannot exist on that host
No sequential enumeration - only the IDs already recorded in the corpus.
"""
import json
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Programs  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "application/json, text/html;q=0.9,*/*;q=0.8"}
T = 20
BOGUS = "zq999999999999"
IDISH = re.compile(r"(id|uuid|guid|ref)", re.I)
RECORDY = re.compile(r'^\s*[\[{]')          # JSON object/array
ERRWORD = re.compile(r"(unauthoriz|forbidden|access denied|not found|"
                     r"sign in|log in|login|permission)", re.I)


def load_scope():
    """program -> (allowed suffixes, explicit OOS hostnames or None) from
    /opt/watch/programs/*.json  ({program_name, scopes[], ooscopes[]})."""
    import glob
    scopes = {}
    for f in glob.glob("/opt/watch/programs/*.json"):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        name = (d.get("program_name") or "").strip().lower()
        sfx = [str(s).strip().lstrip("*.").lower() for s in (d.get("scopes") or [])]
        oos = [str(s).strip().lstrip("*.").lower() for s in (d.get("ooscopes") or [])]
        if name:
            scopes[name] = (sfx, oos)
    return scopes


def ins_scope(url, program, scopes):
    host = urlsplit(url).netloc.lower().split(":")[0]
    if program not in scopes:
        return False
    sfx, oos = scopes[program]
    if any(host == o or host.endswith("." + o) for o in oos):
        return False
    return any(host == s or host.endswith("." + s) for s in sfx)


def swap(url):
    p = urlsplit(url)
    q = [(k, BOGUS if IDISH.search(k) else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def body_sig(r):
    b = r.content or b""
    return len(b), (b[:200] if b else b"")


def probe(t):
    url, program = t["url"], t["program"]
    host = urlsplit(url)
    ctl_path = host.scheme + "://" + host.netloc + "/zq-nonexistent-" + BOGUS
    out = {"url": url, "program": program}
    try:
        a = requests.get(url, timeout=T, verify=False, headers=UA, allow_redirects=False)
        b = requests.get(swap(url), timeout=T, verify=False, headers=UA, allow_redirects=False)
        c = requests.get(ctl_path, timeout=T, verify=False, headers=UA, allow_redirects=False)
    except Exception as e:
        out["error"] = type(e).__name__
        return out

    out.update({
        "recorded": {"status": a.status_code, "len": len(a.content or b"")},
        "diff_ctl": {"status": b.status_code, "len": len(b.content or b"")},
        "catchall": {"status": c.status_code, "len": len(c.content or b"")},
        "ctype": a.headers.get("content-type", ""),
    })
    body = (a.text or "")
    ct = out["ctype"].lower()
    same_as_catchall = (a.status_code == c.status_code and
                        abs(len(a.content or b"") - len(c.content or b"")) < 40)
    same_as_diff = (a.status_code == b.status_code and
                    abs(len(a.content or b"") - len(b.content or b"")) < 40)
    out["cmp"] = {"same_as_catchall": same_as_catchall, "same_as_diff": same_as_diff}

    record_shaped = (a.status_code == 200 and RECORDY.match(body.strip() or "")
                     and "json" in ct)
    out["open"] = bool(record_shaped and not same_as_catchall and not same_as_diff
                       and not ERRWORD.search(body[:400]))
    return out


def main():
    targets = json.load(open("/opt/watch/logs/bb4/idor_targets_filtered.json"))
    scopes = load_scope()
    print(f"[*] {len(targets)} targets, scope files for {len(scopes)} programs", flush=True)
    res, skipped = [], 0
    for t in targets:
        if scopes and not ins_scope(t["url"], t["program"], scopes):
            print(f"  SCOPE-SKIP {t['program']} {t['url'][:90]}", flush=True)
            skipped += 1
            continue
        r = probe(t)
        res.append(r)
        o = r.get("open")
        flag = "OPEN?" if o else ("err" if "error" in r else "closed")
        print(f"  [{flag}] {r.get('recorded', {}).get('status')}/"
              f"{r.get('diff_ctl', {}).get('status')}/"
              f"{r.get('catchall', {}).get('status')} "
              f"lens={r.get('recorded', {}).get('len')}/{r.get('diff_ctl', {}).get('len')}"
              f"/{r.get('catchall', {}).get('len')} {t['program']} "
              f"{t['url'][:80]}", flush=True)

    json.dump(res, open("/opt/watch/logs/bb4/idor_posture.json", "w"), indent=1)
    opens = [r for r in res if r.get("open")]
    print(f"\n[+] {len(opens)} open candidates, {skipped} scope-skipped")


if __name__ == "__main__":
    main()
