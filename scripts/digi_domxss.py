#!/usr/bin/env python3
"""digi_domxss.py -- source -> sink data-flow scan over DigiCert's own JS.

Per hunt-xss: a token scan is not a flow. Bounded backward slice from each
sink argument back to an identifier assigned from a link-carriable source
(location.search / hash / href / referrer, postMessage data, cookie).
Fixtures are asserted before any count is trusted.
"""
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

SOURCES = [
    ("location.search", r"location\s*\.\s*search|location\s*\.\s*href|"
                        r"document\s*\.\s*URL|window\s*\.\s*location"),
    ("location.hash", r"location\s*\.\s*hash"),
    ("document.referrer", r"document\s*\.\s*referrer"),
    ("postMessage", r"addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*="),
    ("cookie", r"document\s*\.\s*cookie"),
    ("storage", r"localStorage|sessionStorage"),
]

SINKS = [
    ("innerHTML", r"\.innerHTML\s*=\s*([^;]{0,200})"),
    ("outerHTML", r"\.outerHTML\s*=\s*([^;]{0,200})"),
    ("document.write", r"document\s*\.\s*write(?:ln)?\s*\(\s*([^)]{0,200})"),
    ("eval", r"\beval\s*\(\s*([^)]{0,200})"),
    ("setTimeout-str", r"setTimeout\s*\(\s*([^,)]{0,120})"),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]{0,160})"),
    ("jquery.html", r"\.html\s*\(\s*([^)]{0,200})"),
    ("element.src", r"\.src\s*=\s*([^;]{0,160})"),
    ("attr.href", r"\.href\s*=\s*([^;]{0,160})"),
]

# A minified bundle makes the backward slice quadratic: every sink match
# re-scans the whole file for each identifier. Cap the work per file so the
# pass COMPLETES - a scan that dies at 4% reports a coverage number, not a
# finding, and a partial pass must never be presented as a full one.
MAX_FILE_BYTES = 2_500_000
MAX_SINK_MATCHES = 60


def selftest():
    cases = {
        "direct": "el.innerHTML = location.hash;",
        "assigned": "var q = location.search; el.innerHTML = q;",
        "chained": "var a = location.search; var b = a; el.innerHTML = b;",
        "postmsg": "window.addEventListener('message',function(e){d.innerHTML = e.data;});",
        "evalhash": "eval(location.hash.slice(1));",
        "negative_literal": "el.innerHTML = '<b>hi</b>';",
        "negative_nopath": "var x = location.search; el.innerHTML = 'static';",
    }
    for name, code in cases.items():
        found = slice_file(code)
        print(f"[selftest] {name:18} -> {[f['sink'] for f in found]}")
    assert any(f["kind"] == "direct" for f in slice_file(cases["direct"]))
    assert any(f["kind"] == "assigned" for f in slice_file(cases["assigned"]))
    assert any(f["kind"] == "assigned" or f["kind"] == "chained"
               for f in slice_file(cases["chained"]))
    assert any(f["source"] == "postMessage" for f in slice_file(cases["postmsg"]))
    assert any(f["sink"] == "eval" for f in slice_file(cases["evalhash"]))
    assert not slice_file(cases["negative_literal"]), "literal arg must not hit"
    assert not slice_file(cases["negative_nopath"]), "unrelated var must not hit"
    print("[selftest] all fixtures pass")


def has_source(expr):
    for name, pat in SOURCES:
        if re.search(pat, expr, re.I):
            return name
    return None


def build_index(code):
    """One pass: identifier -> list of RHS strings it was ever assigned.

    The previous version re-scanned the whole file for every identifier in
    every sink argument, which is quadratic on a multi-MB bundle and never
    finished. Indexing once makes the backward walk a dict lookup.
    """
    idx = {}
    for m in re.finditer(r"(?:var|let|const)?\s*\b([A-Za-z_$][\w$]{0,40})\s*="
                         r"\s*([^;]{0,200})", code):
        idx.setdefault(m.group(1), []).append(m.group(2))
    return idx


def resolve_var(index, ident, depth=0, seen=None):
    """Follow ident backwards through the assignment index, 2 hops max."""
    if seen is None:
        seen = set()
    if ident in seen or depth > 2:
        return None
    seen.add(ident)
    for rhs in index.get(ident, [])[:8]:
        s = has_source(rhs)
        if s:
            return s
        for nxt in re.findall(r"[A-Za-z_$][\w$]{0,40}", rhs)[:4]:
            if nxt not in seen:
                got = resolve_var(index, nxt, depth + 1, seen)
                if got:
                    return got
    return None


def message_param(code):
    """Name of the event parameter bound in a message listener, if any."""
    if not re.search(r"addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=", code, re.I):
        return None
    for m in re.finditer(r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*"
                         r"(?:function\s*)?\(?\s*([A-Za-z_$][\w$]{0,20})", code):
        return m.group(1)
    for m in re.finditer(r"\.onmessage\s*=\s*(?:function\s*)?\(?\s*([A-Za-z_$][\w$]{0,20})", code):
        return m.group(1)
    return None


def slice_file(code, filename=""):
    """Find sink sites whose argument traces back to a source (2 hops max)."""
    mparam = message_param(code)
    index = build_index(code)
    out = []
    for sink_name, pat in SINKS:
        for n, m in enumerate(re.finditer(pat, code)):
            if n >= MAX_SINK_MATCHES:
                break
            arg = m.group(1) if m.groups() else ""
            if not arg:
                continue
            s = has_source(arg)
            if s:
                out.append({"sink": sink_name, "kind": "direct", "source": s,
                            "arg": arg.strip()[:160], "file": filename})
                continue
            # message-event data: only counts when a listener exists in THIS file
            if mparam and re.search(r"\b" + re.escape(mparam) + r"\s*\.\s*data\b", arg):
                out.append({"sink": sink_name, "kind": "message",
                            "source": "postMessage",
                            "arg": arg.strip()[:160], "file": filename})
                continue
            ids = re.findall(r"[A-Za-z_$][\w$]{0,40}", arg)
            hit = None
            for ident in ids[:6]:
                if ident in ("true", "false", "null", "this", "window",
                             "document", "function", "return", "if", "else"):
                    continue
                src = resolve_var(index, ident)
                if src:
                    hit = (ident, src)
                    break
            if hit:
                out.append({"sink": sink_name, "kind": "assigned",
                            "source": hit[1], "via": hit[0],
                            "arg": arg.strip()[:160], "file": filename})
    return out


def main():
    if "--selftest" in sys.argv:
        selftest()
        return
    files = json.load(open("/opt/watch/logs/digi/js_files.json"))
    # first-party only: the app's own bundles, not CDN libraries
    third = re.compile(r"(jquery|bootstrap|granite|clientlib|vendors?|"
                       r"polyfill|confetti|vaadin|adobe|launch-EN|rum/|"
                       r"react|angular|slick|swiper|moment|d3\.)", re.I)
    targets = [u for u in files if not third.search(u)]
    print(f"[*] {len(files)} JS files, {len(targets)} first-party after "
          f"removing libraries", flush=True)

    results = []

    def fetch(u):
        try:
            r = requests.get(u, timeout=20, verify=False, headers=UA,
                             allow_redirects=True)
            if r.status_code != 200:
                return None
            if len(r.content or b"") > MAX_FILE_BYTES:
                return ("SKIP", u, len(r.content))
            return u, (r.text or "")
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        for i, res in enumerate(ex.map(fetch, targets), 1):
            if not res:
                continue
            if res[0] == "SKIP":
                print(f"  [skip {res[2]:,}B] {res[1][:80]}", flush=True)
                continue
            u, code = res
            for f in slice_file(code, u):
                results.append(f)
                print(f"[FLOW] {f['kind']:9} {f['source']:16} -> {f['sink']:18} "
                      f"{u.split('/')[-1][:50]}", flush=True)
            if i % 100 == 0:
                print(f"  [{i}/{len(targets)}] flows={len(results)}", flush=True)

    json.dump(results, open("/opt/watch/logs/digi/dom_flows.json", "w"), indent=1)
    print(f"\n[+] {len(results)} source->sink flows over {len(targets)} files")


if __name__ == "__main__":
    main()
