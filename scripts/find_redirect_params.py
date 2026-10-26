#!/usr/bin/env python3
"""find_redirect_params.py -- mine auth endpoints carrying a redirect-style
parameter from data Watch already crawled. No network, no login.

Pattern: a login / signup / logout / password-reset / forgot-password / SSO /
OAuth endpoint that takes a parameter whose job is "where to send the browser
next" (redirect, redirect_url, next, returnUrl, RelayState, ...). Those params
are the seed for open-redirect, and -- far more valuable -- OAuth/SSO redirect
hijack and account-takeover chains.

Reads the Urls and Endpoints collections. Matching is case-insensitive on the
parameter name and is scoped to auth-flow paths so the output is signal, not
every url with a "url" param.

Usage:
  ./.venv/bin/python scripts/find_redirect_params.py                 # all programs
  ./.venv/bin/python scripts/find_redirect_params.py --program dell  # one program
  ./.venv/bin/python scripts/find_redirect_params.py --any-path      # drop the auth-path filter
"""
import argparse
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import Urls, Endpoints, upsert_finding  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORDLIST = os.path.join(ROOT, "wordlists", "redirect-params.txt")

# Auth / navigation-flow path signatures. A redirect param here is interesting;
# the same param on a generic page usually is not.
# Word-boundary anchored so a keyword does not match inside an unrelated slug
# (e.g. "auth" inside "authority").
AUTH_PATH = re.compile(
    r"\b(login|log-?in|signin|sign-?in|logon|auth|authorize|authentication|"
    r"oauth|oauth2|openid|connect|sso|saml|cas|idp|adfs|wsfed|session|"
    r"register|signup|sign-?up|join|logout|log-?out|signout|sign-?out|"
    r"password|passwd|pwd|reset|forgot|recover|recovery|verify|confirm|"
    r"activate|validate|callback|return|continue|redirect|relaystate|acs)\b",
    re.I,
)


def load_param_set():
    with open(WORDLIST) as fh:
        return {ln.strip().lower() for ln in fh if ln.strip()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program")
    ap.add_argument("--any-path", action="store_true",
                    help="do not restrict to auth-flow paths")
    ap.add_argument("--write", action="store_true",
                    help="persist each hit to the Finding collection (source=redirect-param, severity info)")
    args = ap.parse_args()

    redirect_names = load_param_set()
    # Exact-match list (with the case variants from the wordlist) pushed to Mongo
    # so we only pull the handful of docs that carry a redirect-style param,
    # instead of scanning >1M URLs in Python.
    with open(WORDLIST) as fh:
        name_variants = sorted({ln.strip() for ln in fh if ln.strip()})

    q = {"params__in": name_variants}
    if args.program:
        q["program_name"] = args.program

    seen = set()
    hits = []

    def consider(program, url, path, params):
        if not params:
            return
        key_path = (path or url or "").lower()
        if not args.any_path and not AUTH_PATH.search(key_path):
            return
        matched = sorted({p for p in params if p and p.lower() in redirect_names})
        if not matched:
            return
        # Dedup on host+path (ignore volatile query values like state/nonce), so
        # one auth endpoint prints once instead of thousands of state-variants.
        full = url or path or ""
        sp = urlsplit(full)
        norm = (sp.netloc + sp.path).lower() if sp.netloc else key_path
        dedup = (program, norm, tuple(matched))
        if dedup in seen:
            return
        seen.add(dedup)
        hits.append((program, full, matched))

    for u in Urls.objects(**q).only("program_name", "url", "path", "params"):
        consider(u.program_name, u.url, u.path, u.params)
    for e in Endpoints.objects(**q).only("program_name", "example_url", "path", "params"):
        consider(e.program_name, e.example_url or e.path, e.path, e.params)

    hits.sort(key=lambda h: (h[0], h[1]))
    written = 0
    for program, where, matched in hits:
        print(f"[{program}] {where}  <=  {', '.join(matched)}")
        if args.write:
            # Candidate, not a confirmed bug: info severity so it shows in
            # findings for review/confirmation without alerting. Keyed per
            # host+path so re-runs refresh instead of duplicating.
            sp = urlsplit(where)
            target = f"{sp.scheme}://{sp.netloc}{sp.path}" if sp.netloc else where
            if upsert_finding({
                "program_name": program,
                "target": target,
                "source": "redirect-param",
                "name": "redirect-param-on-auth-flow",
                "severity": "info",
                "matched": where,
                "extra": {"params": matched, "note": "candidate; confirm open-redirect/OAuth-hijack before reporting"},
            }):
                written += 1
    suffix = f" | {written} new written to findings" if args.write else ""
    print(f"\n{len(hits)} auth-flow endpoint(s) with a redirect-style parameter{suffix}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
