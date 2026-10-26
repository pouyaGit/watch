#!/usr/bin/env python3
"""
watch_nuclei_run.py -- resumable, narrow nuclei lane for the heavy worker.

Two passes per lane slice, both bounded by --max-minutes:

  1. takeover  Subdomains with no recent takeover check -> nuclei `-tags takeover`
               (DNS-level, cheap). Each hit is then graded by actual claimability
               (see takeover_verdict); only genuinely claimable assets alert.
  2. http      Live Http services, never-scanned first then least-recently-scanned,
               newest first within the same bucket. Scanned with the private
               templates, plus tech-tagged public templates for hosts whose
               detected stack maps to a known nuclei tag.

Only in-scope assets are sent to nuclei (scope and ooscopes are checked against
Programs). Results are deduped in Finding; only the first sighting of a
medium+ finding alerts on Telegram.

Usage:
  python3 nuclei/watch_nuclei_run.py --max-minutes 20

Env knobs:
  NUCLEI_SEVERITY        comma list (default medium,high,critical)
  NUCLEI_RATE_LIMIT      requests/second (default 50)
  NUCLEI_CONCURRENCY     templates in parallel (default 10)
  NUCLEI_RESCAN_DAYS     rescan a service after this many days (default 7)
  NUCLEI_BATCH_SIZE      targets per nuclei invocation (default 200)
  NUCLEI_GROUP_TIMEOUT   hard cap seconds per nuclei invocation (default 900)
  NUCLEI_TAKEOVER_BATCH  subdomains per takeover pass (default 500)
  NUCLEI_REDIRECT          0 = skip the redirect pass entirely (default on)
  NUCLEI_REDIRECT_CONFIRM  0 = discover candidates only, send no requests (default on)
  NUCLEI_REDIRECT_WRITE_CANDIDATES  1 = also persist the noisy info worklist to
                           findings (default off; only confirmed redirects are
                           stored, unless confirm is disabled)
  NUCLEI_REDIRECT_BATCH    max in-scope redirect endpoints per run (default 300)
  NUCLEI_TEMPLATES       comma list of template paths (default nuclei/private_templates)
  NUCLEI_PUBLIC_TAGS     public store tags scanned on every host alongside the
                         private templates (default exposure,config,backup,debug,
                         disclosure,default-login,ssrf,rce,lfi,xxe); set "" to disable
  NUCLEI_NO_INTERACTSH   1 = restore -ni (disable OOB/blind detection)
  WATCH_NUCLEI_VERBOSE   1 = post a per-batch summary to Telegram
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urlsplit

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402
from mongoengine import Q  # noqa: E402

from database.db import Http, Subdomains, Urls, Endpoints, upsert_finding  # noqa: E402
from utils.common import require_tools  # noqa: E402
from utils.recon import (  # noqa: E402
    Deadline, alert, env_flag, env_int, host_of, in_scope, log,
    meets_floor, run_tool, scope_index,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PUBLIC_CONFIG = os.path.join(ROOT, "nuclei", "public-config.yaml")
DEFAULT_TEMPLATES = os.path.join(ROOT, "nuclei", "private_templates")
REDIRECT_TEMPLATE = os.path.join(ROOT, "nuclei", "private_templates", "open-redirect-auth.yaml")
REDIRECT_WORDLIST = os.path.join(ROOT, "wordlists", "redirect-params.txt")

# Auth/navigation-flow path signatures, word-boundary anchored so a keyword does
# not match inside an unrelated slug (e.g. "auth" in "authority").
REDIRECT_AUTH_PATH = re.compile(
    r"\b(login|log-?in|signin|sign-?in|logon|auth|authorize|authentication|"
    r"oauth|oauth2|openid|connect|sso|saml|cas|idp|adfs|wsfed|session|"
    r"register|signup|sign-?up|join|logout|log-?out|signout|sign-?out|"
    r"password|passwd|pwd|reset|forgot|recover|recovery|verify|confirm|"
    r"activate|validate|callback|return|continue|redirect|relaystate|acs)\b",
    re.I,
)

# Detected Http.tech value (lowercased) -> nuclei tag that narrows the public set.
TECH_TAGS = {
    "wordpress": "wordpress",
    "jira": "jira",
    "confluence": "confluence",
    "airflow": "airflow",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "grafana": "grafana",
    "phpmyadmin": "phpmyadmin",
    "tomcat": "tomcat",
    "drupal": "drupal",
    "joomla": "joomla",
}


def _write_targets(path, lines):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _nuclei_argv(targets_file, out_file, selector, *, severity):
    argv = [
        "nuclei", "-l", targets_file, "-jsonl", "-o", out_file,
        "-severity", severity,
        "-rl", str(env_int("NUCLEI_RATE_LIMIT", 50)),
        "-c", str(env_int("NUCLEI_CONCURRENCY", 10)),
        "-timeout", "8", "-retries", "1", "-silent",
    ]
    # OOB/blind detection (SSRF, RCE, XXE...) needs interactsh. It is ON by
    # default now that the box can reach the oast servers; an interaction is
    # strong, low-FP proof. Set NUCLEI_NO_INTERACTSH=1 to restore the old -ni
    # behaviour (e.g. if egress to oast is ever blocked).
    if env_flag("NUCLEI_NO_INTERACTSH"):
        argv.append("-ni")
    if os.path.exists(PUBLIC_CONFIG):
        argv += ["-config", PUBLIC_CONFIG]
    return argv + selector


def _group_key(http):
    tags = {TECH_TAGS[t.strip().lower()] for t in (http.tech or []) if t.strip().lower() in TECH_TAGS}
    return tuple(sorted(tags))


# High-signal public tags scanned on every in-scope host regardless of detected
# tech. Without this the no-tech-tag majority of hosts only ever saw the handful
# of private templates and never touched the public store. public-config.yaml's
# exclude-tags/exclude-templates denylist still filters the noise. Set
# NUCLEI_PUBLIC_TAGS="" to disable, or override with your own comma list.
DEFAULT_PUBLIC_TAGS = "exposure,config,backup,debug,disclosure,default-login,ssrf,rce,lfi,xxe"


def _selectors_for(key):
    """List of (selector_argv, fs_safe_label) to run for a group key.

    The no-tech group runs the private templates AND a curated public tag set;
    a tech group runs just its tech-narrowed public templates.
    """
    if key == ():
        sels = [(["-t", os.environ.get("NUCLEI_TEMPLATES", DEFAULT_TEMPLATES)], "private")]
        public_tags = os.environ.get("NUCLEI_PUBLIC_TAGS", DEFAULT_PUBLIC_TAGS).strip()
        if public_tags:
            sels.append((["-tags", public_tags], "public"))
        return sels
    return [(["-tags", ",".join(key)], "+".join(key))]


# Azure resource suffixes whose vhost name can be re-registered once freed.
# A dangling CNAME to one of these that no longer resolves is a real claim target;
# a bare A-record to a shared Azure IP is not (custom-domain binding needs an
# asuid TXT the attacker cannot create).
_AZURE_SUFFIXES = (
    ".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
    ".trafficmanager.net", ".azureedge.net", ".azurefd.net",
    ".blob.core.windows.net", ".azure-api.net",
)


def _mk_resolver():
    r = dns.resolver.Resolver(configure=True)
    fallbacks = ["8.8.8.8", "1.1.1.1"]
    try:
        r.nameservers = list(dict.fromkeys(list(r.nameservers) + fallbacks))
    except Exception:
        r.nameservers = fallbacks
    r.timeout = 4.0
    r.lifetime = 8.0
    return r


def _cname_chain(resolver, host):
    """Follow the CNAME chain, returning each target lowercased without trailing dot."""
    chain, name = [], host
    for _ in range(10):
        try:
            ans = resolver.resolve(name, "CNAME")
        except dns.exception.DNSException:
            break
        target = str(ans[0].target).rstrip(".").lower()
        if not target or target == name or target in chain:
            break
        chain.append(target)
        name = target
    return chain


def _resolves(resolver, name):
    """True if name resolves to anything; False only on a definitive NXDOMAIN.

    Inconclusive answers (timeouts, SERVFAIL) return True so we never suppress a
    finding on a transient DNS failure."""
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(name, rtype)
            return True
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False
        except dns.exception.DNSException:
            return True
    return False


def _has_txt(resolver, name):
    try:
        return len(resolver.resolve(name, "TXT")) > 0
    except dns.exception.DNSException:
        return False


def takeover_verdict(host, template_id):
    """Grade a nuclei takeover hit by actual claimability.

    Returns (severity, reason). Conservative by design: it only downgrades on
    positive evidence that the asset cannot be claimed, and leaves anything it
    cannot disprove at "high" so real takeovers (e.g. S3/GitHub fingerprints
    whose endpoint still resolves) are never silently dropped."""
    tid = (template_id or "").lower()
    try:
        resolver = _mk_resolver()
        chain = _cname_chain(resolver, host)
    except Exception as exc:  # tooling failure -> do not suppress
        return "high", f"dns-check-failed:{exc}"

    if "azure" in tid:
        azure = [c for c in chain if c.endswith(_AZURE_SUFFIXES)]
        if azure:
            target = azure[-1]
            if not _resolves(resolver, target):
                return "high", f"dangling CNAME -> unresolved {target} (claimable)"
            return "info", f"CNAME -> {target} still resolves (registered, not claimable)"
        # No claimable CNAME: bare A/AAAA record to a shared Azure IP.
        if _has_txt(resolver, "asuid." + host):
            return "info", "A-record to Azure + asuid TXT present (domain bound to an existing subscription)"
        return "low", "A-record to Azure, no CNAME to claim (custom-domain binding needs an asuid TXT the attacker cannot set)"

    # Generic takeover templates: a fully dangling CNAME is a strong signal.
    if chain and not _resolves(resolver, chain[-1]):
        return "high", f"dangling CNAME -> unresolved {chain[-1]}"
    return "high", "unverified (left as high)"


def takeover_pass(deadline, index, tmp):
    size = env_int("NUCLEI_TAKEOVER_BATCH", 500)
    docs = list(Subdomains.objects.order_by("last_takeover_check").limit(size))
    if not docs:
        return 0

    now = datetime.now()
    inscope = []
    for d in docs:
        scopes, ooscopes = index.get(d.program_name, ([], []))
        if in_scope(d.subdomain, scopes, ooscopes):
            inscope.append(d)

    found = 0
    if inscope and not deadline.expired():
        log(f"--- Nuclei takeover pass: {inscope[0].subdomain} ({len(inscope)} subdomains)")
        targets_file = os.path.join(tmp, "takeover_targets.txt")
        out_file = os.path.join(tmp, "takeover.jsonl")
        _write_targets(targets_file, [d.subdomain for d in inscope])
        timeout_s = deadline.remaining(env_int("NUCLEI_GROUP_TIMEOUT", 900))
        argv = _nuclei_argv(targets_file, out_file, ["-tags", "takeover"], severity="info,low,medium,high,critical")
        rc, _ = run_tool(argv, timeout_s, quiet=True)
        log(f"takeover pass rc={rc}")
        by_host = {d.subdomain: d for d in inscope}
        for obj in _read_jsonl(out_file):
            host = (obj.get("host") or "").lower()
            host = host_of(host) or host
            sub = by_host.get(host)
            if sub is None:
                continue
            template = obj.get("template-id") or "takeover"
            matched = obj.get("matched-at") or sub.subdomain
            severity, reason = takeover_verdict(sub.subdomain, template)
            is_new = upsert_finding({
                "program_name": sub.program_name,
                "scope": sub.scope,
                "target": sub.subdomain,
                "source": "takeover",
                "name": template,
                "severity": severity,
                "matched": matched,
                "extra": {"template": template, "type": obj.get("type"), "verdict": reason},
            })
            if is_new:
                found += 1
                if meets_floor(severity):
                    alert(f"[takeover] {severity.upper()} · {template} · {matched} · {reason}")
                else:
                    log(f"[takeover:suppressed] {severity} · {template} · {matched} · {reason}")

    Subdomains.objects(id__in=[d.id for d in docs]).update(set__last_takeover_check=now)
    return found


def _redirect_candidates(index, limit):
    """Mine auth-flow endpoints carrying a redirect-style param from already
    crawled Urls/Endpoints. Returns [(program, full_url, [params])], deduped per
    in-scope host+path. No network -- pure DB read with a server-side filter."""
    try:
        with open(REDIRECT_WORDLIST) as fh:
            name_variants = sorted({ln.strip() for ln in fh if ln.strip()})
    except OSError:
        return []
    name_set = {n.lower() for n in name_variants}

    seen, hits = set(), []

    def consider(program, url, path, params):
        if not params or len(hits) >= limit:
            return
        key_path = (path or url or "").lower()
        if not REDIRECT_AUTH_PATH.search(key_path):
            return
        scopes, ooscopes = index.get(program, ([], []))
        host = host_of(url or "") or (url or "")
        if not in_scope(host, scopes, ooscopes):
            return
        matched = sorted({p for p in params if p and p.lower() in name_set})
        if not matched:
            return
        full = url or path or ""
        sp = urlsplit(full)
        norm = (sp.netloc + sp.path).lower() if sp.netloc else key_path
        dedup = (program, norm, tuple(matched))
        if dedup in seen:
            return
        seen.add(dedup)
        hits.append((program, full, matched))

    q = {"params__in": name_variants}
    for u in Urls.objects(**q).only("program_name", "url", "path", "params"):
        consider(u.program_name, u.url, u.path, u.params)
        if len(hits) >= limit:
            return hits
    for e in Endpoints.objects(**q).only("program_name", "example_url", "path", "params"):
        consider(e.program_name, e.example_url or e.path, e.path, e.params)
        if len(hits) >= limit:
            break
    return hits


def redirect_pass(deadline, index, tmp):
    """Discover auth-flow redirect params (candidate findings) and confirm them
    with the nuclei DAST template (confirmed open-redirects). Part of the same
    scheduled lane as takeover/http -- no separate cron needed.

    Disable with NUCLEI_REDIRECT=0. Confirmation only touches in-scope hosts."""
    if os.environ.get("NUCLEI_REDIRECT", "1") == "0":
        return 0
    limit = env_int("NUCLEI_REDIRECT_BATCH", 300)
    candidates = _redirect_candidates(index, limit)
    if not candidates:
        return 0
    log(f"--- Redirect pass: {len(candidates)} in-scope candidate endpoint(s)")

    confirm_on = os.environ.get("NUCLEI_REDIRECT_CONFIRM", "1") != "0"
    # Candidates (merely "has a redirect param") are a noisy worklist, not bugs:
    # in practice almost all are validated OAuth redirect_uri / handled next=
    # params that never actually redirect off-host. So they are NOT written to
    # findings by default -- only genuinely confirmed redirects are. Set
    # NUCLEI_REDIRECT_WRITE_CANDIDATES=1 to also persist the info worklist, and
    # note that if confirmation is off the candidate list is the only output,
    # so it is written then regardless.
    write_candidates = os.environ.get("NUCLEI_REDIRECT_WRITE_CANDIDATES", "0") == "1"
    if write_candidates or not confirm_on:
        for program, url, matched in candidates:
            sp = urlsplit(url)
            target = f"{sp.scheme}://{sp.netloc}{sp.path}" if sp.netloc else url
            upsert_finding({
                "program_name": program,
                "target": target,
                "source": "redirect-param",
                "name": "redirect-param-on-auth-flow",
                "severity": "info",
                "matched": url,
                "extra": {"params": matched, "note": "candidate; confirm before reporting"},
            })

    # 2. confirm with nuclei DAST (fuzz the redirect param -> external canary).
    #    NUCLEI_REDIRECT_CONFIRM=0 keeps the pass discover-only (sends no requests).
    if not confirm_on:
        log("redirect pass: confirm disabled (NUCLEI_REDIRECT_CONFIRM=0), candidates only")
        return 0
    if deadline.expired() or not os.path.exists(REDIRECT_TEMPLATE):
        return 0
    targets_file = os.path.join(tmp, "redirect_targets.txt")
    out_file = os.path.join(tmp, "redirect.jsonl")
    prog_of = {}
    with open(targets_file, "w") as fh:
        for program, url, _ in candidates:
            fh.write(url + "\n")
            prog_of[url] = program
    timeout_s = deadline.remaining(env_int("NUCLEI_GROUP_TIMEOUT", 900))
    argv = [
        "nuclei", "-dast", "-l", targets_file, "-t", REDIRECT_TEMPLATE,
        "-jsonl", "-o", out_file, "-silent", "-disable-update-check",
        "-rl", str(env_int("NUCLEI_RATE_LIMIT", 50)), "-timeout", "8",
    ]
    rc, _ = run_tool(argv, timeout_s, quiet=True)
    log(f"redirect confirm pass rc={rc}")

    found = 0
    for obj in _read_jsonl(out_file):
        matched = obj.get("matched-at") or obj.get("host") or ""
        host = host_of(matched) or matched
        program = prog_of.get(matched) or next(
            (p for u, p in ((u, prog_of[u]) for u in prog_of) if host_of(u) == host),
            "unknown")
        is_new = upsert_finding({
            "program_name": program,
            "target": matched,
            "source": "redirect",
            "name": "open-redirect-auth-confirmed",
            "severity": "medium",
            "matched": matched,
            "extra": {"template": "open-redirect-auth-custom",
                      "confirmed": "Location -> external canary"},
        })
        if is_new:
            found += 1
            if meets_floor("medium"):
                alert(f"[redirect] MEDIUM confirmed open-redirect · {matched}")
    return found


def _scan_group(targets, selector, tmp, deadline, label):
    targets_file = os.path.join(tmp, f"targets_{label}.txt")
    out_file = os.path.join(tmp, f"out_{label}.jsonl")
    _write_targets(targets_file, [h.url for h in targets])
    timeout_s = deadline.remaining(env_int("NUCLEI_GROUP_TIMEOUT", 900))
    if timeout_s < 30:
        return None
    argv = _nuclei_argv(
        targets_file, out_file, selector,
        severity=os.environ.get("NUCLEI_SEVERITY", "medium,high,critical"),
    )
    rc, _ = run_tool(argv, timeout_s, quiet=True)
    log(f"nuclei group '{label}' ({len(targets)} targets) rc={rc}")
    return _read_jsonl(out_file)


def _persist(results, by_host):
    new_findings = 0
    for obj in results:
        http = by_host.get(host_of(obj.get("matched-at") or obj.get("host") or ""))
        if http is None:
            continue
        info = obj.get("info") or {}
        template = obj.get("template-id") or ""
        severity = (info.get("severity") or "unknown").lower()
        matched = obj.get("matched-at") or http.url
        is_new = upsert_finding({
            "program_name": http.program_name,
            "scope": http.scope,
            "target": http.url,
            "source": "nuclei",
            "name": template,
            "severity": severity,
            "matched": matched,
            "extra": {
                "template": template,
                "name": info.get("name"),
                "tags": (info.get("tags") or [])[:10] if isinstance(info.get("tags"), list) else [],
                "type": obj.get("type"),
            },
        })
        if is_new:
            new_findings += 1
            if meets_floor(severity):
                alert(f"[nuclei] {severity.upper()} · {template} · {matched}")
    return new_findings


def http_pass(deadline, index, tmp, cutoff):
    size = env_int("NUCLEI_BATCH_SIZE", 200)
    scanned_total = 0
    findings_total = 0
    batches = 0

    while not deadline.expired():
        page = list(
            Http.objects(url__exists=True)
            .filter(Q(last_nuclei_run=None) | Q(last_nuclei_run__lt=cutoff))
            .order_by("last_nuclei_run", "-created_date")
            .limit(size)
        )
        if not page:
            break

        now = datetime.now()
        inscope = []
        for h in page:
            scopes, ooscopes = index.get(h.program_name, ([], []))
            if h.url and in_scope(h.subdomain, scopes, ooscopes):
                inscope.append(h)
        out_of_scope_ids = [h.id for h in page if h not in inscope]
        if out_of_scope_ids:
            Http.objects(id__in=out_of_scope_ids).update(set__last_nuclei_run=now)

        if not inscope:
            continue

        batches += 1
        log(f"--- Nuclei batch: {inscope[0].subdomain} ({len(inscope)} targets)")
        groups = {(): list(inscope)}
        for h in inscope:
            key = _group_key(h)
            if key:
                groups.setdefault(key, []).append(h)

        by_host = {h.subdomain: h for h in inscope}
        done = []
        results = []
        bsz = env_int("NUCLEI_BATCH_SIZE", 200)
        for key, members in groups.items():
            if deadline.expired():
                break
            selectors = _selectors_for(key)
            for start in range(0, len(members), bsz):
                if deadline.expired():
                    break
                chunk = members[start:start + bsz]
                chunk_scanned = False
                for selector, label in selectors:
                    if deadline.expired():
                        break
                    res = _scan_group(chunk, selector, tmp, deadline, label)
                    if res is None:   # ran out of time budget for this scan
                        continue
                    results.extend(res)
                    chunk_scanned = True
                if chunk_scanned:
                    done.extend(chunk)

        findings_total += _persist(results, by_host)
        scanned_total += len(done)
        if done:
            Http.objects(id__in=[h.id for h in done]).update(set__last_nuclei_run=datetime.now())

        if env_flag("WATCH_NUCLEI_VERBOSE"):
            alert(f"nuclei batch: {len(done)} scanned, {len(results)} raw results, "
                  f"{findings_total} new findings so far this run")

    log(f"=== Nuclei http pass: {scanned_total} services scanned in {batches} batches, "
        f"{findings_total} new findings ===")
    return scanned_total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    require_tools(["nuclei"])
    deadline = Deadline(args.max_minutes)
    index = scope_index()
    cutoff = datetime.now() - timedelta(days=env_int("NUCLEI_RESCAN_DAYS", 7))

    tmp = tempfile.mkdtemp(prefix="watch-nuclei-")
    try:
        takeover_pass(deadline, index, tmp)
        redirect_pass(deadline, index, tmp)
        http_pass(deadline, index, tmp, cutoff)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
