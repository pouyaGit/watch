#!/usr/bin/env python3
"""
watch_nuclei_run.py -- resumable, narrow nuclei lane for the heavy worker.

Two passes per lane slice, both bounded by --max-minutes:

  1. takeover  Subdomains with no recent takeover check -> nuclei `-tags takeover`
               (DNS-level, cheap). Every new candidate is a high-priority finding.
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
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mongoengine import Q  # noqa: E402

from database.db import Http, Subdomains, upsert_finding  # noqa: E402
from utils.common import require_tools  # noqa: E402
from utils.recon import (  # noqa: E402
    Deadline, alert, env_flag, env_int, host_of, in_scope, log,
    meets_floor, run_tool, scope_index,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PUBLIC_CONFIG = os.path.join(ROOT, "nuclei", "public-config.yaml")
DEFAULT_TEMPLATES = os.path.join(ROOT, "nuclei", "private_templates")

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
            is_new = upsert_finding({
                "program_name": sub.program_name,
                "scope": sub.scope,
                "target": sub.subdomain,
                "source": "takeover",
                "name": template,
                "severity": "high",
                "matched": matched,
                "extra": {"template": template, "type": obj.get("type")},
            })
            if is_new:
                found += 1
                alert(f"[takeover] HIGH · {template} · {matched}")

    Subdomains.objects(id__in=[d.id for d in docs]).update(set__last_takeover_check=now)
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
        http_pass(deadline, index, tmp, cutoff)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
