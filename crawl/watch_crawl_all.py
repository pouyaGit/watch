#!/usr/bin/env python3
"""
watch_crawl_all.py — کرال کامل روی همه‌ی HTTPهای زنده (نه فقط fresh)

هدف: برخلاف watch_crawl_fresh.py که فقط ساب‌دامین‌های تازه رو می‌گیره، این اسکریپت
کل دیتابیس رو پوشش می‌ده. این کار سنگینه، پس طراحی شده که:

1. با --max-minutes بعد از یه مدت مشخص خودش تمیز متوقف بشه (برای اجرای دستی محدود
   یا برای اینکه قبل از شروع پایپ‌لاین ۱۲ساعته تمومش کنی).
2. دامنه‌هایی که دیرتر کرال شدن (یا اصلاً کرال نشدن) رو اول پردازش کنه — یعنی اگه
   یه اجرا کامل تموم نشه، اجرای بعدی خودش از همون‌جا ادامه می‌ده، بدون نیاز به
   فایل state جدا (بر اساس last_update تو کالکشن Urls).
3. با --filter بشه فقط روی یه دامنه/کلمه تست کرد، نه کل ۲۳۴۹ تا یک‌جا.

Usage:
  python3 watch_crawl_all.py --max-minutes 320          # کل دیتابیس، حداکثر ۵.۳ ساعت
  python3 watch_crawl_all.py --filter dell.com --max-minutes 30   # تست روی یه دامنه
  python3 watch_crawl_all.py                             # بدون محدودیت زمانی (تا آخر)
"""

import os
import sys
import re
import time
import argparse
import subprocess
import requests
import gzip
import shutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from database.db import Http, bulk_store_crawl_results

OUT_DIR = Path("/opt/watch/crawl/output")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
API = "http://127.0.0.1:5000/api/http/all?raw=1"

BAD_EXT = re.compile(
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|'
    r'mp4|webm|pdf|zip|rar|gz|xml|txt)(\?|$)',
    re.I
)

# ---------------- server-load tuning ----------------
KATANA_DEPTH        = 3
KATANA_CONCURRENCY  = 5
KATANA_PARALLELISM  = 3
KATANA_RATE_LIMIT   = 40
KATANA_TIMEOUT      = 8
KATANA_CRAWL_DURATION = "5m"  # a bit more room than fresh since this runs weekly
ROBOTS_WORKERS      = 5

# -kf all (sitemap.xml/robots.txt) IS kept here since this is the weekly,
# thorough pass -- but a hard per-domain cap still applies, since a single
# large sitemap can otherwise produce hundreds of thousands of URLs from
# one domain and stall MongoDB on insert.
MAX_URLS_PER_DOMAIN = 50000
TELEGRAM_MAX_FILE_MB = 45
# -----------------------------------------------------------------------------------

START_TIME = time.time()


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def get_host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def get_all_targets(filter_arg=None):
    try:
        r = requests.get(API, headers={"X-API-Key": config().get("API_KEY", "")}, timeout=60)
        r.raise_for_status()
        lines = [x.strip() for x in r.text.splitlines() if x.strip().startswith("http")]
        cleaned = [u.rstrip("/") for u in lines if not BAD_EXT.search(u)]
        if filter_arg:
            f = filter_arg.lower()
            cleaned = [u for u in cleaned if f in u.lower()]
        return sorted(set(cleaned))
    except Exception as e:
        log(f"Error getting targets: {e}")
        return []


def group_by_root_domain(urls):
    by_domain = defaultdict(list)
    for u in urls:
        host = get_host(u)
        if not host:
            continue
        parts = host.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else host
        by_domain[root].append(u)
    return dict(by_domain)


def order_by_least_recently_crawled(by_domain):
    """دامنه‌هایی که هیچ‌وقت کرال نشدن یا خیلی وقته کرال نشدن رو اول می‌ذاره،
    تا اگه اجرای فعلی نیمه‌کاره متوقف بشه، دفعه‌ی بعد از بقیه شروع بشه."""
    scored = []
    for domain, urls in by_domain.items():
        hosts = {get_host(u) for u in urls if get_host(u)}
        last = (
            Urls.objects(subdomain__in=list(hosts))
            .order_by('-last_update')
            .first()
        )
        last_ts = last.last_update if last else datetime.min
        scored.append((last_ts, domain, urls))
    scored.sort(key=lambda x: x[0])  # قدیمی‌ترین/هرگز-کرال‌نشده اول
    return [(domain, urls) for _, domain, urls in scored]


def resolve_program(host):
    doc = Http.objects(subdomain=host).first()
    return doc.program_name if doc else "Unknown"


def run_katana(targets_file, out_file):
    # -kf all kept here (weekly thorough pass), but -ct caps wall-clock time
    # so a crawler trap or huge sitemap can't run forever. Verify flag name
    # with `katana -h`, it may differ across versions.
    cmd = (
        f'katana -list "{targets_file}" '
        f'-d {KATANA_DEPTH} -jc -kf all -fs rdn '
        f'-c {KATANA_CONCURRENCY} -p {KATANA_PARALLELISM} '
        f'-rl {KATANA_RATE_LIMIT} -timeout {KATANA_TIMEOUT} -retry 1 '
        f'-ct {KATANA_CRAWL_DURATION} '
        f'-silent -o "{out_file}"'
    )
    log(f"$ {cmd}")
    try:
        subprocess.run(cmd, shell=True, timeout=3600)
    except subprocess.TimeoutExpired:
        log(f"katana timeout on {targets_file}")

    if not out_file.exists():
        return []
    return [
        l.strip() for l in out_file.read_text(errors="ignore").splitlines()
        if l.strip().startswith("http")
    ]


def fetch_robots_history(domain):
    try:
        r = requests.get(
            f"https://web.archive.org/web/timemap/link/{domain}/robots.txt",
            timeout=8
        )
        return re.findall(r'https?://[^"<>\s]+', r.text)
    except Exception:
        return []


def send_telegram_message(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
    except Exception as e:
        log(f"Telegram exception: {e}")


def crawl_domain(domain, urls):
    log(f"\n--- Crawling {domain} ({len(urls)} seeds) ---")
    send_telegram_message(f"Now crawling {domain} [crawlAll]\nSeeds: {len(urls)}")
    domain_dir = OUT_DIR / f"all_{domain}_{DATE}"
    domain_dir.mkdir(parents=True, exist_ok=True)

    seeds_file = domain_dir / "seeds.txt"
    seeds_file.write_text("\n".join(urls) + "\n")

    katana_out = domain_dir / "katana.txt"
    crawled = set(run_katana(seeds_file, katana_out))

    if len(crawled) > MAX_URLS_PER_DOMAIN:
        log(f"{domain}: WARNING -- katana returned {len(crawled)} URLs, "
            f"likely a crawler trap or huge sitemap. Capping to {MAX_URLS_PER_DOMAIN}.")
        crawled = set(sorted(crawled)[:MAX_URLS_PER_DOMAIN])

    all_urls = sorted(set(urls) | crawled)

    hosts = sorted({get_host(u) for u in urls if get_host(u)})
    robots_urls = set()
    with ThreadPoolExecutor(max_workers=ROBOTS_WORKERS) as ex:
        futures = {ex.submit(fetch_robots_history, h): h for h in hosts}
        for fut in as_completed(futures):
            robots_urls.update(fut.result())
    if robots_urls:
        all_urls = sorted(set(all_urls) | robots_urls)

    # ---------- build entries and store in one bulk_write (in-scope only) ----------
    entries = []
    skipped_out_of_scope = 0
    for u in all_urls:
        host = get_host(u)
        if not host:
            continue
        program_name = resolve_program(host)
        if program_name == "Unknown":
            skipped_out_of_scope += 1
            continue
        if u in crawled:
            source = "katana"
        elif u in robots_urls:
            source = "wayback-robots"
        else:
            source = "http-seed"

        parsed = urlparse(u)
        entries.append({
            "program_name": program_name,
            "subdomain": host,
            "url": u,
            "path": parsed.path or "/",
            "params": sorted(set(parse_qs(parsed.query).keys())),
            "source": source,
        })

    if skipped_out_of_scope:
        log(f"{domain}: skipped {skipped_out_of_scope} out-of-scope/third-party URLs")

    saved_new = bulk_store_crawl_results(entries)

    log(f"{domain}: total {len(all_urls)} URLs | {saved_new} new in DB")
    send_telegram_message(
        f"Result -- {domain} [crawlAll]\n"
        f"Seeds: {len(urls)} | Final: {len(all_urls)} | New in DB: {saved_new}"
    )
    return len(all_urls), saved_new


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None, help="فقط دامنه/کلمه‌ی خاص")
    parser.add_argument("--max-minutes", type=float, default=None,
                         help="بعد از این مدت (دقیقه) خودش تمیز متوقف می‌شه")
    args = parser.parse_args()

    log(f"=== Watch Crawl ALL Started | filter={args.filter or 'NONE'} | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    targets = get_all_targets(args.filter)
    log(f"Total targets: {len(targets)}")
    if not targets:
        log("No targets. Exit.")
        return

    by_domain = group_by_root_domain(targets)
    ordered = order_by_least_recently_crawled(by_domain)
    log(f"{len(ordered)} root domains, ordered oldest-crawled-first")

    domain_list = "\n".join(f"  - {d} ({len(by_domain[d])} seeds)" for d in [x[0] for x in ordered])
    send_telegram_message(
        f"Starting crawlAll run\nTime budget: {args.max_minutes or 'unlimited'} min\n"
        f"Queued domains ({len(ordered)}):\n{domain_list}"
    )

    total_urls = 0
    total_new = 0
    done_domains = 0
    skipped_domains = []

    for domain, urls in ordered:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            skipped_domains.append(domain)
            continue

        u_count, n_count = crawl_domain(domain, urls)
        total_urls += u_count
        total_new += n_count
        done_domains += 1

    summary = (
        f"🕷 Crawl ALL finished\n"
        f"Domains crawled: {done_domains}/{len(ordered)}\n"
        f"URLs total: {total_urls} | New in DB: {total_new}\n"
        f"Runtime: {elapsed_minutes():.1f} min"
    )
    if skipped_domains:
        summary += f"\nStopped by time limit — {len(skipped_domains)} domains left for next run"
        log(f"Skipped (time budget hit): {skipped_domains}")

    log(summary)
    send_telegram_message(summary)


if __name__ == "__main__":
    main()