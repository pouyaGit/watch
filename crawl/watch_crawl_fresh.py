#!/usr/bin/env python3
"""
watch_crawl_fresh.py — کرال خودکار روی HTTPهای تازه‌کشف‌شده + ذخیره در دیتابیس

تغییرات نسبت به نسخه قبل:
- فقط katana (به‌جای katana+gospider همزمان) برای کاهش بار روی اجرای زمان‌بندی‌شده.
  gospider همچنان توی watch_crawl.py (کرال دستی/سنگین‌تر روی همه) باقی می‌مونه.
- کرال به‌ازای هر دامنه‌ی ریشه جدا اجرا می‌شه (نه یک‌جا روی همه‌ی تارگت‌ها)، تا هم
  scope کنترل‌شده باشه هم بشه program_name درست هر URL رو resolve کرد.
- concurrency / rate-limit / depth صریح و پایین‌تر، متناسب با سروری که بیشتر از
  ۲-۳ برنامه همزمان جواب نمی‌ده.
- نتایج در کالکشن Urls (مونگو) ذخیره می‌شن، نه فقط فایل — همراه با پارامترهای
  استخراج‌شده از query string هر URL (پیش‌نیاز فاز بعدی: param discovery).
- fetch تاریخچه‌ی robots.txt از وی‌بک‌مشین موازی شده (قبلاً سریال بود، تا ۱۰ دقیقه طول می‌کشید).
"""

import os
import sys
import re
import subprocess
import requests
import gzip
import shutil
import html
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
# مسیر import رو با ساختار واقعی پروژه‌ت هماهنگ کن (database/db.py یا db.py)
from database.db import Http, bulk_store_crawl_results

OUT_DIR = Path("/opt/watch/crawl/output")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
API = "http://127.0.0.1:5000/api/http/fresh?raw=1"

BAD_EXT = re.compile(
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|'
    r'mp4|webm|pdf|zip|rar|gz|xml|txt)(\?|$)',
    re.I
)

# ---------------- server-load tuning ----------------
KATANA_DEPTH        = 3   # was 5; requests were growing exponentially
KATANA_CONCURRENCY  = 5   # -c  8->5 : concurrent requests per host
KATANA_PARALLELISM  = 3   # -p  : concurrent hosts
KATANA_RATE_LIMIT   = 40  # -rl 60->40: requests/sec (total)
KATANA_TIMEOUT      = 8
KATANA_CRAWL_DURATION = "3m"  # -ct hard ceiling per run, defense against crawler traps
ROBOTS_WORKERS      = 5   # parallel robots.txt history fetches, 10 -> 5

# hard cap on URLs stored per domain per run -- a single seed can otherwise
# pull in an entire sitemap.xml (hundreds of thousands of URLs for a site
# like dell.com/indeed.com) and grind MongoDB to a halt
MAX_URLS_PER_DOMAIN = 5000
# --------------------------------------------------------------------------


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def get_fresh_targets():
    try:
        r = requests.get(API, headers={"X-API-Key": config().get("API_KEY", "")}, timeout=30)
        r.raise_for_status()
        lines = [x.strip() for x in r.text.splitlines() if x.strip().startswith("http")]
        cleaned = [u.rstrip("/") for u in lines if not BAD_EXT.search(u)]
        return sorted(set(cleaned))
    except Exception as e:
        log(f"Error getting targets: {e}")
        return []


def get_host(url):
    """هاست رو بدون پورت برمی‌گردونه (katana بعضی‌وقتا :443/:80 رو صریح توی URL می‌ذاره،
    و اگه با split ساده جدا کنیم پورت می‌چسبه به هاست و program_name resolve نمی‌شه)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def group_by_root_domain(urls):
    """گروه‌بندی ساده بر اساس دو لیبل آخر (برای دامنه‌هایی مثل .co.uk دقیق نیست،
    ولی برای هدف فعلی -- تفکیک برنامه‌ها از هم -- کافیه)."""
    by_domain = defaultdict(list)
    for u in urls:
        host = get_host(u)
        if not host:
            continue
        parts = host.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else host
        by_domain[root].append(u)
    return dict(by_domain)


PROGRAM_CACHE = {}

def resolve_program(host):
    """پیدا کردن program_name از روی subdomain با cache.
    اگر host خارج از scope باشد، Unknown برمی‌گرداند.
    """
    if host in PROGRAM_CACHE:
        return PROGRAM_CACHE[host]

    doc = Http.objects(subdomain=host).first()
    program_name = doc.program_name if doc else "Unknown"

    PROGRAM_CACHE[host] = program_name
    return program_name


def run_katana(targets_file, out_file):
    # NOTE: -kf all (robots.txt/sitemap.xml) intentionally dropped here --
    # a single sitemap on a large site can contain 100k-1M+ URLs, which is
    # exactly what caused the 2M-URL blowup from 3 seed hosts. That's kept
    # for the weekly watch_crawl_all.py run only, where it's an acceptable
    # one-time cost, not something we want every 12 hours.
    # -ct is a hard wall-clock ceiling so a crawler trap can't run forever
    # even if it generates near-infinite unique links (verify flag name
    # with `katana -h`, it may differ across versions).
    cmd = (
        f'katana -list "{targets_file}" '
        f'-d {KATANA_DEPTH} -jc -fs rdn '
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


TELEGRAM_MAX_FILE_MB = 45  # bot API hard limit is 50MB, leave margin


def send_telegram_file(file_path, caption=""):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return False

    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    upload_path = file_path

    if size_mb > TELEGRAM_MAX_FILE_MB:
        gz_path = f"{file_path}.gz"
        try:
            with open(file_path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            gz_size_mb = os.path.getsize(gz_path) / (1024 * 1024)
            if gz_size_mb <= TELEGRAM_MAX_FILE_MB:
                log(f"File was {size_mb:.1f}MB, gzip brought it to {gz_size_mb:.1f}MB")
                upload_path = gz_path
            else:
                log(f"File still {gz_size_mb:.1f}MB after gzip, skipping upload, "
                    f"sending summary only. Full file stays at: {file_path}")
                return send_telegram_message(
                    f"{caption}\n\n(File too large to send: {size_mb:.1f}MB, "
                    f"kept on server at {file_path})"
                )
        except Exception as e:
            log(f"gzip error: {e}, sending summary only")
            return send_telegram_message(caption)

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(upload_path, "rb") as f:
            r = requests.post(
                url,
                data={"chat_id": chat_id, "caption": caption[:1000]},
                files={"document": f},
                timeout=180
            )
        return r.status_code == 200
    except Exception as e:
        log(f"Telegram exception: {e}")
        return False


def send_telegram_message(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
        return r.status_code == 200
    except Exception as e:
        log(f"Telegram exception: {e}")
        return False


def main():
    log("=== Watch Crawl Fresh (v2) Started ===")
    targets = get_fresh_targets()
    log(f"Clean fresh targets: {len(targets)}")
    if not targets:
        log("No targets. Exit.")
        return

    by_domain = group_by_root_domain(targets)
    log(f"Grouped into {len(by_domain)} root domains: {list(by_domain.keys())}")

    domain_list = "\n".join(f"  - {d} ({len(u)} seeds)" for d, u in by_domain.items())
    send_telegram_message(f"Starting crawlFresh run\nDomains queued ({len(by_domain)}):\n{domain_list}")

    total_new = 0
    total_urls = 0

    for domain, urls in by_domain.items():
        log(f"\n--- Crawling {domain} ({len(urls)} seeds) ---")
        send_telegram_message(f"Now crawling {domain} [crawlFresh]\nSeeds: {len(urls)}")

        try:
            domain_dir = OUT_DIR / f"{domain}_{DATE}"
            domain_dir.mkdir(parents=True, exist_ok=True)

            seeds_file = domain_dir / "seeds.txt"
            seeds_file.write_text("\n".join(urls) + "\n")

            # ---------- Katana ----------
            katana_out = domain_dir / "katana.txt"
            crawled = set(run_katana(seeds_file, katana_out))

            if len(crawled) > MAX_URLS_PER_DOMAIN:
                log(f"{domain}: WARNING -- katana returned {len(crawled)} URLs, "
                    f"likely a crawler trap or huge sitemap. Capping to {MAX_URLS_PER_DOMAIN}.")
                crawled = set(sorted(crawled)[:MAX_URLS_PER_DOMAIN])

            all_urls = sorted(set(urls) | crawled)
            log(f"{domain}: katana added {len(all_urls) - len(urls)} new URLs")

            # ---------- Historical robots (فقط هاست‌های همین گروه، موازی) ----------
            hosts = sorted({get_host(u) for u in urls if get_host(u)})
            robots_urls = set()
            with ThreadPoolExecutor(max_workers=ROBOTS_WORKERS) as ex:
                futures = {ex.submit(fetch_robots_history, h): h for h in hosts}
                for fut in as_completed(futures):
                    robots_urls.update(fut.result())
            if robots_urls:
                log(f"{domain}: historical robots added {len(robots_urls)} URLs")
                all_urls = sorted(set(all_urls) | robots_urls)

            # ---------- Build entries and store in one bulk_write (not per-URL) ----------
            entries = []
            skipped_out_of_scope = 0
            for u in all_urls:
                host = get_host(u)
                if not host:
                    continue
                program_name = resolve_program(host)
                if program_name == "Unknown":
                    # host not in Http -- out of scope (e.g. third-party link katana
                    # pulled from JS). Skip, don't store.
                    skipped_out_of_scope += 1
                    continue
                if u in crawled:
                    source = "katana"
                elif u in robots_urls:
                    source = "wayback-robots"
                else:
                    source = "http-seed"

                clean_url = html.unescape(u)  # fixes "&amp" -> "&" before parsing, else params after it get missed
                parsed = urlparse(clean_url)
                entries.append({
                    "program_name": program_name,
                    "subdomain": host,
                    "url": clean_url,
                    "path": parsed.path or "/",
                    "params": sorted(set(parse_qs(parsed.query).keys())),
                    "source": source,
                })

            if skipped_out_of_scope:
                log(f"{domain}: skipped {skipped_out_of_scope} out-of-scope/third-party URLs")

            saved_new = bulk_store_crawl_results(entries)
            log(f"{domain}: bulk-stored {len(entries)} entries, {saved_new} new")

            total_new += saved_new
            total_urls += len(all_urls)

            # ---------- output file + telegram (best-effort, for quick review) ----------
            final_file = domain_dir / f"{domain}_final.txt"
            final_file.write_text("\n".join(all_urls) + "\n")

            caption = (
                f"Result -- {domain} [crawlFresh]\n"
                f"Seeds: {len(urls)} | Final: {len(all_urls)} | New in DB: {saved_new}"
            )
            send_telegram_file(str(final_file), caption)

        except Exception as e:
            log(f"ERROR crawling {domain}, skipping to next domain: {e}")
            send_telegram_message(f"crawlFresh: {domain} FAILED ({e}) -- continuing with next domain")
            continue

    summary = (
        f"crawlFresh run finished\n"
        f"Domains processed: {len(by_domain)}\n"
        f"Total URLs: {total_urls} | New in DB: {total_new}"
    )
    log(f"=== Done | Domains: {len(by_domain)} | Total URLs: {total_urls} | New in DB: {total_new} ===")
    send_telegram_message(summary)


if __name__ == "__main__":
    from backend.task_report import mark_finished
    try:
        main()
        mark_finished("success", 0)
    except Exception as e:
        mark_finished("failed", 1)
        log(f"FATAL: crawlFresh crashed before/outside the per-domain loop: {e}")
        send_telegram_message(f"crawlFresh CRASHED: {e}\nCheck server logs.")
        raise