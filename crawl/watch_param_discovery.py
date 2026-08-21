#!/usr/bin/env python3
"""
watch_param_discovery.py — Hidden Parameter Discovery با x8، روی اندپوینت‌های یکتا

چرا رو Endpoints کار می‌کنیم نه Urls؟
چون Urls سطح URL کامله (با query) و ۸۰۰هزار رکورده -- اجرای x8 رو همه‌شون هم بی‌فایده‌ست
(چندبار تست یه path با query متفاوت) هم منابع سرور رو نابود می‌کنه.
Endpoints سطح path یکتاست (بعد از مایگریشن/کرال‌های جدید) -- تعدادش خیلی کمتره.

Usage:
  python3 watch_param_discovery.py --max-minutes 180
  python3 watch_param_discovery.py --filter dell.com --max-minutes 20   # تست
"""

import os
import sys
import re
import json
import time
import argparse
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from database.db import Endpoints

WORDLIST = os.getenv(
    "X8_WORDLIST",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
)
# اگه SecLists نصب نیست، یه wordlist کوچیک خودت بساز یا مسیر رو با env عوض کن:
#   export X8_WORDLIST=/opt/watch/wordlists/params_base.txt

WORDLIST_DIR = Path("/opt/watch/wordlists")
WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

X8_TIMEOUT = 60            # ثانیه، هر اندپوینت
X8_RATE_LIMIT_DELAY = 0.5  # فاصله‌ی بین درخواست‌های x8 به هدف بعدی (ثانیه)، ملایم برای سرور

START_TIME = time.time()


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def elapsed_minutes():
    return (time.time() - START_TIME) / 60


def run_x8(url):
    """
    اجرای x8 روی یه URL و برگردوندن لیست پارامترهای پیدا‌شده.
    تلاش می‌کنه اول JSON پارس کنه، اگه نشد fallback به regex متنی.
    فلگ‌های دقیق x8 رو با `x8 --help` چک کن -- ممکنه بین نسخه‌ها فرق کنه.
    """
    if subprocess.call(["which", "x8"], stdout=subprocess.DEVNULL) != 0:
        log("x8 not found in PATH")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        "x8",
        "-u", url,
        "-w", WORDLIST,
        "-O", "json",
        "-o", out_path,
        "-c", "5",          # concurrency per url (پیش‌فرض 1 -- خیلی کند بود برای 82k اندپوینت)
        "-W", "1",           # تعداد url همزمان -- 1 نگهش می‌داریم، سرور محدوده
        "--timeout", "10",
        "--verify",          # پارامترهای پیدا‌شده رو دوباره چک می‌کنه، false positive کمتر
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=X8_TIMEOUT)
    except subprocess.TimeoutExpired:
        log(f"x8 timeout: {url}")
        return []
    except Exception as e:
        log(f"x8 error on {url}: {e}")
        return []

    params = set()
    try:
        with open(out_path, "r", errors="ignore") as f:
            data = json.load(f)
        # فرمت واقعی x8: [{"method":..,"url":..,"status":..,"found_params":[...],"injection_place":..}]
        if isinstance(data, list):
            for item in data:
                for p in item.get("found_params", []):
                    params.add(p)
        elif isinstance(data, dict):
            for p in data.get("found_params", []):
                params.add(p)
    except Exception:
        log(f"Could not parse x8 JSON output for {url} — بررسی دستی کن: {out_path}")
        return []
    finally:
        try:
            os.remove(out_path)
        except Exception:
            pass

    return sorted(params)


def get_pending_endpoints(filter_arg=None, limit=None):
    query = Endpoints.objects(x8_checked=False)
    if filter_arg:
        f = filter_arg.lower()
        query = query.filter(subdomain__icontains=f)
    query = query.order_by('-hit_count')  # پرتکرارترین اندپوینت‌ها اول
    if limit:
        query = query[:limit]
    return list(query)


def export_wordlists():
    """برای هر برنامه یه فایل وردلیست از پارامترهای کشف‌شده می‌سازه."""
    programs = Endpoints.objects.distinct("program_name")
    for prog in programs:
        params = set()
        for ep in Endpoints.objects(program_name=prog).only("params"):
            params.update(ep.params or [])
        if not params:
            continue
        out_file = WORDLIST_DIR / f"{prog}_params.txt"
        out_file.write_text("\n".join(sorted(params)) + "\n")
        log(f"Wordlist saved: {out_file} ({len(params)} params)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default=None, help="فقط ساب‌دامین/کلمه‌ی خاص")
    parser.add_argument("--max-minutes", type=float, default=None)
    parser.add_argument("--limit", type=int, default=None, help="حداکثر تعداد اندپوینت در این اجرا")
    args = parser.parse_args()

    if not os.path.exists(WORDLIST):
        log(f"⚠ Wordlist not found: {WORDLIST} — قبل از ادامه یه wordlist معتبر بذار (env: X8_WORDLIST)")
        return

    log(f"=== Param Discovery Started | filter={args.filter or 'NONE'} | "
        f"max_minutes={args.max_minutes or 'unlimited'} ===")

    endpoints = get_pending_endpoints(args.filter, args.limit)
    log(f"Pending endpoints: {len(endpoints)}")

    checked = 0
    found_total = 0

    for ep in endpoints:
        if args.max_minutes and elapsed_minutes() >= args.max_minutes:
            log(f"Time budget hit after {checked} endpoints — بقیه اجرای بعدی انجام می‌شن")
            break

        if not ep.example_url:
            continue

        new_params = run_x8(ep.example_url)
        if new_params:
            merged = sorted(set((ep.params_from_x8 or []) + new_params))
            ep.params_from_x8 = merged
            ep.params = sorted(set((ep.params or []) + merged))
            found_total += len(new_params)
            log(f"[+] {ep.example_url} -> {new_params}")

        ep.x8_checked = True
        ep.x8_last_checked = datetime.now()
        ep.last_update = datetime.now()
        ep.save()

        checked += 1
        time.sleep(X8_RATE_LIMIT_DELAY)

    log(f"=== Done | Endpoints checked: {checked} | New params found: {found_total} ===")

    export_wordlists()


if __name__ == "__main__":
    main()