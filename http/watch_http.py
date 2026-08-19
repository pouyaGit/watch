#!/usr/bin/env python3
import sys, os, json, tempfile
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db import *
from config import config
from utils.common import colors, current_time, run_command_in_zsh_http

def httpx_bulk(subdomains, domain):
    if not subdomains:
        return

    # نوشتن ساب‌دامین‌ها در فایل موقت
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        for sub in subdomains:
            f.write(sub + '\n')
        temp_file = f.name

    try:
        httpx_bin = config().get('HTTPX_BIN', '/root/go/bin/httpx')

        # تنظیمات خیلی سریع‌تر
        command = (
            f"{httpx_bin} -l {temp_file} "
            "-silent -json -favicon -fhr -tech-detect -irh -include-chain "
            "-timeout 7 -retries 2 "
            "-threads 15 -rate-limit 15 "
            "-ports 443 "
            "-random-agent"
        )

        print(f"{colors.GRAY}[{current_time()}] Running bulk httpx on {len(subdomains)} subdomains for {domain}{colors.RESET}")
        print(f"{colors.GRAY}Command: {command}{colors.RESET}")

        results = run_command_in_zsh_http(command)

        if not results:
            print(f"[{current_time()}] No results from httpx for {domain}")
            return

        count = 0
        for line in results.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                json_obj = json.loads(line)
                subdomain = json_obj.get("input") or json_obj.get("host") or ""
                if not subdomain:
                    continue

                upsert_http({
                    "subdomain": subdomain,
                    "scope": domain,
                    "ips": json_obj.get("a", []) or json_obj.get("ip", []),
                    "tech": json_obj.get("tech", []) or [],
                    "title": json_obj.get("title", "") or "",
                    "status_code": json_obj.get("status_code", 0) or 0,
                    "headers": json_obj.get("header", {}) or {},
                    "url": json_obj.get("url", "") or "",
                    "final_url": json_obj.get("final_url", "") or "",
                    "favicon": json_obj.get("favicon", "") or "",
                })
                count += 1
            except Exception as e:
                print(f"[{current_time()}] Error parsing line: {e}")
                continue

        print(f"[{current_time()}] Finished {domain} → {count} HTTP results saved")

    finally:
        os.unlink(temp_file)


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else False

    if not domain:
        print("Usage: watch_http.py domain")
        sys.exit(1)

    # فقط ساب‌دامین‌های زنده و غیر internal
    obj_lives = LiveSubdomains.objects(scope=domain, cdn__ne="Internal")
    subdomains = [obj.subdomain for obj in obj_lives]

    if subdomains:
        print(f"[{current_time()}] Running HTTPx for '{domain}' ({len(subdomains)} live subdomains)")
        httpx_bulk(subdomains, domain)
    else:
        print(f"[{current_time()}] No live subdomains found for {domain}")