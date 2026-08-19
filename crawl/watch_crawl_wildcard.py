#!/usr/bin/env python3
"""
Usage:
  python3 watch_wildcard_crawl.py wildcards.txt

wildcards.txt example:
*.target.com
*.api.target.com
"""

import os, sys, re, subprocess, tempfile, requests
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

OUT_DIR = Path("/opt/watch/crawl/output/wildcard")
OUT_DIR.mkdir(parents=True, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def run(cmd):
    log(f"$ {cmd}")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
    return p.stdout.strip().splitlines()

def send_telegram(file_path, caption):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    try:
        with open(file_path, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                data={"chat_id": chat_id, "caption": caption[:1000]},
                files={"document": f},
                timeout=180
            )
        log(f"Telegram sent: {file_path}")
    except Exception as e:
        log(f"Telegram error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 watch_wildcard_crawl.py wildcards.txt")
        sys.exit(1)

    wc_file = Path(sys.argv[1])
    if not wc_file.exists():
        log("File not found")
        sys.exit(1)

    wildcards = [l.strip() for l in wc_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
    log(f"Wildcards: {wildcards}")

    work = OUT_DIR / DATE
    work.mkdir(exist_ok=True)

    all_final = []

    for wc in wildcards:
        domain = wc.replace("*.", "").strip()
        log(f"\n===== {wc} → {domain} =====")

        # 1. Subfinder
        subs_file = work / f"{domain}_subs.txt"
        run(f'subfinder -d {domain} -silent -all -o {subs_file}')
        subs = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()] if subs_file.exists() else []
        log(f"Subfinder: {len(subs)}")

        if not subs:
            continue

        # 2. Dnsx (live)
        live_file = work / f"{domain}_live.txt"
        run(f'cat {subs_file} | dnsx -silent -a -resp -o {live_file}')
        lives = []
        if live_file.exists():
            for line in live_file.read_text().splitlines():
                host = line.split()[0].strip()
                if host:
                    lives.append(host)
        lives = sorted(set(lives))
        log(f"Live: {len(lives)}")

        if not lives:
            continue

        # 3. Httpx
        http_file = work / f"{domain}_http.txt"
        run(f'cat {live_file} | awk \'{{print $1}}\' | httpx -silent -mc 200,201,301,302,401,403 -o {http_file}')
        https = [l.strip() for l in http_file.read_text().splitlines() if l.strip()] if http_file.exists() else []
        log(f"HTTP: {len(https)}")

        if not https:
            continue

        # 4. Gospider crawl
        seeds = work / f"{domain}_seeds.txt"
        seeds.write_text("\n".join(https) + "\n")
        gospider_dir = work / f"{domain}_gospider"
        gospider_dir.mkdir(exist_ok=True)
        run(
            f'gospider -S {seeds} -d 5 -c 5 --robots --sitemap -a -o {gospider_dir} '
            f'--blacklist ".(css|js|png|jpg|jpeg|gif|svg|ico|woff|mp4|pdf|zip)"'
        )

        crawl_urls = set(https)
        for f in gospider_dir.rglob("*"):
            if f.is_file():
                try:
                    for line in f.read_text(errors="ignore").splitlines():
                        if line.startswith("http"):
                            crawl_urls.add(line.strip())
                except:
                    pass

        final_file = work / f"{domain}_final.txt"
        final_sorted = sorted(crawl_urls)
        final_file.write_text("\n".join(final_sorted) + "\n")
        all_final.extend(final_sorted)

        log(f"Final {domain}: {len(final_sorted)}")
        send_telegram(str(final_file), f"Wildcard Crawl\n{wc}\nFinal: {len(final_sorted)}")

    # یک فایل کلی هم بفرست
    if all_final:
        all_file = work / f"ALL_wildcard_{DATE}.txt"
        all_file.write_text("\n".join(sorted(set(all_final))) + "\n")
        send_telegram(str(all_file), f"All Wildcard Results\n{DATE}")

    log("=== Wildcard Crawl Done ===")

if __name__ == "__main__":
    main()