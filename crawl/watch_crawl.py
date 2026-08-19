#!/usr/bin/env python3
"""
Usage:
  python3 watch_crawl.py                     # همه HTTPها
  python3 watch_crawl.py indeed              # فقط برنامه indeed
  python3 watch_crawl.py indeed.com          # فقط دامنه indeed.com
"""

import os, sys, re, subprocess, requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

OUT_DIR = Path("/opt/watch/crawl/output")
OUT_DIR.mkdir(parents=True, exist_ok=True)
DATE = datetime.now().strftime("%Y%m%d_%H%M%S")

BAD_EXT = re.compile(
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|mp4|webm|pdf|zip|rar|gz)(\?|$)',
    re.I
)

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def get_http_targets(filter_arg=None):
    """از API همه HTTPها را می‌گیرد و فیلتر می‌کند"""
    try:
        r = requests.get("http://127.0.0.1:5000/api/http/all?raw=1", timeout=60)
        r.raise_for_status()
        urls = [x.strip() for x in r.text.splitlines() if x.strip().startswith("http")]
    except Exception as e:
        log(f"API error: {e}")
        return {}

    # گروه‌بندی بر اساس دامنه اصلی (scope)
    by_domain = defaultdict(list)
    for u in urls:
        if BAD_EXT.search(u):
            continue
        try:
            host = u.split("/")[2].lower()
        except:
            continue

        if filter_arg:
            f = filter_arg.lower()
            if f not in host and f not in u.lower():
                continue

        # دامنه ریشه ساده
        parts = host.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
        else:
            root = host
        by_domain[root].append(u.rstrip("/"))

    # unique
    for d in by_domain:
        by_domain[d] = sorted(set(by_domain[d]))
    return dict(by_domain)

def run_gospider(targets_file, out_dir):
    if subprocess.call(["which", "gospider"], stdout=subprocess.DEVNULL) != 0:
        log("gospider not found")
        return set()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = (
        f'gospider -S "{targets_file}" -d 5 -c 6 --robots --sitemap -a '
        f'-o "{out_dir}" '
        f'--blacklist ".(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|pdf|zip)"'
    )
    log(f"Gospider: {cmd}")
    subprocess.run(cmd, shell=True, timeout=7200)
    found = set()
    for f in out_dir.rglob("*"):
        if f.is_file():
            try:
                for line in f.read_text(errors="ignore").splitlines():
                    if line.startswith("http"):
                        found.add(line.strip())
            except:
                pass
    return found

def wayback_robots(domains):
    found = set()
    for domain in domains:
        try:
            r = requests.get(
                f"https://web.archive.org/web/timemap/link/{domain}/robots.txt",
                timeout=10
            )
            found.update(re.findall(r'https?://[^"<>\s]+', r.text))
        except:
            continue
    return found

def send_telegram(file_path, caption):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as f:
            r = requests.post(url, data={
                "chat_id": chat_id,
                "caption": caption[:1000]
            }, files={"document": f}, timeout=180)
        log(f"Telegram → {file_path} | {r.status_code}")
    except Exception as e:
        log(f"Telegram error: {e}")

def main():
    filter_arg = sys.argv[1] if len(sys.argv) > 1 else None
    log(f"=== Watch Crawl Started | filter={filter_arg or 'ALL'} ===")

    by_domain = get_http_targets(filter_arg)
    if not by_domain:
        log("No targets found")
        return

    log(f"Domains to crawl: {list(by_domain.keys())}")

    for domain, urls in by_domain.items():
        log(f"\n--- Crawling {domain} ({len(urls)} seeds) ---")
        domain_dir = OUT_DIR / f"{domain}_{DATE}"
        domain_dir.mkdir(exist_ok=True)

        seeds_file = domain_dir / "seeds.txt"
        seeds_file.write_text("\n".join(urls) + "\n")

        # Gospider
        gospider_urls = run_gospider(seeds_file, domain_dir / "gospider")

        # Wayback robots
        robots_urls = wayback_robots([domain] + [u.split("/")[2] for u in urls[:30]])

        final = sorted(set(urls) | gospider_urls | robots_urls)
        final_file = domain_dir / f"{domain}_crawl.txt"
        final_file.write_text("\n".join(final) + "\n")

        log(f"{domain} → {len(final)} unique URLs")

        caption = (
            f"🕷 Crawl Result\n"
            f"Domain: {domain}\n"
            f"Seeds: {len(urls)}\n"
            f"Final unique: {len(final)}\n"
            f"Time: {DATE}"
        )
        send_telegram(str(final_file), caption)

    log("=== All Done ===")

if __name__ == "__main__":
    main()