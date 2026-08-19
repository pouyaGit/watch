#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

OUT_DIR = Path("/opt/watch/crawl/output")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DATE = datetime.now().strftime("%Y%m%d_%H%M%S")
API = "http://127.0.0.1:5000/api/http/fresh?raw=1"

BAD_EXT = (
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|'
    r'mp4|webm|pdf|zip|rar|gz|xml|txt)(\?|$)'
)


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def get_fresh_targets():
    try:
        r = requests.get(API, timeout=30)
        r.raise_for_status()
        lines = [x.strip() for x in r.text.splitlines() if x.strip().startswith("http")]
        # فیلتر پسوندهای بی‌فایده
        import re
        cleaned = []
        for u in lines:
            if not re.search(BAD_EXT, u, re.I):
                cleaned.append(u.rstrip("/"))
        return sorted(set(cleaned))
    except Exception as e:
        log(f"Error getting targets: {e}")
        return []


def run_cmd(cmd, outfile=None):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3600)
        out = res.stdout or ""
        if outfile:
            Path(outfile).write_text(out)
        return out
    except Exception as e:
        log(f"Command failed: {e}")
        return ""


def send_telegram_file(file_path, caption=""):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return False

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as f:
            files = {"document": f}
            data = {"chat_id": chat_id, "caption": caption[:1000]}
            r = requests.post(url, data=data, files=files, timeout=120)
        if r.status_code == 200:
            log(f"Telegram sent: {file_path}")
            return True
        log(f"Telegram error: {r.text}")
        return False
    except Exception as e:
        log(f"Telegram exception: {e}")
        return False


def main():
    log("=== Watch Crawl Fresh Started ===")
    targets = get_fresh_targets()
    log(f"Clean fresh targets: {len(targets)}")

    if not targets:
        log("No targets. Exit.")
        return

    targets_file = OUT_DIR / f"targets_{DATE}.txt"
    targets_file.write_text("\n".join(targets) + "\n")

    all_urls = set(targets)

    # ---------- Gospider ----------
    if subprocess.call(["which", "gospider"], stdout=subprocess.DEVNULL) == 0:
        log("Running Gospider...")
        gospider_dir = OUT_DIR / f"gospider_{DATE}"
        gospider_dir.mkdir(exist_ok=True)
        cmd = (
            f'gospider -S "{targets_file}" -d 5 -c 5 --robots --sitemap -a '
            f'-o "{gospider_dir}" '
            f'--blacklist ".(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|pdf|zip)"'
        )
        run_cmd(cmd)

        # جمع‌آوری لینک‌های پیدا شده
        for f in gospider_dir.rglob("*"):
            if f.is_file():
                try:
                    for line in f.read_text(errors="ignore").splitlines():
                        if line.startswith("http"):
                            all_urls.add(line.strip())
                except:
                    pass
    else:
        log("gospider not found")

    # ---------- Katana ----------
    if subprocess.call(["which", "katana"], stdout=subprocess.DEVNULL) == 0:
        log("Running Katana...")
        katana_out = OUT_DIR / f"katana_{DATE}.txt"
        cmd = f'katana -list "{targets_file}" -d 5 -jc -kf all -silent -o "{katana_out}"'
        run_cmd(cmd)
        if katana_out.exists():
            for line in katana_out.read_text(errors="ignore").splitlines():
                if line.startswith("http"):
                    all_urls.add(line.strip())
    else:
        log("katana not found")

    # ---------- Historical robots ----------
    log("Running historical robots...")
    domains = sorted({u.split("/")[2] for u in targets if "://" in u})
    robots_urls = set()
    for domain in domains[:80]:  # محدودیت برای سرعت
        try:
            r = requests.get(
                f"https://web.archive.org/web/timemap/link/{domain}/robots.txt",
                timeout=8
            )
            import re
            found = re.findall(r'https?://[^"<>\s]+', r.text)
            robots_urls.update(found)
        except:
            continue

    robots_file = OUT_DIR / f"historical_robots_{DATE}.txt"
    robots_file.write_text("\n".join(sorted(robots_urls)) + "\n")
    all_urls.update(robots_urls)

    # ---------- Final unique sorted ----------
    final_file = OUT_DIR / f"crawl_all_unique_{DATE}.txt"
    final_sorted = sorted(all_urls)
    final_file.write_text("\n".join(final_sorted) + "\n")

    log(f"Final unique URLs: {len(final_sorted)}")
    log(f"Saved → {final_file}")

    # ارسال تلگرام
    caption = (
        f"🕷 Watch Crawl Fresh\n"
        f"Targets: {len(targets)}\n"
        f"Final unique: {len(final_sorted)}\n"
        f"Time: {DATE}"
    )
    send_telegram_file(str(final_file), caption)

    # اگر فایل خیلی بزرگ بود، فقط مسیر رو هم می‌تونی بفرستی
    # send_telegram_message(f"Crawl finished: {final_file}")

    log("=== Done ===")


if __name__ == "__main__":
    main()