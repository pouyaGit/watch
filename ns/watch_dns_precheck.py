#!/usr/bin/env python3
"""
watch_dns_precheck.py — قدم ۱ فلوچارت DNSBrute استادت

چک می‌کنه یه ساب‌دامین کاملاً ساختگی و ناموجود (مثل xk3f9d81jd.domain.tld) A record
داره یا نه. اگه داشت => دامنه wildcard کلیه => بروت‌فورس روش بی‌فایده‌ست، رد می‌شیم.
اگه نداشت => می‌شه ادامه داد (قدم‌های ShuffleDNS+DNSGen، که مرحله‌ی بعدن).

نتیجه برای هر دامنه‌ی هر برنامه در تلگرام فرستاده می‌شه.

Usage:
  python3 watch_dns_precheck.py
"""

import subprocess
import random
import string
import sys
import os
from datetime import datetime

import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config
from database.db import Programs


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def random_label(length=15):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def has_wildcard(domain, timeout=3):
    """
    دقیقاً طبق قدم ۱ فلوچارت: یه ساب‌دامین تصادفی/ناموجود رو تست می‌کنه.
    True  => A record برگردوند => wildcard کلی => بروت‌فورس بی‌فایده
    False => چیزی برنگردوند => قابل بروت‌فورسه
    None  => خود dig خطا داد (شبکه/دامنه نامعتبر)، نامشخص
    """
    test_fqdn = f"{random_label()}.{domain}"
    try:
        result = subprocess.run(
            ["dig", "+short", f"+time={timeout}", "+tries=1", "A", test_fqdn],
            capture_output=True, text=True, timeout=timeout + 2
        )
        ips = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return len(ips) > 0
    except Exception as e:
        log(f"dig error for {domain}: {e}")
        return None


def send_telegram(text):
    token = config().get("TELEGRAM_BOT_TOKEN")
    chat_id = config().get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log("Telegram not configured")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": text[:4000]},
            timeout=30
        )
    except Exception as e:
        log(f"Telegram error: {e}")


def main():
    programs = list(Programs.objects().all())
    log(f"Checking bruteforce feasibility for {len(programs)} programs...")

    can_bf, cannot_bf, unknown = [], [], []

    for p in programs:
        for domain in (p.scopes or []):
            result = has_wildcard(domain)
            label = f"{p.program_name} → {domain}"
            if result is True:
                cannot_bf.append(label)
                log(f"[wildcard] {domain} -- cannot bruteforce")
            elif result is False:
                can_bf.append(label)
                log(f"[ok] {domain} -- can bruteforce")
            else:
                unknown.append(label)
                log(f"[?] {domain} -- dig failed, unknown")

    lines = ["🧱 DNS Bruteforce Feasibility Check"]
    if can_bf:
        lines.append("\n✅ قابل بروت‌فورس:")
        lines += [f"  • {d}" for d in can_bf]
    if cannot_bf:
        lines.append("\n🚫 غیرقابل (wildcard کلی روی کل دامنه):")
        lines += [f"  • {d}" for d in cannot_bf]
    if unknown:
        lines.append("\n⚠️ نامشخص (خطای dig):")
        lines += [f"  • {d}" for d in unknown]

    msg = "\n".join(lines)
    log(msg)
    send_telegram(msg)

    # این لیست، ورودی قدم بعدی (ShuffleDNS + Wordlist) خواهد بود
    return can_bf


if __name__ == "__main__":
    main()