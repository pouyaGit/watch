#!/usr/bin/env python3
import sys, os, json, tempfile, subprocess, asyncio
from datetime import datetime
from telegram import Bot
from telegram.request import HTTPXRequest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database.db import *
from config import config

async def send_message(text):
    chat_id = config().get("TELEGRAM_CHAT_ID")
    token = config().get("TELEGRAM_BOT_TOKEN")
    request = HTTPXRequest(
        connection_pool_size=8,  # برای اتصالات همزمان
        read_timeout=60,         # timeout خواندن پاسخ
        write_timeout=60,        # timeout نوشتن (ارسال)
        connect_timeout=60,      # timeout اتصال
        pool_timeout=60          # timeout استخر اتصالات
    )
    bot = Bot(token=token, request=request)
    try:
        await bot.send_message(chat_id=chat_id, text=text)
        print("پیام ارسال شد!")
    except Exception as e:
        print(f"خطا: {e}")

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class colors:
    GRAY = "\033[90m"
    RESET = "\033[0m"

def create_temp_file(subdomains_array):
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as temp_file:
        for sub in subdomains_array:
            temp_file.write(f"{sub}\n")
        return temp_file.name
    
def run_command_in_zsh(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[{current_time()}] Error executing command: {result.stderr}")
            return False
        return result.stdout
    except Exception as e:
        print(f"[{current_time()}] Exception in run_command_in_zsh: {e}")
        return []

def nuclei_all(subdomains_array):
    temp_file_path = create_temp_file(subdomains_array)

    try:
        for subdomain in subdomains_array:
            command = (
                f"nuclei -l {temp_file_path} -config {config().get('WATCH_DIR')}nuclei/public-config.yaml "
            )

            print(f"{colors.GRAY}Executing HTTPx: {command}{colors.RESET}")
            results = run_command_in_zsh(command)
            
            if results != '':
                #send_message
                asyncio.run(send_message(f"Nuclei results: {results}"))

        
        return True
    finally:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

if __name__ == "__main__":
    https_obj = Http.objects().all()

    if https_obj:
        print(f"[{current_time()}] running Nuclei module for all http services")
        nuclei_all([http_obj.url for http_obj in https_obj])
        