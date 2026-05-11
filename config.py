import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def config():
    return {
        'WATCH_DIR': os.getenv('WATCH_DIR', '/opt/watch/'),
        'TELEGRAM_BOT_TOKEN': os.getenv('TELEGRAM_BOT_TOKEN', ''),
        'TELEGRAM_CHAT_ID': os.getenv('TELEGRAM_CHAT_ID', ''),
        'HTTPX_BIN': os.getenv('HTTPX_BIN', '/usr/local/bin/httpx'),
    }
