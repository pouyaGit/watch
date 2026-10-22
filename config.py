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
        'API_KEY': os.getenv('API_KEY', ''),
        'DASHBOARD_USER': os.getenv('DASHBOARD_USER', 'admin'),
        'DASHBOARD_PASS_HASH': os.getenv('DASHBOARD_PASS_HASH', ''),
        'DASHBOARD_SECRET': os.getenv('DASHBOARD_SECRET', ''),
        'DASHBOARD_SESSION_TTL': os.getenv('DASHBOARD_SESSION_TTL', '43200'),
    }

def get_path(*paths):
    """Helper function to safely join paths"""
    return os.path.join(config()['WATCH_DIR'], *paths)