# database/telegram.py
from telegram import Bot
from telegram.request import HTTPXRequest
from telegram.error import TelegramError, NetworkError, TimedOut
import asyncio
from config import config

async def send_telegram_message(text: str, chat_id: int = None) -> bool:
    """
    Send message to Telegram with retry logic
    
    Args:
        text: Message text (supports HTML formatting)
        chat_id: Telegram chat ID
    
    Returns:
        bool: True if sent successfully, False otherwise
    """
    token = config().get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("⚠️  TELEGRAM_BOT_TOKEN not configured")
        return False

    if chat_id is None:
        chat_id = config().get("TELEGRAM_CHAT_ID")
        if not chat_id:
            print("⚠️  TELEGRAM_CHAT_ID not configured")
            return False
        chat_id = int(chat_id)

    # Configure request with reasonable timeouts
    request = HTTPXRequest(
        connection_pool_size=8,
        connect_timeout=10.0,
        read_timeout=30.0,
        write_timeout=30.0,
        pool_timeout=10.0
    )
    
    bot = Bot(token=token, request=request)
    
    # Retry logic with exponential backoff
    max_retries = 3
    for attempt in range(max_retries):
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode='HTML'
            )
            return True
            
        except TimedOut:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"⏱️  Timeout, retrying in {wait_time}s... ({attempt + 1}/{max_retries})")
                await asyncio.sleep(wait_time)
            else:
                print(f"❌ Telegram timeout after {max_retries} attempts")
                return False
                
        except (NetworkError, TelegramError) as e:
            print(f"❌ Telegram error: {e}")
            return False
            
        except Exception as e:
            print(f"❌ Unexpected error sending Telegram: {e}")
            return False
    
    return False


def send_message(text: str, chat_id: int = None) -> bool:
    """Synchronous wrapper for send_telegram_message"""
    return asyncio.run(send_telegram_message(text, chat_id))
