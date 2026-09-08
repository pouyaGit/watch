import os

from dotenv import load_dotenv


load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "openrouter")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "")

AVALAI_API_KEY = os.getenv("AVALAI_API_KEY", "")
AVALAI_MODEL = os.getenv("AVALAI_MODEL", "")

# MongoDB connection for the research-only track (Watch asset
# correlation). Credentials come exclusively from the environment;
# no default contains secrets. An empty value means "not configured"
# and research entry points must fail closed with a clear message.
WATCH_MONGO_URI = os.getenv("WATCH_MONGO_URI", "")


def require_mongo_uri() -> str:
    if not WATCH_MONGO_URI:
        raise RuntimeError(
            "WATCH_MONGO_URI is not configured; refusing to run "
            "research without an explicit MongoDB connection."
        )
    return WATCH_MONGO_URI