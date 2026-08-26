import os

from dotenv import load_dotenv


load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "openrouter")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "")

AVALAI_API_KEY = os.getenv("AVALAI_API_KEY", "")
AVALAI_MODEL = os.getenv("AVALAI_MODEL", "")