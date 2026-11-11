import os
from dotenv import load_dotenv

# Resolve backend root directory (two levels up from app/config.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")

# Load environment variables from .env file if it exists
load_dotenv(dotenv_path=ENV_PATH)

# JWT Configuration (strictly loaded from environment, never hardcoded)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError(
        "Missing required environment variable: 'JWT_SECRET_KEY'. "
        "Please set it in your environment or inside backend/.env."
    )

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# AES-256 Encryption Configuration (32-byte key stored as 64-char hex)
AES_SECRET_KEY = os.getenv("AES_SECRET_KEY")
if not AES_SECRET_KEY:
    raise RuntimeError(
        "Missing required environment variable: 'AES_SECRET_KEY'. "
        "Please set it in your environment or inside backend/.env."
    )

try:
    AES_KEY_BYTES = bytes.fromhex(AES_SECRET_KEY.strip())
    if len(AES_KEY_BYTES) != 32:
        raise ValueError
except ValueError:
    raise RuntimeError(
        "AES_SECRET_KEY must be a 64-character hexadecimal string representing a 256-bit (32-byte) key."
    )

# SQLite Database Path (defaults to backend/qr_shield.db)
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "qr_shield.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")
