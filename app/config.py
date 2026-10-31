"""Application configuration and local data paths."""
import os, secrets, warnings
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"
REPORT_DIR = DATA_DIR / "reports"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
APP_ENV = os.getenv("APP_ENV", "development").lower()
SECRET_KEY = os.getenv("APP_SECRET_KEY", "").strip()
if not SECRET_KEY or SECRET_KEY.lower().startswith("replace-this"):
    if APP_ENV == "production":
        raise RuntimeError("APP_SECRET_KEY must be configured for production")
    # Local-only fallback is deliberately not a source-code constant. It is ignored by git.
    key_file = DATA_DIR / ".local_secret_key"
    if key_file.exists():
        SECRET_KEY = key_file.read_text(encoding="utf-8").strip()
    else:
        SECRET_KEY = secrets.token_urlsafe(48)
        key_file.write_text(SECRET_KEY, encoding="utf-8")
        try: key_file.chmod(0o600)
        except OSError: pass
    warnings.warn("APP_SECRET_KEY is not configured; using a local-only generated key. Set it in .env for a stable explicit configuration.", RuntimeWarning)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'traceforge.db').as_posix()}")
MAX_UPLOAD_MB = max(1, min(100, int(os.getenv("MAX_UPLOAD_MB", "10"))))
ACCESS_TOKEN_MINUTES = max(5, min(1440, int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))))
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
