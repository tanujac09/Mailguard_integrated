"""
Central configuration. Everything is read from environment variables
(loaded from a .env file in local dev). Nothing secret is hard-coded.
"""
import os
from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default)


class Settings:
    SECRET_KEY: str = _get("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(_get("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

    ANALYST_USERNAME: str = _get("ANALYST_USERNAME", "analyst")
    ANALYST_PASSWORD_HASH: str = _get("ANALYST_PASSWORD_HASH", "")

    DATABASE_URL: str = _get("DATABASE_URL", "sqlite:///./mailguard.db")

    FRONTEND_ORIGIN: str = _get("FRONTEND_ORIGIN", "http://localhost:5173")

    IPINFO_TOKEN: str = _get("IPINFO_TOKEN", "")
    VIRUSTOTAL_API_KEY: str = _get("VIRUSTOTAL_API_KEY", "")
    ANTHROPIC_API_KEY: str = _get("ANTHROPIC_API_KEY", "")

    FLAG_THRESHOLD: int = int(_get("FLAG_THRESHOLD", "40"))
    FRAUD_THRESHOLD: int = int(_get("FRAUD_THRESHOLD", "70"))

    # ---- NLP engine (transformer + TF-IDF/LogisticRegression) ------
    # The TF-IDF/LR model trains once from backend/data/email_text.csv
    # and caches to backend/app/model_cache/ - always on, no download.
    # The transformer (~250MB download on first run) is optional: turn
    # it off for a fast/offline demo and the engine falls back to
    # TF-IDF + regex only.
    USE_TRANSFORMER_MODEL: bool = _get("USE_TRANSFORMER_MODEL", "true").lower() in ("1", "true", "yes")


settings = Settings()


def validate_startup_config():
    """Fail loudly at startup instead of quietly running insecurely."""
    problems = []
    if not settings.SECRET_KEY or settings.SECRET_KEY.startswith("change_this"):
        problems.append(
            "SECRET_KEY is not set. Generate one with: "
            "python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if not settings.ANALYST_PASSWORD_HASH:
        problems.append(
            "ANALYST_PASSWORD_HASH is not set. Generate one with: "
            "python -c \"from passlib.hash import bcrypt; print(bcrypt.hash('YOUR_PASSWORD'))\""
        )
    if problems:
        raise RuntimeError(
            "MailGuard refused to start because of missing configuration:\n- "
            + "\n- ".join(problems)
            + "\n\nSee backend/.env.example for instructions."
        )
