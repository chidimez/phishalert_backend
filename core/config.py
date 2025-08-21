from __future__ import annotations
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Auth/JWT ---
    SECRET_KEY: str = Field(default="change-me")           # override in env
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_CODE_EXPIRE_MINUTES: int = 10

    # --- SMTP ---
    SMTP_SERVER: str = "sandbox.smtp.mailtrap.io"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""                                # <- empty by default
    SMTP_PASSWORD: str = ""                                # <- empty by default
    FROM_EMAIL: str = "noreply@phishalert.com"

    # --- Agent Two local DB paths (use Path) ---
    PHISHTANK_DB_PATH: Path = Path("artifacts/phishtank/online-valid.json")
    GEOLITE2_CITY_DB: Path = Path("artifacts/geoip/GeoLite2-City.mmdb")
    GEOLITE2_ASN_DB: Path = Path("artifacts/geoip/GeoLite2-ASN.mmdb")

    # --- Agent One model paths ---
    BERT_BINARY: Path = Path("artifacts/agent_one_bert_binary.pt")
    TOKENIZER: Path = Path("artifacts/tokenizer.json")      # ✅ fixed env name

    # --- LLM mode switches ---
    LLM_MODE: str = "openai"                                # "openai" | "local"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"

    # Optional local LLM settings
    LOCAL_LLM_MODEL: str = "llama3.1"
    LOCAL_LLM_BACKEND: str = "ollama"                       # "ollama" | "llama_cpp"

    # --- Autonomy knobs ---
    AUTO_DEEP_SCAN: bool = True
    MAX_ACTIONS_PER_EMAIL: int = 4

    # Agent autonomy policy
    # (Note: Pydantic will parse JSON strings into dict automatically if passed via env)
    AUTO_APPROVE: dict = Field(
        default_factory=lambda: {
            "high_risk": {
                "mark_as_phishing": True,
                "notify_security_team": True,
                "quarantine_email": True,
                "deep_scan": True,
            },
            "suspicious": {"deep_scan": True},
            "safe": {},
        }
    )

    # Settings behavior
    model_config = SettingsConfigDict(
        env_file=".env",                # load from .env automatically
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Validators / sanity checks (optional but helpful) ---

    @field_validator("LLM_MODE")
    @classmethod
    def _valid_llm_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in {"openai", "local"}:
            raise ValueError("LLM_MODE must be 'openai' or 'local'")
        return v

    @field_validator("LOCAL_LLM_BACKEND")
    @classmethod
    def _valid_backend(cls, v: str) -> str:
        v = v.lower()
        if v not in {"ollama", "llama_cpp"}:
            raise ValueError("LOCAL_LLM_BACKEND must be 'ollama' or 'llama_cpp'")
        return v

    @field_validator("PHISHTANK_DB_PATH", "GEOLITE2_CITY_DB", "GEOLITE2_ASN_DB",
                     "BERT_BINARY", "TOKENIZER")
    @classmethod
    def _as_path(cls, v: Path) -> Path:
        # Ensure we always end up with a Path (BaseSettings might give str)
        return Path(v)


settings = Settings()

# Alias plain module-level constants if you rely on them elsewhere
LLM_MODE = settings.LLM_MODE
OPENAI_API_KEY = settings.OPENAI_API_KEY
OPENAI_MODEL = settings.OPENAI_MODEL

LOCAL_LLM_MODEL = settings.LOCAL_LLM_MODEL
LOCAL_LLM_BACKEND = settings.LOCAL_LLM_BACKEND

AUTO_DEEP_SCAN = settings.AUTO_DEEP_SCAN
AUTO_APPROVE = settings.AUTO_APPROVE
MAX_ACTIONS_PER_EMAIL = settings.MAX_ACTIONS_PER_EMAIL
