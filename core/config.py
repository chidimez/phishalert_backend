import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_CODE_EXPIRE_MINUTES: int = 10
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "sandbox.smtp.mailtrap.io")
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "c9b19a2bf3db61")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "ebcb82f3692888")
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", "noreply@phishalert.com")

settings = Settings()