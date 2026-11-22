from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_DIR = BASE_DIR / "reports" / "output"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = f"sqlite:///{BASE_DIR / 'cloudaudit360.db'}"
    secret_key: str = "dev-secret-change-me"
    app_env: str = "development"
    demo_mode: bool = True
    aws_region: str = "us-east-1"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_role_arn: str | None = None
    admin_username: str = "admin"
    admin_password: str = "admin123"
    session_max_age: int = 60 * 60 * 12  # 12 hours


@lru_cache
def get_settings() -> Settings:
    return Settings()
