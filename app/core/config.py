from pathlib import Path
from pydantic_settings import BaseSettings


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    APP_NAME: str = "Cyber Sentinel XDR"
    APP_VERSION: str = "2.0.0"
    APP_ENV: str = "LAB"
    DEBUG: bool = True

    DATABASE_URL: str = (
        "sqlite+aiosqlite:///./data/cyber_sentinel.db"
    )

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    RISK_THRESHOLD: int = 70
    CORRELATION_WINDOW_MINUTES: int = 10

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
