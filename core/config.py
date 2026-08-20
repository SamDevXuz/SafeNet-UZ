from functools import lru_cache
from typing import Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    bot_token: SecretStr
    log_level: str = "INFO"
    request_timeout: float = 10.0
    virustotal_api_key: Optional[str] = None
    urlhaus_api_key: Optional[str] = None
    google_safebrowsing_api_key: Optional[str] = None

    @property
    def log_level_upper(self) -> str:
        return self.log_level.upper()


@lru_cache
def get_settings() -> Settings:
    return Settings()