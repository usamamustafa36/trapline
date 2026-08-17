"""Application configuration, loaded from environment."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg://trapline:trapline@localhost:5432/trapline"

    # Security
    secret_key: str = "change-me-in-prod-please-0000000000000000"
    # Fernet key for encrypting per-VPS OTX keys. Empty => generated at boot (dev only).
    fernet_key: str = ""

    # Behaviour — demo data is OFF by default; production stays clean and fills
    # only from real shipper ingestion. Opt in with SEED_ON_START=true for a demo.
    seed_on_start: bool = False

    # Archived-dataset mode. When the console is showing a historical capture rather
    # than a live fleet, wall-clock recency makes every sensor read "offline" forever,
    # which is both useless and misleading. With this on, sensor status is computed
    # relative to the newest event in the dataset, so "reporting" means the sensor was
    # still shipping at the end of the capture window and "stopped" means it died
    # partway through. The UI labels the dataset as archived either way; it never
    # claims to be live.
    dataset_mode: bool = False
    api_key_prefix: str = "lsk_"  # Trapline key

    # Ingestion guardrails
    max_events_per_batch: int = 500
    ingest_rate_limit_per_min: int = 6000  # per-VPS key

    # AlienVault OTX — used by the central enrichment worker to classify
    # every unique source IP (backfill + continuous for new events).
    otx_api_key: str = ""

    # CORS
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
