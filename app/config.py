from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Alerta Clara"
    app_env: str = "development"
    database_url: str = "sqlite:///./alerta_clara.db"
    redis_url: str = "redis://localhost:6379/0"
    server_pepper: SecretStr = SecretStr("development-only-change-me")
    forwarded_allow_ips: str = "127.0.0.1"
    health_api_key: SecretStr | None = None

    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-5.4-nano-2026-03-17"
    allow_external_image_analysis: bool = False
    enable_google_safe_browsing: bool = False
    google_safe_browsing_api_key: SecretStr | None = None

    enable_network_checks: bool = True
    enable_threat_feeds: bool = False
    threat_feed_refresh_seconds: int = 900
    threat_feed_max_bytes: int = 25 * 1024 * 1024
    threat_feed_stale_hours: int = 6
    enable_qr_decode: bool = True
    enable_local_ocr: bool = True
    ocr_min_confidence: float = 0.35
    enable_ml_classifier: bool = True
    ml_classifier_path: str = "models/phishing_tfidf.joblib"
    ml_classifier_high_threshold: float = 0.70
    enable_browser_checks: bool = False
    browser_scanner_url: str = "http://scanner:8090"
    browser_scan_timeout_seconds: float = 18.0
    browser_scanner_token: SecretStr | None = None
    campaign_window_days: int = 30
    campaign_min_artifact_matches: int = 2
    review_api_key: SecretStr | None = None
    review_tokens: str | None = None
    rate_limit_analyses_per_minute: int = 30
    rate_limit_feedback_per_minute: int = 60
    rate_limit_use_redis: bool = False
    signal_timeout_seconds: float = 3.0
    body_retention_hours: int = 24
    retention_purge_interval_seconds: int = 3600
    ruleset_version: str = "2026.08.3"
    signalset_version: str = "2026.08.3"
    max_upload_bytes: int = 5 * 1024 * 1024

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> Settings:
        if self.app_env.lower() == "production":
            if self.server_pepper.get_secret_value() == "development-only-change-me":
                raise ValueError("SERVER_PEPPER debe configurarse en producción")
            if self.database_url.startswith("sqlite"):
                raise ValueError("Producción requiere Postgres, no SQLite")
            if not self.review_api_key and not self.review_tokens:
                raise ValueError(
                    "REVIEW_TOKENS o REVIEW_API_KEY debe configurarse en producción"
                )
            if not self.health_api_key:
                raise ValueError("HEALTH_API_KEY debe configurarse en producción")
            if self.enable_browser_checks and not self.browser_scanner_token:
                raise ValueError(
                    "BROWSER_SCANNER_TOKEN debe configurarse si se activa el navegador"
                )
        if self.enable_google_safe_browsing and not self.google_safe_browsing_api_key:
            raise ValueError(
                "GOOGLE_SAFE_BROWSING_API_KEY debe configurarse si se activa Safe Browsing"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
