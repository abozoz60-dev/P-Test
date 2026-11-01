"""Application configuration.

All settings are environment-driven. Safety-relevant defaults are
intentionally conservative (deny-by-default, low concurrency, safe checks only).
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PTEST_", env_file=".env", extra="ignore")

    # --- Platform ---
    app_name: str = "P-Test Assessment Platform"
    environment: str = "development"
    # Separate DB from any production/game DB by design.
    database_url: str = "sqlite:///./ptest.db"
    secret_key: str = "CHANGE-ME-dev-only-not-for-production"

    # Bootstrap admin (first run only; ignored once a user exists).
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "changeme-admin"

    # --- Safety controls (see docs/SAFETY.md) ---
    # Global kill switch. When true, no scan may start and running scans stop.
    emergency_stop: bool = False
    # Deny-by-default: a target must be explicitly registered AND approved.
    require_authorization_record: bool = True
    # Concurrency / rate limits for network checks.
    max_scan_concurrency: int = 32
    port_scan_rate_per_sec: float = 50.0
    http_rate_per_sec: float = 5.0
    connect_timeout_sec: float = 3.0
    # Hard cap on ports scanned per host per scan.
    max_ports_per_host: int = 1024
    # Token lifetime.
    token_ttl_minutes: int = 720

    # Audit log file (append-only mirror of the hash-chained DB table).
    audit_log_file: str = "./audit.log"


@lru_cache
def get_settings() -> Settings:
    return Settings()
