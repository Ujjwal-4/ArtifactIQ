"""ArtifactIQ configuration.

All secrets and paths come from environment variables. Nothing is hardcoded.
Default mode is single-investigator, localhost, offline.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent

APP_NAME = "ArtifactIQ"
VERSION = "2.3.0"


def _env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def data_dir() -> Path:
    """Root of all persistent data (DB, evidence store, reports, logs)."""
    raw = os.environ.get("ARTIFACTIQ_DATA_DIR", "").strip()
    base = Path(raw) if raw else _APP_DIR / "instance"
    base.mkdir(parents=True, exist_ok=True)
    return base


class Config:
    SECRET_KEY = os.environ.get("ARTIFACTIQ_SECRET_KEY", "").strip() or secrets.token_hex(32)
    VERSION = VERSION
    # Keep the app bound to loopback by default. Exposing it to a network is
    # a deliberate operator decision and explicitly unsupported.
    HOST = os.environ.get("ARTIFACTIQ_HOST", "127.0.0.1")
    PORT = _env_int("ARTIFACTIQ_PORT", 5555)
    DEBUG = _env_bool("ARTIFACTIQ_DEBUG")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # loopback-only; set via env when TLS-terminating
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 4

    MAX_CONTENT_LENGTH = _env_int("ARTIFACTIQ_MAX_UPLOAD_MB", 2048) * 1024 * 1024
    DB_PATH = str(data_dir() / "artifactiq.db")
    EVIDENCE_DIR = str(Path(data_dir()) / "evidence" / "store")
    WORK_DIR = str(Path(data_dir()) / "evidence" / "work")
    REPORTS_DIR = str(Path(data_dir()) / "reports")
    LOG_DIR = str(Path(data_dir()) / "logs")
    EXPORTS_DIR = str(Path(data_dir()) / "exports")

    # Parser safety: untrusted input must never be able to stall the app.
    PARSER_TIMEOUT_S = _env_int("ARTIFACTIQ_PARSER_TIMEOUT_S", 300)
    MAX_EVENTS_PER_EVIDENCE = _env_int("ARTIFACTIQ_MAX_EVENTS", 200_000)

    # Live acquisition is opt-in, per-source, and audited.
    LIVE_ACQUISITION_ENABLED = _env_bool("ARTIFACTIQ_ALLOW_LIVE", "0")
    ACQ_REQUIRE_CONFIRM = True

    # Optional remote LLM assistance: disabled unless explicitly configured.
    LLM_ENABLED = _env_bool("ARTIFACTIQ_LLM_ENABLED", "0")

    CSRF_ENABLED = _env_bool("ARTIFACTIQ_CSRF", "1")

    @staticmethod
    def ensure_dirs() -> None:
        for d in (Config.EVIDENCE_DIR, Config.WORK_DIR, Config.REPORTS_DIR, Config.LOG_DIR, Config.EXPORTS_DIR):
            Path(d).mkdir(parents=True, exist_ok=True)
        Path(Config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
