"""Shared pytest fixtures for ArtifactIQ.

Every test runs against a throwaway SQLite database and evidence store in a
per-session temp directory (ARTIFACTIQ_DATA_DIR). No test touches real
evidence or the developer's instance folder.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# MUST be set before any test module imports artifactiq (collection imports
# happen before fixtures run, and artifactiq.config binds DB_PATH at import).
# Unique dir per pytest process, wiped at session start -> zero cross-run state.
_TEST_RUN_DIR = Path(tempfile.gettempdir()) / f"aiq_pytest_{uuid.uuid4().hex[:8]}"
os.environ["ARTIFACTIQ_DATA_DIR"] = str(_TEST_RUN_DIR)
os.environ.setdefault("ARTIFACTIQ_SECRET_KEY", "pytest-secret")
os.environ["ARTIFACTIQ_CSRF"] = "1"


@pytest.fixture(scope="session")
def data_dir():
    d = _TEST_RUN_DIR
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    return d


@pytest.fixture(scope="session", autouse=True)
def _fresh_db(data_dir):
    """pytest retains tmp dirs across sessions; a leftover DB would collide
    with hard-coded test ids and hashes. Guarantee a run-fresh store."""
    for name in ("artifactiq.db", "artifactiq.db-wal", "artifactiq.db-shm"):
        (Path(data_dir) / name).unlink(missing_ok=True)
    yield


@pytest.fixture(scope="session")
def app(data_dir):
    from artifactiq import create_app

    application = create_app()
    application.testing = True
    return application


@pytest.fixture()
def client(app):
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_csrf_token"] = "pytest-csrf-token"
        c.csrf_header = {"X-CSRF-Token": "pytest-csrf-token"}
        yield c


@pytest.fixture()
def context(app):
    with app.app_context():
        yield app


@pytest.fixture(scope="session")
def demo_case_id(app):
    """A fully-built synthetic demo case, built once for read-only checks."""
    with app.app_context():
        from artifactiq.demo_loader import build_demo_case

        return build_demo_case()


@pytest.fixture()
def fresh_case_id(app, context):
    """A fresh demo case per test (for mutation-heavy checks)."""
    from artifactiq.demo_loader import build_demo_case

    return build_demo_case()
