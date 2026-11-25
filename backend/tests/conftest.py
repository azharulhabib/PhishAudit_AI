"""Test setup: in-memory SQLite, no .env, and no real model unless a test opts in."""
import os
import sys
import types

import pytest

# Must happen before main/connection are imported.
os.environ["DATABASE_URL"] = "sqlite://"

# Stub dotenv so connection.py never reads backend/.env.
_dotenv = types.ModuleType("dotenv")
_dotenv.load_dotenv = lambda *a, **k: False
sys.modules["dotenv"] = _dotenv

# Point the served model at a path that does not exist, so no test loads the
# real model by accident. Tests that need a model set their own path and hash.
os.environ["PHISHAUDIT_MODEL_PATH"] = "/nonexistent/phishaudit-test-model.joblib"

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from connection import Base, get_db  # noqa: E402


@pytest.fixture()
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture()
def client(session_factory):
    def _get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = _get_db
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
