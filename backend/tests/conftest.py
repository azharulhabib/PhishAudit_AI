"""Test setup: in-memory SQLite, stubbed model, no .env, no pickle loading."""
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

# Stub ml_engine so rf_model.pkl is never loaded.
_ml = types.ModuleType("ml_engine")
_ml.predict = lambda url: {
    "status": "Safe", "score": 0.0, "threshold": 0.5,
    "features": {}, "error": None,
}
sys.modules["ml_engine"] = _ml

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
