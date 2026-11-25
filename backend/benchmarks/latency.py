"""Latency and memory benchmark for the full /audit path.

In-process only: FastAPI TestClient, in-memory SQLite, no server, no network and
no .env. Included: JSON parsing, the trusted/typosquat/combo/keyword stages,
normalization, feature extraction, model scoring and an insert plus commit into
in-memory SQLite. Not included: PostgreSQL, uvicorn, sockets, TLS, the browser
extension. TestClient overhead is part of every measured request.

Usage (from backend/): python -B benchmarks/latency.py [--requests 1200]
"""
import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time
import types
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
dotenv = types.ModuleType("dotenv")
dotenv.load_dotenv = lambda *a, **k: False
sys.modules["dotenv"] = dotenv
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import main  # noqa: E402
import ml_engine  # noqa: E402
from connection import Base, get_db  # noqa: E402
from tests.synthetic_urls import generate  # noqa: E402
from url_features import FeatureExtractionError, features_for_url  # noqa: E402


def current_rss_bytes():
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())], capture_output=True, text=True, check=True).stdout
    return int(out.strip()) * 1024


def percentiles(values_ms):
    p = np.percentile(values_ms, [50, 95, 99], method="linear")
    return {"p50_ms": float(p[0]), "p95_ms": float(p[1]), "p99_ms": float(p[2]),
            "mean_ms": float(np.mean(values_ms)), "max_ms": float(np.max(values_ms)), "count": len(values_ms)}


def main_run(requests, warmup):
    rss_before_load = current_rss_bytes()
    started = time.perf_counter()
    loaded = ml_engine.load_model()
    load_seconds = time.perf_counter() - started
    if not loaded:
        raise SystemExit("model failed to load: " + str(ml_engine.model_info()["model_error"]))
    rss_after_load = current_rss_bytes()

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override
    client = TestClient(main.app)

    urls = []
    for url in generate():
        try:
            features_for_url(url)
            urls.append(url)
        except FeatureExtractionError:
            pass

    for i in range(warmup):
        client.post("/audit", json={"url": urls[i % len(urls)]})

    latencies, statuses = [], {}
    for i in range(requests):
        payload = {"url": urls[i % len(urls)]}
        t = time.perf_counter()
        response = client.post("/audit", json=payload)
        latencies.append((time.perf_counter() - t) * 1000.0)
        statuses[response.json()["status"]] = statuses.get(response.json()["status"], 0) + 1

    model_only = []
    for i in range(requests):
        t = time.perf_counter()
        ml_engine.predict(urls[i % len(urls)])
        model_only.append((time.perf_counter() - t) * 1000.0)

    rss_after_run = current_rss_bytes()
    return {
        "requests_measured": requests, "warmup_requests": warmup, "distinct_urls_cycled": len(urls),
        "statuses_returned": statuses,
        "full_audit_path": percentiles(latencies),
        "model_stage_only_predict": percentiles(model_only),
        "model_load_seconds_hash_load_and_extractor_init": load_seconds,
        "resident_memory_bytes": {"before_model_load": rss_before_load, "after_model_load": rss_after_load,
                                  "after_run": rss_after_run, "peak_since_process_start": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)},
        "model_sha256": ml_engine.model_info()["model_sha256"],
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
                        "logical_cpus": os.cpu_count(), "numpy": np.__version__, "scikit_learn": sklearn.__version__,
                        "model_n_jobs": 1},
        "scope": {"included": ["json parsing", "gate, combo and keyword stages", "N(u)", "feature extraction", "model scoring",
                               "insert and commit into in-memory SQLite", "TestClient overhead"],
                  "not_included": ["PostgreSQL writes", "uvicorn and sockets", "TLS", "browser extension", "cold start"]},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=1200)
    parser.add_argument("--warmup", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(main_run(args.requests, args.warmup), indent=2, sort_keys=True))
