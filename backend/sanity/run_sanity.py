"""Smoke check: run hand-written URL lists through the full /audit pipeline.

In-process only (TestClient, in-memory SQLite, no server, no network, no .env).
This is not a performance estimate and nothing is tuned from its output.

Usage (from backend/): python -B sanity/run_sanity.py
"""
import json
import os
import sys
import types
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
dotenv = types.ModuleType("dotenv")
dotenv.load_dotenv = lambda *a, **k: False
sys.modules["dotenv"] = dotenv
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import main  # noqa: E402
import ml_engine  # noqa: E402
import serving_config as config  # noqa: E402
from connection import Base, get_db  # noqa: E402

HERE = Path(__file__).resolve().parent
STAGES = ("trusted_bypass", "typosquat_tier2", "combo_squatting_tier4", "keyword_context", "model_default")


def read_list(name):
    return [line.strip() for line in (HERE / name).read_text().splitlines() if line.strip() and not line.startswith("#")]


def stage_of(body):
    if body["source"] == "trusted_domain":
        return "trusted_bypass"
    if body["source"] == "hvt_combo_squatting":
        return "combo_squatting_tier4"
    if body["source"] == "keyword_context":
        return "keyword_context"
    return "typosquat_tier2" if body["tier"] == 2 else "model_default"


def run_list(client, urls):
    rows = []
    for url in urls:
        body = client.post("/audit", json={"url": url}).json()
        direct = ml_engine.predict(url)
        rows.append({"url": url, "status": body["status"], "stage": stage_of(body), "tier": body["tier"],
                     "threshold_used": body["threshold_used"], "score": body["score"], "error": body["error"],
                     "model_only_score": direct["score"] if direct["error"] is None else None,
                     "model_only_flagged_at_cutoff": (direct["score"] >= config.SERVING_CUTOFF) if direct["error"] is None else None})
    return rows


def summarize(rows):
    per_stage = {s: {"reached": 0, "flagged": 0} for s in STAGES}
    for r in rows:
        per_stage[r["stage"]]["reached"] += 1
        per_stage[r["stage"]]["flagged"] += r["status"] == "Phishing"
    return {"urls": len(rows), "phishing": sum(r["status"] == "Phishing" for r in rows),
            "safe": sum(r["status"] == "Safe" for r in rows), "unknown": sum(r["status"] == "Unknown" for r in rows),
            "per_stage": per_stage,
            "model_only_diagnostic": {"scored": sum(r["model_only_score"] is not None for r in rows),
                                      "flagged_at_cutoff": sum(bool(r["model_only_flagged_at_cutoff"]) for r in rows)}}


def run():
    if not ml_engine.load_model():
        raise SystemExit("model failed to load: " + str(ml_engine.model_info()["model_error"]))
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
    legit, invented = run_list(client, read_list("legit_sites.txt")), run_list(client, read_list("invented_patterns.txt"))
    flagged_legit = [{"url": r["url"], "stage": r["stage"], "score": r["score"], "threshold_used": r["threshold_used"]}
                     for r in legit if r["status"] == "Phishing"]
    unknown_legit = [{"url": r["url"], "error": r["error"]} for r in legit if r["status"] == "Unknown"]
    model_only_flagged_legit = [r["url"] for r in legit if r["model_only_flagged_at_cutoff"]]
    return {"model_sha256": ml_engine.model_info()["model_sha256"], "serving_cutoff": config.SERVING_CUTOFF,
            "note": "Smoke check on hand-written lists. Not a performance estimate. Nothing was tuned from this output.",
            "legitimate": {"summary": summarize(legit), "flagged": flagged_legit, "unknown": unknown_legit,
                           "flagged_by_model_alone_at_cutoff_diagnostic": model_only_flagged_legit, "rows": legit},
            "invented_suspicious": {"summary": summarize(invented), "rows": invented}}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
