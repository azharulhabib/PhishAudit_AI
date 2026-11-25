import hashlib
import logging
import math
import warnings

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.exceptions import InconsistentVersionWarning

import main
import ml_engine
import serving_config as config
from database.models import AuditLog
from domain_gate import classify_domain
from tests.stub_model import StubForest
from url_features import FeatureExtractionError

PLAIN_URL = "http://zz-unlisted-example-host.test/page"
TRUSTED_URL = "https://www.google.com/"
CUTOFF = config.SERVING_CUTOFF


@pytest.fixture(autouse=True)
def reset_engine():
    ml_engine._state.update(attempted=False, model=None, sha256=None, error=None, load_seconds=None)
    yield
    ml_engine._state.update(attempted=False, model=None, sha256=None, error=None, load_seconds=None)


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def serve_stub(monkeypatch, tmp_path, **kwargs):
    path = tmp_path / "model.joblib"
    joblib.dump(StubForest(**kwargs), path)
    monkeypatch.setenv("PHISHAUDIT_MODEL_PATH", str(path))
    monkeypatch.setenv("PHISHAUDIT_MODEL_SHA256", _sha(path))
    return path


def _count_logs(session_factory):
    db = session_factory()
    try:
        return db.query(AuditLog).count()
    finally:
        db.close()


def test_configuration_defaults():
    assert config.EXPECTED_MODEL_SHA256.startswith("14b852f7") and config.EXPECTED_MODEL_SHA256.endswith("024c8")
    assert CUTOFF == 0.7411850967153485
    assert config.expected_model_sha256() == config.EXPECTED_MODEL_SHA256
    assert config.BACKEND_DIR.joinpath("models", config.MODEL_FILENAME) != config.model_path()


def test_missing_model_file_is_refused_and_reported():
    assert ml_engine.load_model() is False
    info = ml_engine.model_info()
    assert info["model_loaded"] is False and info["model_error"] == "Model file not found."
    result = ml_engine.predict("https://www.example.test/")
    assert result["status"] == "Error" and result["error"] == "Model unavailable."


def test_hash_mismatch_never_deserializes(monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path)
    monkeypatch.setenv("PHISHAUDIT_MODEL_SHA256", "0" * 64)

    def must_not_load(*args, **kwargs):
        raise AssertionError("joblib.load must not run when the hash differs")

    monkeypatch.setattr(ml_engine.joblib, "load", must_not_load)
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Model file failed the integrity check."


def test_altered_model_file_is_refused(monkeypatch, tmp_path):
    path = serve_stub(monkeypatch, tmp_path)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Model file failed the integrity check."


def test_valid_model_loads_with_single_thread_and_records_identity(monkeypatch, tmp_path):
    path = serve_stub(monkeypatch, tmp_path)
    assert ml_engine.load_model() is True
    info = ml_engine.model_info()
    assert info["model_loaded"] is True and info["model_sha256"] == _sha(path) and info["model_error"] is None
    assert ml_engine._state["model"].n_jobs == 1
    assert info["serving_cutoff"] == CUTOFF and info["extractor_contract_version"] == "1.0.0"
    assert info["extractor_bundle_sha256"] == "217767dd2fcf545dec381d62b3059b49b61f6d7bd43180f3950f0c6008f5c58e"
    assert info["model_load_seconds"] is not None


@pytest.mark.parametrize("kwargs", [{"classes": (1, 0)}, {"n_features": 36}])
def test_model_that_breaks_the_serving_contract_is_refused(monkeypatch, tmp_path, kwargs):
    serve_stub(monkeypatch, tmp_path, **kwargs)
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Model does not match the serving contract."


def test_corrupt_file_with_matching_hash_is_refused(monkeypatch, tmp_path):
    path = tmp_path / "garbage.joblib"
    path.write_bytes(b"not a model")
    monkeypatch.setenv("PHISHAUDIT_MODEL_PATH", str(path))
    monkeypatch.setenv("PHISHAUDIT_MODEL_SHA256", _sha(path))
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Model file could not be loaded."


def test_library_version_mismatch_is_refused(monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path)

    def versioned(*args, **kwargs):
        warnings.warn(InconsistentVersionWarning(estimator_name="StubForest", current_sklearn_version="1.8.0",
                                                 original_sklearn_version="1.9.0"))
        return StubForest()

    monkeypatch.setattr(ml_engine.joblib, "load", versioned)
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Model file could not be loaded."


def test_unavailable_extractor_is_refused(monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path)

    def broken():
        raise FeatureExtractionError("EXTRACTOR_UNAVAILABLE")

    monkeypatch.setattr(ml_engine, "contract_info", broken)
    assert ml_engine.load_model() is False
    assert ml_engine.model_info()["model_error"] == "Feature extractor unavailable."


def test_predict_returns_unrounded_score_cutoff_and_contract_features(monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path, probability=0.9123456789)
    result = ml_engine.predict("https://www.example.test/a?b=1")
    assert result["status"] == "Phishing" and result["error"] is None
    assert result["score"] == 0.9123456789 and result["threshold"] == CUTOFF
    assert len(result["features"]) == 37


@pytest.mark.parametrize("probability,status", [
    (CUTOFF, "Phishing"), (math.nextafter(CUTOFF, 0.0), "Safe"), (math.nextafter(CUTOFF, 1.0), "Phishing"),
    (0.74118, "Safe"), (0.74119, "Phishing"),
])
def test_model_decision_uses_raw_score_at_the_cutoff(monkeypatch, tmp_path, probability, status):
    serve_stub(monkeypatch, tmp_path, probability=probability)
    assert ml_engine.predict("https://www.example.test/")["status"] == status


@pytest.mark.parametrize("bad", ["http://user@a.test/", "http://a .test/", "", "ftp://a.test/x", None, 7])
def test_extractor_errors_become_errors_never_a_score(monkeypatch, tmp_path, bad):
    serve_stub(monkeypatch, tmp_path, probability=0.0)
    result = ml_engine.predict(bad)
    assert result["status"] == "Error" and result["error"] == "Feature extraction failed."


def test_prediction_failure_and_invalid_probability_are_errors(monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path)
    assert ml_engine.load_model()
    monkeypatch.setattr(ml_engine._state["model"], "predict_proba", lambda m: (_ for _ in ()).throw(RuntimeError("x")))
    assert ml_engine.predict("https://www.example.test/")["error"] == "Prediction failed."
    monkeypatch.setattr(ml_engine._state["model"], "predict_proba", lambda m: np.array([[0.5, float("nan")]]))
    assert ml_engine.predict("https://www.example.test/")["error"] == "Prediction failed."


def test_audit_decision_uses_raw_score_not_the_rounded_display_value(client, session_factory, monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path, probability=0.74118)
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["threshold_used"] == CUTOFF and body["tier"] == 3
    assert body["score"] == 0.7412 and body["score"] > CUTOFF
    assert body["status"] == "Safe" and body["recommendation"] == "allow"


def test_audit_at_or_above_cutoff_is_phishing_and_persisted(client, session_factory, monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path, probability=CUTOFF)
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["status"] == "Phishing" and body["recommendation"] == "block"
    assert _count_logs(session_factory) == 1


@pytest.mark.parametrize("url", [PLAIN_URL, "http://user@zz-unlisted-example-host.test/"])
def test_missing_model_or_extractor_error_returns_unknown(client, session_factory, url):
    body = client.post("/audit", json={"url": url}).json()
    assert body["status"] == "Unknown" and body["recommendation"] == "unavailable"
    assert body["score"] is None and body["db_id"] is None
    assert _count_logs(session_factory) == 0


def test_extractor_error_with_a_loaded_model_returns_unknown(client, session_factory, monkeypatch, tmp_path):
    serve_stub(monkeypatch, tmp_path, probability=0.0)
    body = client.post("/audit", json={"url": "http://user@zz-unlisted-example-host.test/"}).json()
    assert body["status"] == "Unknown" and body["error"] == "Feature extraction failed."
    assert _count_logs(session_factory) == 0


def test_trusted_bypass_does_not_need_the_model(client):
    body = client.post("/audit", json={"url": TRUSTED_URL}).json()
    assert body["status"] == "Safe" and body["source"] == "trusted_domain"


def test_startup_reports_a_missing_model_and_status_route_shows_it(caplog):
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        with TestClient(main.app) as live:
            body = live.get("/").json()
    assert any("MODEL UNAVAILABLE" in r.getMessage() and r.levelno == logging.ERROR for r in caplog.records)
    assert body["status"] == "online" and body["model"]["model_loaded"] is False
    assert body["model"]["model_error"] == "Model file not found."
    assert body["model"]["serving_cutoff"] == CUTOFF and body["model"]["extractor_contract_version"] == "1.0.0"


def test_startup_reports_a_verified_model(monkeypatch, tmp_path, caplog):
    path = serve_stub(monkeypatch, tmp_path)
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        with TestClient(main.app) as live:
            body = live.get("/").json()
    assert any("Model verified and loaded" in r.getMessage() for r in caplog.records)
    assert body["model"]["model_loaded"] is True and body["model"]["model_sha256"] == _sha(path)


def test_only_the_default_tier3_threshold_is_replaced():
    assert classify_domain("zz-unlisted-example-host.test")["threshold"] == CUTOFF
    assert classify_domain("")["threshold"] == CUTOFF
    assert classify_domain("gogle.com")["tier"] == 2 and classify_domain("gogle.com")["threshold"] == 0.30


REAL_MODEL = config.BACKEND_DIR / "models" / config.MODEL_FILENAME


@pytest.mark.skipif(not REAL_MODEL.is_file(), reason="served model file is not present on this machine")
def test_real_model_loads_scores_and_is_scheme_blind(monkeypatch):
    monkeypatch.setenv("PHISHAUDIT_MODEL_PATH", str(REAL_MODEL))
    monkeypatch.delenv("PHISHAUDIT_MODEL_SHA256", raising=False)
    assert ml_engine.load_model() is True
    assert ml_engine.model_info()["model_sha256"] == config.EXPECTED_MODEL_SHA256
    scores = [ml_engine.predict(prefix + "example.test/account/login?id=1")["score"]
              for prefix in ("", "http://", "https://", "https://www.", "HTTP://WWW.")]
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert max(scores) - min(scores) <= 1e-12
