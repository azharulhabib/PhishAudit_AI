import main
from database.models import AuditLog

# Unknown domain, no combo-squatting/keywords expected -> tier 3, threshold 0.75.
PLAIN_URL = "http://zz-unlisted-example-host.test/page"
TRUSTED_URL = "https://www.google.com/"


def _count_logs(session_factory):
    db = session_factory()
    try:
        return db.query(AuditLog).count()
    finally:
        db.close()


def test_failed_prediction_returns_unknown_and_is_not_persisted(
    client, session_factory, monkeypatch
):
    monkeypatch.setattr(main, "predict", lambda url: {
        "status": "Error", "score": 0.0, "threshold": 0.5,
        "features": {}, "error": "Prediction failed.",
    })
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["status"] == "Unknown"
    assert body["recommendation"] == "unavailable"
    assert body["score"] is None
    assert body["error"] == "Prediction failed."
    assert body["db_id"] is None
    assert _count_logs(session_factory) == 0


def test_raised_prediction_exception_also_fails_closed(
    client, session_factory, monkeypatch
):
    def boom(url):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(main, "predict", boom)
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["status"] == "Unknown"
    assert body["recommendation"] == "unavailable"
    assert _count_logs(session_factory) == 0


def test_bypass_path_still_safe_allow(client, monkeypatch):
    def must_not_run(url):
        raise AssertionError("predict must not run for trusted domains")

    monkeypatch.setattr(main, "predict", must_not_run)
    body = client.post("/audit", json={"url": TRUSTED_URL}).json()
    assert body["status"] == "Safe"
    assert body["recommendation"] == "allow"
    assert body["source"] == "trusted_domain"


def _stub_score(monkeypatch, score):
    monkeypatch.setattr(main, "predict", lambda url: {
        "status": "x", "score": score, "threshold": 0.5,
        "features": {"f": 1}, "error": None,
    })


def test_normal_path_phishing_at_or_above_threshold(
    client, session_factory, monkeypatch
):
    _stub_score(monkeypatch, 0.95)
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["tier"] == 3
    assert body["score"] >= body["threshold_used"]
    assert body["status"] == "Phishing"
    assert body["recommendation"] == "block"
    assert _count_logs(session_factory) == 1


def test_normal_path_safe_below_threshold(client, monkeypatch):
    _stub_score(monkeypatch, 0.05)
    body = client.post("/audit", json={"url": PLAIN_URL}).json()
    assert body["score"] < body["threshold_used"]
    assert body["status"] == "Safe"
    assert body["recommendation"] == "allow"
