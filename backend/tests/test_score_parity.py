import json
import math
import os
import subprocess

import pytest

import ml_engine
import serving_config as config
from tests.synthetic_urls import generate

URLS = generate()
TOLERANCE = 1e-12

RESEARCH_SCRIPT = r'''
import json, sys
import joblib
import numpy as np
root, model_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, root + "/prototypes/url-features-v1/src")
sys.path.insert(0, root + "/research/scheme-normalization-v1/scripts")
from phishaudit_features import Extractor
import m2_common
extractor = Extractor(root + "/contracts/url-features-v1")
model = joblib.load(model_path)
model.n_jobs = 1
out = []
for url in json.load(sys.stdin):
    result = extractor.extract(m2_common.N(url))
    if result["status"] != "ok":
        out.append({"score": None, "code": result["error_code"]})
        continue
    vector = np.asarray(result["features"], dtype=np.float64).reshape(1, -1)
    out.append({"score": float(model.predict_proba(vector)[0][1]), "code": None})
print(json.dumps(out))
'''

REAL_MODEL = config.BACKEND_DIR / "models" / config.MODEL_FILENAME
CONFIGURED = all(os.environ.get(k) for k in ("PHISHAUDIT_RESEARCH_ROOT", "PHISHAUDIT_RESEARCH_PYTHON", "PHISHAUDIT_RESEARCH_MODEL"))


@pytest.mark.skipif(not CONFIGURED or not REAL_MODEL.is_file(), reason="research workspace or served model not configured")
def test_app_scores_match_research_environment(monkeypatch):
    monkeypatch.setenv("PHISHAUDIT_MODEL_PATH", str(REAL_MODEL))
    monkeypatch.delenv("PHISHAUDIT_MODEL_SHA256", raising=False)
    assert ml_engine.load_model() is True
    completed = subprocess.run(
        [os.environ["PHISHAUDIT_RESEARCH_PYTHON"], "-B", "-I", "-c", RESEARCH_SCRIPT,
         os.environ["PHISHAUDIT_RESEARCH_ROOT"], os.environ["PHISHAUDIT_RESEARCH_MODEL"]],
        input=json.dumps(URLS), capture_output=True, text=True, check=True)
    research = json.loads(completed.stdout)
    assert len(research) == len(URLS)

    compared, errors_matched, max_diff, decision_differences = 0, 0, 0.0, 0
    nearest_to_cutoff = float("inf")
    for url, expected in zip(URLS, research):
        app = ml_engine.predict(url)
        if expected["score"] is None:
            assert app["status"] == "Error" and app["error"] == "Feature extraction failed."
            errors_matched += 1
            continue
        assert app["error"] is None
        compared += 1
        max_diff = max(max_diff, abs(app["score"] - expected["score"]))
        nearest_to_cutoff = min(nearest_to_cutoff, abs(app["score"] - config.SERVING_CUTOFF))
        if (app["score"] >= config.SERVING_CUTOFF) != (expected["score"] >= config.SERVING_CUTOFF):
            decision_differences += 1

    summary = {"urls": len(URLS), "scores_compared": compared, "extractor_errors_matched": errors_matched,
               "max_abs_score_difference": max_diff, "decision_differences_at_cutoff": decision_differences,
               "tolerance": TOLERANCE, "cutoff": config.SERVING_CUTOFF, "smallest_distance_to_cutoff": nearest_to_cutoff,
               "app_model_sha256": ml_engine.model_info()["model_sha256"]}
    if os.environ.get("PHISHAUDIT_PARITY_OUTPUT"):
        with open(os.environ["PHISHAUDIT_PARITY_OUTPUT"], "w") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True)
    assert compared >= 200
    assert math.isfinite(max_diff) and max_diff <= TOLERANCE
    assert decision_differences == 0
