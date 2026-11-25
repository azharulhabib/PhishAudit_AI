"""Single source of truth for the served model and its model-stage cutoff.

The cutoff is the scheme-blind retrain's own 1% false-warning budget cutoff,
selected from validation scores only (research M2, Stage B). It is a validation
estimate, not a guarantee, and has not been tested on held-out data.
"""
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
MODEL_VERSION = "scheme-blind-rf-v1"
MODEL_FILENAME = "scheme_blind_rf_v1.joblib"
EXPECTED_MODEL_SHA256 = "14b852f7390467fd34b447aa4eab77171a26018dbae5b686e514bc7c33a024c8"
SERVING_CUTOFF = 0.7411850967153485
EXPECTED_FEATURE_COUNT = 37


def model_path() -> Path:
    override = os.environ.get("PHISHAUDIT_MODEL_PATH")
    return Path(override) if override else BACKEND_DIR / "models" / MODEL_FILENAME


def expected_model_sha256() -> str:
    return os.environ.get("PHISHAUDIT_MODEL_SHA256", EXPECTED_MODEL_SHA256).strip().lower()
