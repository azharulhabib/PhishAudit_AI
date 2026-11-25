import hashlib
import logging
import math
import time
import warnings

import joblib
import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

import serving_config as config
from url_features import FeatureExtractionError, contract_info, features_for_url

logger = logging.getLogger("phishaudit")

_state = {"attempted": False, "model": None, "sha256": None, "error": None, "load_seconds": None}


def _file_sha256(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _refuse(message: str, detail: str = "") -> bool:
    _state.update(model=None, sha256=None, error=message)
    logger.error("Model not loaded: %s %s", message, detail)
    return False


def load_model() -> bool:
    """Verify the model file hash before deserializing it. Never raises."""
    _state.update(attempted=True, model=None, sha256=None, error=None, load_seconds=None)
    started = time.monotonic()
    path = config.model_path()
    if not path.is_file():
        return _refuse("Model file not found.", str(path))
    try:
        actual = _file_sha256(path)
    except OSError:
        return _refuse("Model file could not be read.", str(path))
    expected = config.expected_model_sha256()
    if actual != expected:
        return _refuse("Model file failed the integrity check.", "expected %s, found %s" % (expected, actual))
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            model = joblib.load(path)
        classes = [int(c) for c in model.classes_]
        if classes != [0, 1] or int(model.n_features_in_) != config.EXPECTED_FEATURE_COUNT or not hasattr(model, "predict_proba"):
            return _refuse("Model does not match the serving contract.")
        model.n_jobs = 1
    except Exception:
        return _refuse("Model file could not be loaded.")
    try:
        contract_info()
    except FeatureExtractionError:
        return _refuse("Feature extractor unavailable.")
    _state.update(model=model, sha256=actual, load_seconds=time.monotonic() - started)
    logger.info("Model loaded and verified (sha256 %s, cutoff %r).", actual, config.SERVING_CUTOFF)
    return True


def model_info() -> dict:
    try:
        contract = contract_info()
    except FeatureExtractionError:
        contract = {"contract_version": None, "bundle_sha256": None}
    return {
        "model_loaded":              _state["model"] is not None,
        "model_version":             config.MODEL_VERSION,
        "model_sha256":              _state["sha256"],
        "model_error":               _state["error"],
        "model_load_seconds":        _state["load_seconds"],
        "serving_cutoff":            config.SERVING_CUTOFF,
        "normalizer":                "N(u): strip leading http(s):// and www.",
        "extractor_contract_version": contract["contract_version"],
        "extractor_bundle_sha256":   contract["bundle_sha256"],
    }


def _error(message: str) -> dict:
    return {
        "status":    "Error",
        "score":     0.0,
        "threshold": config.SERVING_CUTOFF,
        "features":  {},
        "error":     message
    }


def predict(url: str) -> dict:
    if not _state["attempted"]:
        load_model()
    model = _state["model"]
    if model is None:
        return _error("Model unavailable.")
    try:
        extracted = features_for_url(url)
        score = float(model.predict_proba(extracted["vector"].reshape(1, -1))[0][1])
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("score out of range")
        return {
            "status":    "Phishing" if score >= config.SERVING_CUTOFF else "Safe",
            "score":     score,
            "threshold": config.SERVING_CUTOFF,
            "features":  extracted["features"],
            "error":     None
        }
    except FeatureExtractionError:
        return _error("Feature extraction failed.")
    except Exception:
        return _error("Prediction failed.")
