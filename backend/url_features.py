"""Contract 1.0.0 feature extraction for scoring.

Every URL is normalized with N(u) and then passed to the vendored, unmodified
extractor. Any extractor error raises FeatureExtractionError; there is no
fallback and no zero vector, so a caller can never mistake a failure for Safe.
"""
import sys
from pathlib import Path

import numpy as np

from normalization import normalize_url

VENDOR_ROOT = Path(__file__).resolve().parent / "vendor" / "url-features-v1"
CONTRACT_DIR = VENDOR_ROOT / "contract"
FEATURE_COUNT = 37

_state = {"extractor": None, "failed": False}


class FeatureExtractionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def get_extractor():
    if _state["failed"]:
        raise FeatureExtractionError("EXTRACTOR_UNAVAILABLE")
    if _state["extractor"] is None:
        try:
            source = str(VENDOR_ROOT / "src")
            if source not in sys.path:
                sys.path.insert(0, source)
            from phishaudit_features import Extractor
            _state["extractor"] = Extractor(CONTRACT_DIR)
        except Exception:
            _state["failed"] = True
            raise FeatureExtractionError("EXTRACTOR_UNAVAILABLE") from None
    return _state["extractor"]


def feature_order():
    return list(get_extractor().feature_order)


def contract_info():
    get_extractor()
    from phishaudit_features import extractor as module
    return {"contract_version": module.CONTRACT_VERSION, "bundle_sha256": module.BUNDLE_SHA256}


def extract_vector(normalized_url):
    extractor = get_extractor()
    result = extractor.extract(normalized_url)
    if result.get("status") != "ok":
        raise FeatureExtractionError(result.get("error_code") or "EXTRACTION_FAILED")
    values = result["features"]
    vector = np.asarray(values, dtype=np.float64)
    if vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all():
        raise FeatureExtractionError("INVALID_VECTOR")
    return vector, dict(zip(extractor.feature_order, values))


def features_for_url(url):
    try:
        normalized = normalize_url(url)
    except TypeError:
        raise FeatureExtractionError("INPUT_TYPE") from None
    vector, named = extract_vector(normalized)
    return {"vector": vector, "features": named}
