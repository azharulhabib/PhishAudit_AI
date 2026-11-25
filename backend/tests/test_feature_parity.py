import json
import math
import os
import subprocess
import sys

import numpy as np
import pytest

import url_features
from normalization import normalize_url
from tests.synthetic_urls import generate
from url_features import FeatureExtractionError, features_for_url, get_extractor

GOLDEN = json.loads((url_features.CONTRACT_DIR / "fixtures" / "golden-fixtures.json").read_text())
SCHEMA = json.loads((url_features.CONTRACT_DIR / "feature-schema.json").read_text())
URLS = generate()
TAGGED = {"NaN": float("nan"), "Infinity": float("inf"), "-Infinity": float("-inf")}

RESEARCH_SCRIPT = r'''
import json, sys
root = sys.argv[1]
sys.path.insert(0, root + "/prototypes/url-features-v1/src")
sys.path.insert(0, root + "/research/scheme-normalization-v1/scripts")
from phishaudit_features import Extractor
import m2_common
extractor = Extractor(root + "/contracts/url-features-v1")
out = []
for url in json.load(sys.stdin):
    normalized = m2_common.N(url)
    result = extractor.extract(normalized)
    out.append({"n": normalized, "status": result["status"], "code": result["error_code"], "features": result["features"]})
print(json.dumps(out))
'''


def _golden_input(case):
    spec = case["input"]
    if spec["kind"] == "string":
        return spec["text"]
    if spec["kind"] == "json":
        return spec["value"]
    return TAGGED[spec["value_tag"]]


def _close(a, b):
    return a == b or math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-12)


def test_at_least_200_distinct_synthetic_urls():
    assert len(set(URLS)) >= 200


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda c: c["id"])
def test_vendored_extractor_matches_golden_fixture(case):
    result = get_extractor().extract(_golden_input(case))
    expected = case["expected"]
    assert result["status"] == expected["status"]
    assert result["error_code"] == expected["error_code"]
    assert result["metadata"] == expected["metadata"]
    if expected["status"] == "ok":
        assert len(result["features"]) == 37
        assert all(_close(a, b) for a, b in zip(result["features"], expected["features"]))
    else:
        assert result["features"] is None


def test_feature_order_matches_contract_order():
    assert url_features.feature_order() == SCHEMA["x-feature-order"]
    assert len(SCHEMA["x-feature-order"]) == 37


def test_vectors_are_float64_in_contract_order_and_failures_raise():
    ok = failed = 0
    for url in URLS:
        try:
            result = features_for_url(url)
        except FeatureExtractionError as error:
            assert error.code
            failed += 1
            continue
        ok += 1
        assert result["vector"].dtype == np.float64 and result["vector"].shape == (37,)
        assert list(result["features"]) == SCHEMA["x-feature-order"]
        assert np.array_equal(result["vector"], np.asarray(list(result["features"].values()), dtype=np.float64))
    assert ok >= 150 and failed >= 5


@pytest.mark.parametrize("bad", [
    "http://user@a.test/", "http://a .test/", "", "https://", "ftp://a.test/x", "javascript:alert(1)",
    "http://256.1.1.1/", "http://a.test/%zz", "http://a.test/" + "p/" * 40000, None, 7, ["a.test"],
])
def test_extractor_errors_raise_never_return_a_vector(bad):
    with pytest.raises(FeatureExtractionError):
        features_for_url(bad)


@pytest.mark.parametrize("base", ["example.com/a/b?c=d", "sub.example.org/login"])
def test_scheme_and_www_variants_give_identical_features(base):
    vectors = []
    for prefix in ("", "http://", "https://", "HTTPS://", "https://www.", "HTTP://WWW.", "www."):
        vectors.append(features_for_url(prefix + base)["vector"])
    assert all(np.array_equal(vectors[0], v) for v in vectors[1:])


def test_bare_host_port_is_an_other_scheme_and_keeps_www():
    with_scheme = [features_for_url(p + "a.test:8080/x")["vector"] for p in ("http://", "https://", "HTTPS://", "https://www.")]
    assert all(np.array_equal(with_scheme[0], v) for v in with_scheme[1:])
    assert normalize_url("www.a.test:8080/x") == "www.a.test:8080/x"


def test_pipeline_features_equal_extractor_on_normalized_url():
    extractor = get_extractor()
    for url in URLS:
        result = extractor.extract(normalize_url(url))
        if result["status"] != "ok":
            with pytest.raises(FeatureExtractionError):
                features_for_url(url)
        else:
            assert features_for_url(url)["vector"].tolist() == [float(v) for v in result["features"]]


@pytest.mark.skipif(not os.environ.get("PHISHAUDIT_RESEARCH_ROOT") or not os.environ.get("PHISHAUDIT_RESEARCH_PYTHON"),
                    reason="research workspace not configured")
def test_features_equal_research_extractor_exactly():
    completed = subprocess.run(
        [os.environ["PHISHAUDIT_RESEARCH_PYTHON"], "-B", "-I", "-c", RESEARCH_SCRIPT, os.environ["PHISHAUDIT_RESEARCH_ROOT"]],
        input=json.dumps(URLS), capture_output=True, text=True, check=True)
    research = json.loads(completed.stdout)
    assert len(research) == len(URLS)
    compared = 0
    for url, expected in zip(URLS, research):
        assert normalize_url(url) == expected["n"]
        if expected["status"] != "ok":
            with pytest.raises(FeatureExtractionError) as info:
                features_for_url(url)
            assert info.value.code == expected["code"]
            continue
        assert features_for_url(url)["vector"].tolist() == [float(v) for v in expected["features"]]
        compared += 1
    assert compared >= 150
