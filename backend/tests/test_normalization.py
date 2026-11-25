import ast
from pathlib import Path

import pytest

from normalization import normalize_url, scheme_group


def force_https(url):
    group = scheme_group(url)
    if group in ("http", "https"):
        return "https://" + url[len("https://") if group == "https" else len("http://"):]
    return "https://" + url if group == "none" else url


@pytest.mark.parametrize("url,group", [
    ("https://a.test/x", "https"), ("HTTPS://a.test", "https"), ("http://a.test", "http"),
    ("HtTp://a.test", "http"), ("a.test/x", "none"), ("www.a.test", "none"), ("//a.test", "network_path"),
    ("ftp://a.test", "other"), ("a.test:8080/x", "other"), ("", "none"),
])
def test_scheme_group(url, group):
    assert scheme_group(url) == group


@pytest.mark.parametrize("url,expected", [
    ("http://www.a.test/x", "a.test/x"),
    ("HTTPS://WWW.a.test", "a.test"),
    ("https://a.test/x?q=1#f", "a.test/x?q=1#f"),
    ("www.a.test", "a.test"),
    ("a.test", "a.test"),
    ("http://www2.a.test", "www2.a.test"),
    ("http://www.www.a.test", "www.a.test"),
    ("ftp://www.a.test", "ftp://www.a.test"),
    ("//www.a.test", "//www.a.test"),
    ("a.test:80/x", "a.test:80/x"),
])
def test_normalize_cases(url, expected):
    assert normalize_url(url) == expected


@pytest.mark.parametrize("url", [
    "http://www.a.test/x", "HTTPS://a.test", "www.a.test/p?q=1", "a.test", "ftp://a.test", "//a.test",
    "a.test:80/x", "http://http://a.test", "https://www.example.com/a/b?c=d#e",
])
def test_normalized_of_forced_https_equals_normalized(url):
    assert normalize_url(force_https(url)) == normalize_url(url)


@pytest.mark.parametrize("url", [
    "http://www.a.test/x", "https://www.example.com/", "www.a.test", "a.test", "ftp://a.test", "//a.test",
])
def test_idempotent_on_ordinary_urls(url):
    once = normalize_url(url)
    assert normalize_url(once) == once


def test_predict_normalizes_before_extraction():
    tree = ast.parse((Path(__file__).resolve().parents[1] / "ml_engine.py").read_text())
    predict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "predict")
    called = {n.func.id for n in ast.walk(predict) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "features_for_url" in called
    assert "extract_features" not in called
    source = (Path(__file__).resolve().parents[1] / "url_features.py").read_text()
    assert "normalize_url(url)" in source
