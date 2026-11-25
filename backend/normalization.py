"""Scheme-blind URL normalizer N(u) (M2 plan v1, section 2).

N(u) removes a leading http:// or https:// (case-insensitive), then a leading
www. (case-insensitive) from the remainder. Strings with another explicit
scheme or a leading // are returned unchanged. Nothing else is modified.
"""
import re

HTTP_PREFIX = re.compile(r"^(https?)://", re.IGNORECASE | re.ASCII)
SCHEME_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:", re.ASCII)
WWW_PREFIX = re.compile(r"^www\.", re.IGNORECASE | re.ASCII)


def scheme_group(url: str) -> str:
    match = HTTP_PREFIX.match(url)
    if match:
        return "https" if match.group(1).lower() == "https" else "http"
    if url.startswith("//"):
        return "network_path"
    return "other" if SCHEME_PREFIX.match(url) else "none"


def normalize_url(url: str) -> str:
    group = scheme_group(url)
    if group in ("network_path", "other"):
        return url
    remainder = url[HTTP_PREFIX.match(url).end():] if group in ("https", "http") else url
    return WWW_PREFIX.sub("", remainder, count=1)
