import re
import math
from urllib.parse import urlparse, parse_qs

FEATURE_ORDER = [
    'url_len', '@', '?', '-', '=', '.', '#', '%',
    '+', '$', '!', '*', ',', '//', 'digits', 'letters',
    'https', 'having_ip_address', 'abnormal_url',
    'Shortining_Service', 'phish_has_brand',
    'phish_brand_in_subdomain', 'phish_brand_in_path',
    'phish_hyphen_count', 'phish_digit_count',
    'phish_long_domain', 'phish_many_subdomains',
    'phish_suspicious_tld', 'phish_keyword_count',
    'phish_has_redirect', 'phish_param_count',
    'phish_encoded_chars', 'adv_domain_ngram_entropy',
    'adv_path_entropy', 'adv_digit_ratio',
    'adv_subdomain_count', 'adv_token_count',
]

BRANDS = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "dropbox", "adobe", "spotify", "yahoo", "ebay", "dhl"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".club", ".work", ".date", ".faith", ".review", ".zip"
]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "password", "credential", "banking",
    "paypal", "alert", "suspend", "unusual", "validate",
    "authorize", "authenticate", "recover", "unlock", "urgent"
]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _has_ip(hostname: str) -> int:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return 1 if re.match(pattern, hostname or "") else 0


def _is_abnormal(url: str, hostname: str) -> int:
    if not hostname:
        return 1
    return 0 if hostname in url else 1


def extract_features(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = url.lower()
        domain_parts = hostname.split(".")
        tld = "." + domain_parts[-1] if domain_parts else ""
        subdomain_parts = domain_parts[:-2] if len(domain_parts) > 2 else []
        tokens = re.split(r'[/\-_.?=&%#+]', url)
        tokens = [t for t in tokens if t]

    except Exception:
        return {k: 0 for k in FEATURE_ORDER}

    features = {
        # ── Basic character counts ──
        'url_len':          len(url),
        '@':                url.count('@'),
        '?':                url.count('?'),
        '-':                url.count('-'),
        '=':                url.count('='),
        '.':                url.count('.'),
        '#':                url.count('#'),
        '%':                url.count('%'),
        '+':                url.count('+'),
        '$':                url.count('$'),
        '!':                url.count('!'),
        '*':                url.count('*'),
        ',':                url.count(','),
        '//':               url.count('//'),
        'digits':           sum(c.isdigit() for c in url),
        'letters':          sum(c.isalpha() for c in url),

        'https':            1 if parsed.scheme == 'https' else 0,
        'having_ip_address': _has_ip(hostname),
        'abnormal_url':     _is_abnormal(url, hostname),
        'Shortining_Service': 1 if any(
            s in hostname for s in SHORTENERS
        ) else 0,

        'phish_has_brand':  1 if any(
            b in full for b in BRANDS
        ) else 0,
        'phish_brand_in_subdomain': 1 if any(
            b in ".".join(subdomain_parts).lower()
            for b in BRANDS
        ) else 0,
        'phish_brand_in_path': 1 if any(
            b in path.lower() for b in BRANDS
        ) else 0,
        'phish_hyphen_count':   url.count('-'),
        'phish_digit_count':    sum(c.isdigit() for c in url),
        'phish_long_domain':    1 if len(hostname) > 20 else 0,
        'phish_many_subdomains': 1 if len(subdomain_parts) > 2 else 0,
        'phish_suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'phish_keyword_count':  sum(
            1 for k in PHISHING_KEYWORDS if k in full
        ),
        'phish_has_redirect':   1 if url.count('http') > 1 else 0,
        'phish_param_count':    len(parse_qs(query)),
        'phish_encoded_chars':  len(re.findall(r'%[0-9a-fA-F]{2}', url)),

        'adv_domain_ngram_entropy': _entropy(hostname),
        'adv_path_entropy':         _entropy(path),
        'adv_digit_ratio':          sum(
            c.isdigit() for c in url
        ) / len(url) if url else 0,
        'adv_subdomain_count':      len(subdomain_parts),
        'adv_token_count':          len(tokens),
    }

    return features


def features_to_vector(features: dict) -> list:
    return [features.get(k, 0) for k in FEATURE_ORDER]