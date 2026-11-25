"""Seeded synthetic URL patterns. No dataset, no real site, reserved/invented hosts only."""
import random

SCHEMES = ["https://", "http://", "HTTPS://", "HtTp://", "", "", "//", "ftp://"]
WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "kilo", "lima",
         "mike", "login", "secure", "account", "verify", "update", "paypal", "bank", "pay-ment", "my_site", "shop24"]
TLDS = ["test", "example", "invalid", "example.com", "example.org", "co.uk", "com.bd", "xyz", "tk", "info"]
SEGMENTS = ["index.html", "a", "b-c", "d_e", "signin", "verify-account", "2026", "x%20y", "caf%C3%A9", "a.b", "~u"]
KEYS = ["id", "q", "redirect", "token", "next", "u", "a", "page"]
VALUES = ["1", "abc", "http://inner.test/x", "a%2Fb", "x+y", "", "42", "https%3A%2F%2Finner.test"]
FRAGMENTS = ["", "", "top", "a/b", "x=1#y"]
IDN_LABELS = ["münchen", "例え", "xn--mnchen-3ya", "straße", "пример"]
EDGE = [
    "https://a.test", "a.test", "www.a.test", "HTTP://WWW.A.TEST/PATH", "//a.test/x", "ftp://a.test/x", "a.test:8080/x",
    "http://a.test:80/", "https://[2001:db8::1]/x", "http://192.0.2.7/login", "http://user@a.test/", "http://a .test/",
    "", "https://", "http://a.test/%zz", "http://a.test/%ff", "http://bit.ly/abc", "a.test.", "A.TEST/UP",
    "https://" + "a" * 70 + ".test/", "http://a.test/" + "p/" * 200, "javascript:alert(1)", "http://a.test?x=1#f",
    "http://256.1.1.1/", "http://0x7f.0.0.1/", "https://sub.sub.sub.sub.a.test/",
]


def _host(rng):
    kind = rng.random()
    if kind < 0.08:
        return ".".join(str(rng.randint(0, 255)) for _ in range(4))
    if kind < 0.12:
        return "[2001:db8::%x]" % rng.randint(1, 65535)
    labels = [rng.choice(WORDS) + (str(rng.randint(0, 99)) if rng.random() < 0.3 else "") for _ in range(rng.randint(0, 4))]
    if rng.random() < 0.08:
        labels.append(rng.choice(IDN_LABELS))
    host = ".".join(labels + [rng.choice(TLDS)]) if labels else rng.choice(WORDS) + "." + rng.choice(TLDS)
    if rng.random() < 0.35:
        host = "www." + host
    if rng.random() < 0.1:
        host = host.upper()
    return host + ("." if rng.random() < 0.03 else "")


def generate(seed=20261125, count=400):
    rng = random.Random(seed)
    urls = list(EDGE)
    while len(set(urls)) < count + len(EDGE):
        host = _host(rng)
        authority = ("user:pw@" if rng.random() < 0.03 else "") + host + (":" + str(rng.choice([80, 443, 8080, 65535])) if rng.random() < 0.12 else "")
        path = "".join("/" + rng.choice(SEGMENTS) for _ in range(rng.randint(0, 4)))
        query = "&".join(rng.choice(KEYS) + "=" + rng.choice(VALUES) for _ in range(rng.randint(0, 4)))
        fragment = rng.choice(FRAGMENTS)
        urls.append(rng.choice(SCHEMES) + authority + path + ("?" + query if query else "") + ("#" + fragment if fragment else ""))
    return sorted(set(urls))
