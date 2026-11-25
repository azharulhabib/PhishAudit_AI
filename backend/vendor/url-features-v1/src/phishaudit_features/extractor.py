"""Independent deterministic implementation of released URL contract 1.0.0.

No application, training artifact, CSV feature or golden fixture is imported.
Only the released reference assets/schema/vocabularies are runtime inputs.
"""
from collections import Counter
from hashlib import sha256
from importlib.metadata import version
import ipaddress
import json
import math
from pathlib import Path
import re

from jsonschema import Draft202012Validator

from .idna_profile import IDNAProfile
from .psl import SuffixRules

CONTRACT_VERSION = "1.0.0"
BUNDLE_SHA256 = "217767dd2fcf545dec381d62b3059b49b61f6d7bd43180f3950f0c6008f5c58e"
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
HTTP_PREFIX = re.compile(r"^(https?)://", re.IGNORECASE | re.ASCII)
TOKENS = re.compile(r"[A-Za-z0-9]+")
NESTED = re.compile(r"(?<![A-Za-z0-9])https?://", re.IGNORECASE | re.ASCII)
HEX = frozenset("0123456789abcdefABCDEF")
DOT_MAP = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
UNSUPPORTED = frozenset(("INPUT_TOO_LONG", "UNSUPPORTED_SCHEME", "USERINFO_UNSUPPORTED", "HOST_PERCENT_UNSUPPORTED", "IP_UNSUPPORTED"))
METADATA_KEYS = ("source_scheme", "scheme_form", "host_recovered", "host_kind", "host", "port", "public_suffix", "registrable_domain", "suffix_rule", "suffix_section", "query_present", "fragment_present")
FLOAT_SLOTS = frozenset((32, 33, 34))


class ConfigurationError(RuntimeError):
    """Pinned dependency/reference bundle cannot be used. No fallback occurs."""


class InputFailure(Exception):
    def __init__(self, code):
        self.code = code


def fail(code):
    raise InputFailure(code)


def _ascii_digits(text):
    return bool(text) and all("0" <= c <= "9" for c in text)


def _numeric_candidate(host):
    return all(re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", label) for label in host.split("."))


def _entropy(text):
    if not text:
        return 0.0
    length = len(text)
    # Stable accumulation order follows first occurrence, independent of hashes.
    return float(-math.fsum((count / length) * math.log2(count / length) for count in Counter(text).values()))


def _tokens(text):
    return set(TOKENS.findall(text.translate(FOLD)))


def _forbidden(cp):
    return (cp <= 0x1F or 0x7F <= cp <= 0x9F or cp == 0x5C or
            cp in (0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000) or
            0x2000 <= cp <= 0x200A)


class Extractor:
    def __init__(self, bundle_path):
        self.bundle = Path(bundle_path).resolve()
        try:
            if version("idna") != "3.19" or version("unicodedata2") != "17.0.0" or version("jsonschema") != "4.26.0":
                raise ValueError("Pinned dependency version mismatch")
            dependency_manifest = Path(__file__).resolve().parents[2] / "dependencies/wheel-manifest.json"
            for wheel in json.loads(dependency_manifest.read_text())["wheels"]:
                if version(wheel["name"]) != wheel["version"]:
                    raise ValueError("Pinned transitive dependency version mismatch")
            manifest_bytes = (self.bundle / "normative-manifest.json").read_bytes()
            if sha256(manifest_bytes).hexdigest() != BUNDLE_SHA256:
                raise ValueError("Contract bundle manifest mismatch")
            manifest = json.loads(manifest_bytes)
            for name, expected in manifest["files"].items():
                asset = (self.bundle / name).read_bytes()
                if len(asset) != expected["size_bytes"] or sha256(asset).hexdigest() != expected["sha256"]:
                    raise ValueError("Normative asset identity mismatch")
            self.schema = json.loads((self.bundle / "feature-schema.json").read_text())
            Draft202012Validator.check_schema(self.schema)
            self.validator = Draft202012Validator(self.schema)
            self.feature_order = tuple(self.schema["x-feature-order"])
            if len(self.feature_order) != 37 or len(set(self.feature_order)) != 37:
                raise ValueError("Feature ordering mismatch")
            vocab = json.loads((self.bundle / "vocabularies.json").read_text())
            self.brands = frozenset(vocab["brands"])
            self.keywords = frozenset(vocab["keywords"])
            self.shorteners = frozenset(vocab["shortener_exact_hosts"])
            self.final_labels = frozenset(vocab["final_dns_labels"])
            self.idna = IDNAProfile(self.bundle / "references/IdnaMappingTable-17.0.0.txt")
            self.suffixes = SuffixRules(self.bundle / "references/public_suffix_list.dat", self.idna)
        except Exception as exc:
            # No path, host or user input is echoed in the public diagnostic.
            raise ConfigurationError("Pinned URL-feature configuration validation failed") from exc

    def _failure(self, code):
        return {
            "contract_version": CONTRACT_VERSION, "bundle_sha256": BUNDLE_SHA256,
            "status": "internal_error" if code == "INTERNAL_CONTRACT_ERROR" else "unsupported" if code in UNSUPPORTED else "invalid",
            "error_code": code, "features": None,
            "metadata": dict.fromkeys(METADATA_KEYS),
        }

    def extract(self, value):
        """Return one complete result. Never log the input or partial metadata."""
        try:
            proposed = self._extract(value)
            return self.finalize(proposed)
        except InputFailure as exc:
            return self._failure(exc.code)
        except Exception:
            # Runtime defects are visible unavailability, never a valid zero vector.
            return self._failure("INTERNAL_CONTRACT_ERROR")

    def finalize(self, proposed):
        """Defensive output boundary, also used for non-finite fault injection."""
        try:
            self.validator.validate(proposed)
            if proposed["contract_version"] != CONTRACT_VERSION or proposed["bundle_sha256"] != BUNDLE_SHA256:
                raise ValueError("Wrong envelope")
            if proposed["status"] == "ok":
                values, meta = proposed["features"], proposed["metadata"]
                for index, value in enumerate(values):
                    if index in FLOAT_SLOTS:
                        if type(value) is not float or not math.isfinite(value) or value < 0:
                            raise ValueError("Invalid binary64")
                    elif type(value) is not int or not 0 <= value <= 2**63 - 1:
                        raise ValueError("Invalid int64")
                if values[31] != values[7] or values[18] != int(meta["host_recovered"]):
                    raise ValueError("Cross-field count invariant")
                if meta["source_scheme"] is None and values[16] != 0:
                    raise ValueError("Invented HTTPS")
                if values[24] > len(meta["host"]) or values[34] != values[14] / values[0] or values[26] != int(values[35] > 2):
                    raise ValueError("Cross-field arithmetic invariant")
                if meta["scheme_form"] == "explicit":
                    if meta["source_scheme"] not in ("http", "https") or meta["host_recovered"]:
                        raise ValueError("Scheme metadata invariant")
                elif meta["source_scheme"] is not None or meta["host_recovered"] != (meta["scheme_form"] == "absent"):
                    raise ValueError("Recovery metadata invariant")
                if values[16] != int(meta["source_scheme"] == "https") or values[17] != int(meta["host_kind"] != "dns"):
                    raise ValueError("Type/transport invariant")
                if type(meta["port"]) is bool:
                    raise ValueError("Boolean port")
                if meta["host_kind"] != "dns" and (values[35] or any(meta[k] is not None for k in ("public_suffix", "registrable_domain", "suffix_rule", "suffix_section"))):
                    raise ValueError("IP suffix invariant")
            # allow_nan=False enforces round-trip interoperable numeric JSON.
            json.loads(json.dumps(proposed, ensure_ascii=True, allow_nan=False))
            return proposed
        except Exception:
            return self._failure("INTERNAL_CONTRACT_ERROR")

    @staticmethod
    def _structure(raw):
        prefix = HTTP_PREFIX.match(raw)
        if prefix:
            source, form, recovered = prefix[1].translate(FOLD), "explicit", False
            rest = raw[prefix.end():]
        elif raw.startswith("//"):
            source, form, recovered, rest = None, "network_path", False, raw[2:]
        else:
            source, form, recovered, rest = None, "absent", True, raw
            # RFC scheme spelling wins unless the prefix is a dotted hostname
            # with a decimal port. Port range is validated at its later stage.
            candidate = re.split(r"[/?#]", rest, maxsplit=1)[0]
            if SCHEME.match(raw):
                host, sep, port = candidate.partition(":")
                if not ("." in host.translate(DOT_MAP) and sep and _ascii_digits(port)):
                    fail("UNSUPPORTED_SCHEME")
        end = next((i for i, c in enumerate(rest) if c in "/?#"), len(rest))
        authority, tail = rest[:end], rest[end:]
        if not authority:
            fail("EMPTY_AUTHORITY")
        if "@" in authority:
            fail("USERINFO_UNSUPPORTED")
        before_fragment, marker_f, fragment = tail.partition("#")
        path, marker_q, query = before_fragment.partition("?")
        return source, form, recovered, authority, path, query, fragment, bool(marker_q), bool(marker_f)

    @staticmethod
    def _authority(authority):
        bracketed = authority.startswith("[")
        if bracketed:
            if authority.count("[") != 1 or authority.count("]") != 1:
                fail("INVALID_AUTHORITY")
            close = authority.index("]")
            host, suffix = authority[1:close], authority[close + 1:]
            if suffix and not suffix.startswith(":"):
                fail("INVALID_AUTHORITY")
            port_spelling = suffix[1:] if suffix else None
            if ":" in (port_spelling or ""):
                fail("INVALID_AUTHORITY")
        else:
            if "[" in authority or "]" in authority or authority.count(":") > 1:
                fail("INVALID_AUTHORITY")
            host, separator, port_spelling = authority.partition(":")
            port_spelling = port_spelling if separator else None
        if not host:
            fail("INVALID_AUTHORITY")
        port = None
        if port_spelling is not None:
            if not _ascii_digits(port_spelling):
                fail("INVALID_PORT")
            # A 65K-character zero-prefixed port is legal spelling; avoid
            # Python's process-wide integer conversion length limit.
            significant = port_spelling.lstrip("0") or "0"
            if len(significant) > 5 or int(significant) > 65535:
                fail("INVALID_PORT")
            port = int(significant)
        if "%" in host:
            fail("HOST_PERCENT_UNSUPPORTED")
        return host, port, bracketed

    def _host(self, host, bracketed):
        if bracketed:
            if re.fullmatch(r"v[0-9a-f]+\.[A-Za-z0-9._~!$&'()*+,;=:\-]+", host, re.IGNORECASE | re.ASCII):
                fail("IP_UNSUPPORTED")
            try:
                return str(ipaddress.IPv6Address(host)), "ipv6"
            except ipaddress.AddressValueError:
                fail("INVALID_IP")
        # Only the ORIGINAL ASCII dotted spelling can validate as IPv4.
        # Unicode dot/digit mapping must never manufacture an accepted IP.
        rootless = host[:-1] if host.endswith(".") else host
        if _numeric_candidate(rootless):
            labels = host.split(".")
            if len(labels) != 4 or any(not _ascii_digits(v) or len(v) > 3 or (len(v) > 1 and v[0] == "0") or int(v) > 255 for v in labels):
                fail("INVALID_IP")
            return host, "ipv4"
        try:
            mapped = self.idna.remap(host.translate(DOT_MAP))
        except (ValueError, self.idna.core.IDNAError):
            fail("INVALID_HOST")
        mapped = mapped[:-1] if mapped.endswith(".") else mapped
        if _numeric_candidate(mapped):
            # Mapping must never manufacture a valid alternative IP spelling.
            fail("INVALID_IP")
        if len(mapped.split(".")) < 2 or any(not part for part in mapped.split(".")):
            fail("INVALID_HOST")
        try:
            canonical = self.idna.ascii_labels(mapped)
        except (ValueError, UnicodeError):
            fail("INVALID_HOST")
        if _numeric_candidate(canonical):
            fail("INVALID_IP")
        return canonical, "dns"

    @staticmethod
    def _signals(components):
        # ALL component percent grammar is checked before ANY UTF8 decoding.
        for component in components:
            i = 0
            while i < len(component):
                if component[i] == "%":
                    if i + 2 >= len(component) or component[i + 1] not in HEX or component[i + 2] not in HEX:
                        fail("INVALID_PERCENT_ESCAPE")
                    i += 3
                else:
                    i += 1
        decoded = []
        for component in components:
            octets, i = bytearray(), 0
            while i < len(component):
                if component[i] == "%":
                    octets.append(int(component[i + 1:i + 3], 16))
                    i += 3
                else:
                    octets.extend(component[i].encode("utf-8"))
                    i += 1
            try:
                decoded.append(octets.decode("utf-8", errors="strict"))
            except UnicodeDecodeError:
                fail("INVALID_UTF8_ESCAPE")
        return decoded

    def _extract(self, raw):
        if type(raw) is not str:
            fail("INPUT_TYPE")
        if not raw:
            fail("EMPTY_INPUT")
        if len(raw) > 65536:
            fail("INPUT_TOO_LONG")
        if any(0xD800 <= ord(c) <= 0xDFFF for c in raw):
            fail("INVALID_CODEPOINT")
        if any(_forbidden(ord(c)) for c in raw):
            fail("FORBIDDEN_CHARACTER")
        source, form, recovered, authority, path, query, fragment, query_present, fragment_present = self._structure(raw)
        host_spelling, port, bracketed = self._authority(authority)
        host, kind = self._host(host_spelling, bracketed)
        if kind == "dns":
            suffix, registered, rule, section, subdomains = self.suffixes.lookup(host)
        else:
            suffix, registered, rule, section, subdomains = None, None, None, None, []
        decoded_path, decoded_query, decoded_fragment = self._signals((path, query, fragment))
        signal_tokens = _tokens(host) | _tokens(decoded_path) | _tokens(decoded_query) | _tokens(decoded_fragment)
        subdomain_tokens = _tokens(".".join(subdomains))
        digits = sum("0" <= c <= "9" for c in raw)
        values = [len(raw)] + [raw.count(c) for c in "@?-=.#%+$!*,"]
        values += [raw.count("//"), digits, sum("a" <= c <= "z" or "A" <= c <= "Z" for c in raw)]
        values += [int(source == "https"), int(kind != "dns"), int(recovered), int(kind == "dns" and host in self.shorteners)]
        values += [int(bool(signal_tokens & self.brands)), int(bool(subdomain_tokens & self.brands)), int(bool(_tokens(decoded_path) & self.brands))]
        values += [host.count("-"), sum("0" <= c <= "9" for c in host), int(len(host) > 20), int(len(subdomains) > 2)]
        values += [int(kind == "dns" and host.rsplit(".", 1)[-1] in self.final_labels), len(signal_tokens & self.keywords)]
        values += [int(any(NESTED.search(c) for c in (decoded_path, decoded_query, decoded_fragment))), sum(bool(p) for p in query.split("&")), raw.count("%")]
        values += [_entropy(host), _entropy(path), float(digits / len(raw)), len(subdomains), len(TOKENS.findall(raw))]
        metadata = dict(zip(METADATA_KEYS, (source, form, recovered, kind, host, port, suffix, registered, rule, section, query_present, fragment_present)))
        return {"contract_version": CONTRACT_VERSION, "bundle_sha256": BUNDLE_SHA256, "status": "ok", "error_code": None, "features": values, "metadata": metadata}
