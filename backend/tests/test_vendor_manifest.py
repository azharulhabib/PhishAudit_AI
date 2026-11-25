import hashlib
import json
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "vendor" / "url-features-v1"
MANIFEST = json.loads((VENDOR / "VENDOR_MANIFEST.json").read_text())


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_every_vendored_file_matches_the_hash_manifest():
    for relative, expected in MANIFEST["files"].items():
        path = VENDOR / relative
        assert path.is_file(), relative
        assert path.stat().st_size == expected["size_bytes"], relative
        assert _sha256(path) == expected["sha256"], relative


def test_no_unlisted_files_in_vendor_tree():
    on_disk = {
        p.relative_to(VENDOR).as_posix()
        for p in VENDOR.rglob("*")
        if p.is_file() and p.name != "VENDOR_MANIFEST.json" and "__pycache__" not in p.parts
    }
    assert on_disk == set(MANIFEST["files"])


def test_contract_version_and_bundle_identity():
    assert MANIFEST["contract_version"] == "1.0.0"
    contract_manifest = VENDOR / "contract" / "normative-manifest.json"
    assert _sha256(contract_manifest) == MANIFEST["bundle_sha256"]
    assert json.loads(contract_manifest.read_text())["version"] == "1.0.0"


def test_normative_assets_listed_by_the_contract_are_present():
    normative = json.loads((VENDOR / "contract" / "normative-manifest.json").read_text())["files"]
    for name, expected in normative.items():
        asset = VENDOR / "contract" / name
        assert asset.stat().st_size == expected["size_bytes"], name
        assert _sha256(asset) == expected["sha256"], name
