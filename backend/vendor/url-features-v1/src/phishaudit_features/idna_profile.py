"""Pinned UTS46 mapping and isolated Unicode-17 IDNA2008 validation.

The official mapping asset supplies mapping and post-mapping validity. UTS46
is NOT IDNA2008 PVALID/ContextO: calling idna.alabel would over-reject allowed
symbols. Only its RFC5893 Bidi and ContextJ primitives run privately with UCD17.
"""
from bisect import bisect_right
import importlib.util
from pathlib import Path

import idna
import idna.core
import idna.idnadata
import unicodedata2


class IDNAProfile:
    def __init__(self, table: Path):
        if idna.__version__ != "3.19" or idna.idnadata.__version__ != "17.0.0":
            raise ValueError("IDNA dependency/table version mismatch")
        if unicodedata2.unidata_version != "17.0.0":
            raise ValueError("Unicode property dependency mismatch")
        # Execute the installed pinned core once into a private namespace; its
        # relative imports still resolve its own pinned idna data/intranges.
        spec = importlib.util.spec_from_file_location(
            "idna._phishaudit_private_core", Path(idna.core.__file__)
        )
        core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core)
        core.unicodedata = unicodedata2
        self.core = core
        self.rows = []
        for line in table.read_text(encoding="utf-8").splitlines():
            data = line.split("#", 1)[0].strip()
            if not data:
                continue
            fields = [field.strip() for field in data.split(";")]
            ends = fields[0].split("..")
            start, end = int(ends[0], 16), int(ends[-1], 16)
            mapping = "".join(chr(int(c, 16)) for c in fields[2].split()) if len(fields) > 2 else ""
            self.rows.append((start, end, fields[1], mapping))
        self.starts = [r[0] for r in self.rows]
        # Reject incomplete/corrupt table parsing even after the asset hash check.
        if self.rows[0][0] != 0 or self.rows[-1][1] != 0x10FFFF:
            raise ValueError("Incomplete UTS46 table")
        if any(a[1] + 1 != b[0] for a, b in zip(self.rows, self.rows[1:])):
            raise ValueError("Noncontiguous UTS46 table")

    def remap(self, host: str) -> str:
        output = []
        for char in host:
            cp = ord(char)
            _, end, status, mapping = self.rows[bisect_right(self.starts, cp) - 1]
            if cp > end:
                raise ValueError("Missing UTS46 code point")
            if status in ("valid", "deviation"):
                output.append(char)
            elif status == "mapped":
                output.append(mapping)
            elif status == "ignored":
                continue
            else:
                # Includes legacy disallowed_STD3_* statuses if table changes.
                raise ValueError("Disallowed UTS46 code point")
        return unicodedata2.normalize("NFC", "".join(output))

    def ascii_labels(self, mapped: str) -> str:
        # Never invoke idna.encode(raw_host): its unrelated raw-input limit
        # would reject long spellings that map to short, valid DNS names.
        labels = mapped.split(".")
        decoded = []
        for label in labels:
            if label.startswith("xn--"):
                try:
                    ulabel = label[4:].encode("ascii").decode("punycode")
                except UnicodeError as exc:
                    raise ValueError("Invalid A-label") from exc
                if not any(ord(c) >= 128 for c in ulabel):
                    raise ValueError("ASCII-only A-label")
            else:
                ulabel = label
            decoded.append(ulabel)
        domain_bidi = any(unicodedata2.bidirectional(c) in ("R", "AL", "AN") for label in decoded for c in label)
        result = []
        for label in decoded:
            if not label or unicodedata2.normalize("NFC", label) != label:
                raise ValueError("Empty or non-NFC label")
            if label.startswith("-") or label.endswith("-") or label[2:4] == "--":
                raise ValueError("Invalid hyphens")
            if unicodedata2.category(label[0]).startswith("M"):
                raise ValueError("Leading combining mark")
            for i, c in enumerate(label):
                cp = ord(c)
                _, end, status, _ = self.rows[bisect_right(self.starts, cp) - 1]
                if cp > end or status not in ("valid", "deviation") or c == ".":
                    raise ValueError("Post-mapping validity")
                if cp < 128 and not ("a" <= c <= "z" or "0" <= c <= "9" or c == "-"):
                    raise ValueError("STD3 ASCII rules")
                if cp in (0x200C, 0x200D) and not self.core.valid_contextj(label, i):
                    raise ValueError("Joiner context")
            if domain_bidi:
                self.core.check_bidi(label, check_ltr=True)
            alabel = label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
            result.append(alabel)
        canonical = ".".join(result)
        if any(not 1 <= len(label) <= 63 for label in result) or len(canonical) > 253:
            raise ValueError("DNS length")
        return canonical
