"""Offline PSL algorithm with both pinned ICANN and PRIVATE sections."""


class SuffixRules:
    def __init__(self, path, idna_profile):
        self.rules = {}
        section = None
        for line in path.read_text(encoding="utf-8").splitlines():
            if "BEGIN ICANN DOMAINS" in line:
                section = "ICANN"
            elif "BEGIN PRIVATE DOMAINS" in line:
                section = "PRIVATE"
            value = line.split("//", 1)[0].strip()
            if not value:
                continue
            if section not in ("ICANN", "PRIVATE"):
                raise ValueError("PSL rule outside a section")
            operator = "!" if value.startswith("!") else "*." if value.startswith("*.") else ""
            body = value[len(operator):]
            body = idna_profile.ascii_labels(idna_profile.remap(body))
            rule = operator + body
            if rule in self.rules:
                raise ValueError("Duplicate canonical PSL rule")
            self.rules[rule] = section

    def lookup(self, host):
        labels = host.split(".")
        matches, exceptions = [], []
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if "!" + suffix in self.rules:
                exceptions.append((len(labels) - i, "!" + suffix))
            if suffix in self.rules:
                matches.append((len(labels) - i, suffix))
            if i and "*." + suffix in self.rules:
                matches.append((len(labels) - i + 1, "*." + suffix))
        if exceptions:
            width, rule = max(exceptions)
            suffix_width = width - 1
        elif matches:
            suffix_width, rule = max(matches)
        else:
            suffix_width, rule = 1, "*"
        public = ".".join(labels[-suffix_width:])
        registered = ".".join(labels[-suffix_width - 1:]) if len(labels) > suffix_width else None
        subdomains = labels[:-suffix_width - 1] if registered else []
        section = "DEFAULT" if rule == "*" else self.rules[rule]
        return public, registered, rule, section, subdomains
