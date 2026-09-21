from trusted_domains import TRUSTED_DOMAINS


def _levenshtein(s1: str, s2: str) -> int:
    """
    Computes the Levenshtein edit distance between two strings.
    Used to detect typosquatting domains that closely mimic
    trusted domains through character substitution.
    """
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions    = prev_row[j + 1] + 1
            deletions     = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _extract_root_domain(hostname: str) -> str:
    """
    Extracts root domain from hostname.
    Example: www.google.com → google.com
    """
    hostname = hostname.lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _build_trusted_roots() -> set:
    """
    Builds a set of root domains from the trusted domain list.
    Used for both exact matching and edit distance computation.
    """
    roots = set()
    for domain in TRUSTED_DOMAINS:
        roots.add(_extract_root_domain(domain))
    return roots


TRUSTED_ROOTS = _build_trusted_roots()


def classify_domain(hostname: str) -> dict:
    """
    Classifies a hostname into one of three tiers based on
    its relationship to known trusted domains.

    Tier 1 — Exact match:
        Domain is in the trusted list.
        ML inference is bypassed entirely.
        Threshold: not applicable.

    Tier 2 — Close mimic (edit distance 1-2):
        Domain closely resembles a trusted domain.
        Likely typosquatting attack.
        ML threshold: 0.30 (aggressive).

    Tier 3 — Unknown domain (edit distance 3+):
        No significant similarity to trusted domains.
        ML threshold: 0.75 (standard).

    Returns:
        tier (int): 1, 2, or 3
        threshold (float): ML classification threshold to apply
        bypass (bool): True if ML should be skipped entirely
        closest_match (str): nearest trusted domain found
        distance (int): edit distance to closest match
    """
    if not hostname:
        return {
            "tier":          3,
            "threshold":     0.75,
            "bypass":        False,
            "closest_match": None,
            "distance":      999
        }

    root = _extract_root_domain(hostname)

    if root in TRUSTED_ROOTS:
        return {
            "tier":          1,
            "threshold":     1.0,
            "bypass":        True,
            "closest_match": root,
            "distance":      0
        }

    min_distance = 999
    closest = None

    for trusted_root in TRUSTED_ROOTS:
        dist = _levenshtein(root, trusted_root)
        if dist < min_distance:
            min_distance = dist
            closest = trusted_root

    if min_distance <= 2:
        return {
            "tier":          2,
            "threshold":     0.30,
            "bypass":        False,
            "closest_match": closest,
            "distance":      min_distance
        }

    return {
        "tier":          3,
        "threshold":     0.75,
        "bypass":        False,
        "closest_match": closest,
        "distance":      min_distance
    }