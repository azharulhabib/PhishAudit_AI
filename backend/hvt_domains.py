HVT_BRANDS = {
    #  Global Financial 
    "paypal":           "paypal.com",
    "stripe":           "stripe.com",
    "chase":            "chase.com",
    "citibank":         "citibank.com",
    "wellsfargo":       "wellsfargo.com",
    "bankofamerica":    "bankofamerica.com",
    "barclays":         "barclays.com",
    "hsbc":             "hsbc.com",
    "binance":          "binance.com",
    "coinbase":         "coinbase.com",
    "kraken":           "kraken.com",
    "blockchain":       "blockchain.com",
    "visa":             "visa.com",
    "mastercard":       "mastercard.com",
    "americanexpress":  "americanexpress.com",

    #  Bangladesh-Specific Financial 
    "bkash":            "bkash.com",
    "nagad":            "nagad.com.bd",
    "rocket":           "dutchbanglabank.com",
    "dbbl":             "dutchbanglabank.com",
    "dutchbangla":      "dutchbanglabank.com",
    "islamibank":       "islamibankbd.com",
    "bracbank":         "bracbank.com",
    "citybank":         "thecitybank.com",
    "ebl":              "ebl.com.bd",
    "ucbl":             "ucbl.com.bd",

    #  Big Tech and Data Custodians 
    "google":           "google.com",
    "gmail":            "gmail.com",
    "microsoft":        "microsoft.com",
    "outlook":          "outlook.com",
    "apple":            "apple.com",
    "icloud":           "icloud.com",
    "facebook":         "facebook.com",
    "instagram":        "instagram.com",
    "whatsapp":         "whatsapp.com",
    "twitter":          "twitter.com",
    "linkedin":         "linkedin.com",
    "amazon":           "amazon.com",
    "netflix":          "netflix.com",
    "dropbox":          "dropbox.com",
    "github":           "github.com",
    "adobe":            "adobe.com",
    "spotify":          "spotify.com",
    "yahoo":            "yahoo.com",
    "ebay":             "ebay.com",
    "dhl":              "dhl.com",
    "fedex":            "fedex.com",
    "ups":              "ups.com",

    #  Government and Institutions 
    "irs":              "irs.gov",
    "gov":              "gov.uk",
    "bracu":            "bracu.ac.bd",
}

# Keywords indicating credential harvesting or financial intent.
# Presence of multiple keywords shifts ML threshold downward.

HIGH_RISK_KEYWORDS = [
    # Authentication
    "login", "signin", "sign-in", "logon",
    "verify", "verification", "validate",
    "auth", "authenticate", "authorization",
    "otp", "sso", "2fa", "mfa",

    # Account and credentials
    "account", "credential", "password",
    "username", "passwd", "pin",

    # Security framing
    "secure", "security", "protected",
    "safeguard", "recovery", "recover",
    "unlock", "reactivate", "restore",

    # Financial and urgency
    "banking", "payment", "invoice",
    "wallet", "transaction", "transfer",
    "billing", "renewal", "refund",
    "suspend", "suspended", "unusual",
    "alert", "warning", "urgent",
    "confirm", "update",

    # Bangladesh-specific
    "bkash", "nagad", "rocket",
    "mobile-banking", "mobilebanking",
]


def detect_combo_squatting(hostname: str, full_url: str) -> dict:
    """
    Detects combo-squatting: a known HVT brand name appears
    anywhere in the URL but the root domain does not match
    the official domain for that brand.

    Example:
        secure-paypal-login.xyz contains 'paypal'
        but root domain is not paypal.com
        → combo-squatting detected

    Returns:
        detected (bool): whether combo-squatting was found
        brand (str): the impersonated brand keyword
        official_domain (str): what the correct domain should be
    """
    url_lower = full_url.lower()
    hostname_lower = hostname.lower()

    root = hostname_lower
    if root.startswith("www."):
        root = root[4:]

    for brand, official_domain in HVT_BRANDS.items():
        if brand in url_lower:
            official_root = official_domain
            if official_root.startswith("www."):
                official_root = official_root[4:]

            if root != official_root:
                return {
                    "detected":        True,
                    "brand":           brand,
                    "official_domain": official_domain
                }

    return {
        "detected":        False,
        "brand":           None,
        "official_domain": None
    }


def detect_high_risk_keywords(full_url: str) -> dict:
    """
    Checks if the URL contains high-risk keywords
    associated with credential harvesting or financial fraud.

    Returns:
        detected (bool): whether any keywords were found
        keywords_found (list): matched keywords
        count (int): number of keywords found
    """
    url_lower = full_url.lower()
    found = [kw for kw in HIGH_RISK_KEYWORDS if kw in url_lower]

    return {
        "detected":       len(found) > 0,
        "keywords_found": found,
        "count":          len(found)
    }