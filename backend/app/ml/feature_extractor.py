import re
from urllib.parse import urlparse
from typing import Dict, List, Any

# Common URL shortening domains used to conceal destination links
SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rb.gy"
}

# Suspicious keywords frequently observed in phishing campaigns
SENSITIVE_KEYWORDS = [
    "login", "verify", "verification", "account", "update", "banking",
    "secure", "signin", "sign-in", "confirm", "password", "authenticate",
    "security", "wallet", "recover", "unlock", "support", "billing"
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "having_ip",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question_marks",
    "count_equal_signs",
    "count_slashes",
    "count_digits",
    "subdomain_count",
    "is_https",
    "is_shortened",
    "keyword_in_domain"
]


def extract_url_features_dict(url: str) -> Dict[str, Any]:
    """
    Extracts 14 lexical numerical features from a URL string.
    
    SAFETY GUARANTEE:
    This function performs strictly local string parsing.
    It DOES NOT send HTTP requests, resolve DNS, or visit the target URL.
    """
    url_clean = str(url).strip()
    
    # Prepend http scheme if absent (case-insensitive check) to enable consistent parsing by urlparse
    if not url_clean.lower().startswith(("http://", "https://")):
        parse_target = "http://" + url_clean
    else:
        parse_target = url_clean

    try:
        parsed = urlparse(parse_target)
        domain = parsed.netloc.lower()
        # Remove port if present (e.g., example.com:8080)
        domain = domain.split(":")[0]
        path = parsed.path
        query = parsed.query
    except Exception:
        domain = ""
        path = ""
        query = ""

    # Feature 1: Total URL length
    url_len = len(url_clean)

    # Feature 2: Domain length
    dom_len = len(domain)

    # Feature 3: Having IP address in place of domain (IPv4 or IPv6)
    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^[0-9a-fA-F:]+$"
    having_ip = 1 if (re.match(ipv4_pattern, domain) or (":" in domain and re.match(ipv6_pattern, domain))) else 0

    # Feature 4: Count of dots (.)
    count_dots = url_clean.count(".")

    # Feature 5: Count of hyphens (-)
    count_hyphens = url_clean.count("-")

    # Feature 6: Count of @ symbol
    count_at = url_clean.count("@")

    # Feature 7: Count of question marks (?)
    count_qm = url_clean.count("?")

    # Feature 8: Count of equal signs (=)
    count_equal = url_clean.count("=")

    # Feature 9: Count of forward slashes (/)
    count_slashes = url_clean.count("/")

    # Feature 10: Count of numeric digits
    count_digits = sum(c.isdigit() for c in url_clean)

    # Feature 11: Subdomain count (number of dots in domain minus 1)
    if domain:
        parts = domain.split(".")
        # If domain has 2 or more dots (e.g. sub.domain.com), subdomain count > 0
        subdomain_count = max(0, len(parts) - 2)
    else:
        subdomain_count = 0

    # Feature 12: Is HTTPS protocol used
    is_https = 1 if url_clean.lower().startswith("https://") else 0

    # Feature 13: Is known URL shortener service
    is_shortened = 1 if domain in SHORTENING_DOMAINS else 0

    # Feature 14: Sensitive/phishing keyword present inside domain name
    domain_lower = domain.lower()
    keyword_in_domain = 1 if any(kw in domain_lower for kw in SENSITIVE_KEYWORDS) else 0

    return {
        "url_length": url_len,
        "domain_length": dom_len,
        "having_ip": having_ip,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_question_marks": count_qm,
        "count_equal_signs": count_equal,
        "count_slashes": count_slashes,
        "count_digits": count_digits,
        "subdomain_count": subdomain_count,
        "is_https": is_https,
        "is_shortened": is_shortened,
        "keyword_in_domain": keyword_in_domain,
    }


def extract_url_features_vector(url: str) -> List[float]:
    """
    Returns the feature vector as an ordered list of floats for machine learning input.
    Matches the exact order of FEATURE_NAMES.
    """
    f_dict = extract_url_features_dict(url)
    return [float(f_dict[name]) for name in FEATURE_NAMES]
