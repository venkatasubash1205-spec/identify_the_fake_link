"""Rule-based URL analysis (lexical / structural checks only, no network)."""
import ipaddress
import re
from urllib.parse import urlparse

KEYWORDS = [
    "login", "signin", "verify", "verification", "password", "account",
    "update", "secure", "security", "bank", "confirm", "claim", "free",
    "urgent", "wallet", "payment",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# TLDs that are cheap/free and heavily abused. A hint, never proof.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov",
    "work", "loan", "icu", "buzz", "rest", "country", "kim", "support",
}

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "nic", "res"}


def is_ip_host(host: str) -> bool:
    """True for dotted IPv4/IPv6 and for obfuscated decimal / hex IPv4."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]+", host))


def registrable_domain(host: str) -> str:
    """Approximate 'example.co.in' / 'example.com' without external data."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def analyze_url(url: str, scheme_given: bool = True) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    checks = []
    score = 0

    def add(label, flagged, points, bad, good):
        nonlocal score
        if flagged:
            score += points
        checks.append({
            "label": label,
            "flagged": bool(flagged),
            "points": points if flagged else 0,
            "detail": bad if flagged else good,
        })

    # 1. HTTPS
    if not scheme_given:
        add("HTTPS", False, 0, "", "No scheme was typed, so https:// was assumed.")
    else:
        add("HTTPS", parsed.scheme != "https", 10,
            "The URL does not use HTTPS, so traffic is not encrypted.",
            "The URL uses HTTPS.")

    # 2. IP address instead of a domain
    ip_host = is_ip_host(host)
    add("IP address", ip_host, 25,
        "The URL uses an IP address instead of a domain name.",
        "A domain name is used (not a raw IP address).")

    # 3. '@' in the authority part (everything before '@' is ignored by browsers)
    userinfo = parsed.netloc.rpartition("@")[0] if "@" in parsed.netloc else ""
    if userinfo and "." in userinfo:
        add("@ symbol", True, 45,
            f"Text before the @ ('{userinfo}') looks like a domain but is ignored by the browser; "
            f"the real destination is {host}.", "")
    else:
        add("@ symbol", "@" in parsed.netloc, 25,
            "The URL contains an @ symbol, which can hide the real destination.",
            "No @ symbol in the address.")

    # 4. Length
    n = len(url)
    if n > 200:
        add("URL length", True, 20, f"The URL is extremely long ({n} characters).", "")
    elif n > 100:
        add("URL length", True, 10, f"The URL is unusually long ({n} characters).", "")
    else:
        add("URL length", False, 0, "", f"URL length is normal ({n} characters).")

    # 5. Subdomains
    if ip_host:
        sub_count = 0
    else:
        sub_count = max(0, len(host.split(".")) - len(registrable_domain(host).split(".")))
    add("Subdomains", sub_count >= 3, 15,
        f"The URL contains many subdomains ({sub_count}).",
        f"Subdomain count is normal ({sub_count}).")

    # 6. Suspicious keywords (host + path + query, not the scheme)
    haystack = (host + parsed.path + "?" + parsed.query).lower()
    found = [k for k in KEYWORDS if k in haystack]
    add("Suspicious keywords", bool(found), min(len(found) * 5, 20),
        "Suspicious keywords detected: " + ", ".join(found),
        "No phishing-style keywords found.")

    # 7. Hyphens in the domain
    add("Hyphens", host.count("-") >= 2, 10,
        "The domain contains multiple hyphens.",
        "Hyphen usage in the domain is normal.")

    # 8. Encoded characters
    add("Encoded characters", "%" in url, 5,
        "The URL contains percent-encoded characters.",
        "No encoded characters found.")

    # 9. Too many dots
    add("Dots", url.count(".") > 6, 10,
        "The URL contains an unusually large number of dots.",
        "Number of dots is normal.")

    # 10. Punycode / non-ASCII (look-alike characters)
    lookalike = host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host)
    add("Look-alike characters", lookalike, 20,
        "The domain uses punycode / non-ASCII characters that can imitate real sites.",
        "The domain uses plain ASCII characters.")

    # 11. Unusual port
    try:
        port = parsed.port
    except ValueError:
        port = None
    add("Port", port not in (None, 80, 443), 5,
        f"The URL uses an unusual port ({port}).",
        "Standard port.")

    # 12. URL shortener
    add("URL shortener", host in SHORTENERS, 15,
        "A URL shortener hides the real destination.",
        "Not a known URL shortener.")

    # 13. Commonly abused TLD
    tld = host.rsplit(".", 1)[-1] if "." in host and not ip_host else ""
    add("Top-level domain", tld in SUSPICIOUS_TLDS, 8,
        f"The .{tld} TLD is frequently abused for phishing.",
        "The TLD is not on the commonly-abused list.")

    # 14. 'https' used as a word inside the hostname
    add("Fake 'https' in domain", "https" in host, 10,
        "The word 'https' appears inside the domain name to look trustworthy.",
        "No fake 'https' in the domain name.")

    return {"score": min(score, 100), "checks": checks}
