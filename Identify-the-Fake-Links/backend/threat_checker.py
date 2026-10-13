"""Reputation-style checks: local blacklist, brand impersonation, domain age,
TLS validity, and (optionally) Google Safe Browsing.

Set the environment variable GOOGLE_SAFE_BROWSING_KEY to enable Safe Browsing.
"""
import json
import os
import urllib.request
from pathlib import Path

from url_analyzer import is_ip_host, registrable_domain

BLACKLIST_FILE = Path(__file__).resolve().parent.parent / "database" / "blacklist.txt"

# brand -> official registrable domains
BRANDS = {
    "google": {"google.com", "google.co.in", "gstatic.com", "googleapis.com", "goo.gl"},
    "youtube": {"youtube.com", "youtu.be"},
    "gmail": {"gmail.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "github": {"github.com", "github.io"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
}


def _load_blacklist():
    try:
        lines = BLACKLIST_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    return {l.strip().lower() for l in lines if l.strip() and not l.startswith("#")}


BLACKLIST = _load_blacklist()


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans("0135$", "oless")


def _normalize(label: str) -> str:
    return label.translate(_LEET).replace("rn", "m").replace("vv", "w")


def _brand_impersonation(host: str):
    """Return (brand, why) if host looks like it imitates a known brand."""
    reg = registrable_domain(host)
    if any(reg in official for official in BRANDS.values()):
        return None  # genuinely a brand's own domain
    tokens = [t for t in host.replace(".", "-").split("-") if t]
    for brand in BRANDS:
        for tok in tokens:
            if tok == brand:
                return brand, f"uses the name '{brand}' but is not an official {brand} domain"
            # look-alike spelling, e.g. paypa1, g00gle, arnazon (rn -> m)
            if tok != brand and (
                _normalize(tok) == brand
                or (len(brand) >= 6 and _edit_distance(tok, brand) == 1)
            ):
                return brand, f"'{tok}' looks like a misspelling of '{brand}'"
        # brand glued to other words, e.g. paypalsecure.com (long brands only)
        if len(brand) >= 6 and brand in host:
            return brand, f"uses the name '{brand}' but is not an official {brand} domain"
    return None


def _safe_browsing(url: str):
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return None
    body = {
        "client": {"clientId": "identify-fake-links", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    req = urllib.request.Request(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return bool(json.loads(r.read().decode()).get("matches"))
    except Exception:
        return None


def get_threat_info(url: str, host: str, domain_info: dict | None = None) -> dict:
    host = host.lower()
    domain_info = domain_info or {}
    checks, score = [], 0

    def add(label, flagged, points, bad, good):
        nonlocal score
        if flagged:
            score += points
        checks.append({"label": label, "flagged": bool(flagged),
                       "points": points if flagged else 0,
                       "detail": bad if flagged else good})

    # Local blacklist (host or any parent domain)
    parts = host.split(".")
    parents = {".".join(parts[i:]) for i in range(len(parts))}
    add("Blacklist", bool(parents & BLACKLIST), 60,
        "This domain is on the local blacklist.",
        "Not found in the local blacklist.")

    # Brand impersonation (not meaningful for raw IPs)
    if not is_ip_host(host):
        hit = _brand_impersonation(host)
        add("Brand impersonation", bool(hit), 30,
            f"Possible impersonation: {hit[1]}." if hit else "",
            "No known-brand impersonation pattern found.")

    # Domain age (from RDAP, may be unavailable)
    days = domain_info.get("domain_age_days")
    if days is not None:
        points = 25 if days < 30 else 10 if days < 180 else 0
        add("Domain age", points > 0, points,
            f"The domain was registered only {days} days ago.",
            f"The domain is {days} days old.")

    # TLS certificate validity
    if domain_info.get("tls_valid") is False:
        add("SSL certificate", True, 25,
            "The site's SSL certificate failed validation: " + domain_info.get("ssl", ""), "")
    elif domain_info.get("tls_valid") is True:
        add("SSL certificate", False, 0, "", domain_info.get("ssl", "Valid certificate."))

    # Google Safe Browsing (only when an API key is configured)
    sb = _safe_browsing(url)
    if sb is not None:
        add("Google Safe Browsing", sb, 60,
            "Google Safe Browsing lists this URL as unsafe.",
            "Not listed by Google Safe Browsing.")

    return {"score": score, "checks": checks}
