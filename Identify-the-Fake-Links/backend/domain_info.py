"""Network lookups: DNS, IP geolocation, TLS certificate, domain age (RDAP).

Every lookup is best-effort and fails soft to 'Unavailable'.
Outbound connections are only made to public IP addresses (SSRF protection).
"""
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from url_analyzer import is_ip_host, registrable_domain

UA = {"User-Agent": "identify-the-fake-links/1.0"}


def _json_get(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _geolocate(ip):
    try:
        data = _json_get(f"https://ipwho.is/{ip}")
        if data.get("success"):
            loc = ", ".join(x for x in [data.get("city"), data.get("region"), data.get("country")] if x)
            org = (data.get("connection") or {}).get("org")
            return loc or "Unavailable", org or "Unavailable"
    except Exception:
        pass
    return "Unavailable", "Unavailable"


def _tls_check(host, ip):
    """Return (valid: bool|None, message)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        ca = issuer.get("organizationName") or issuer.get("commonName") or "unknown CA"
        days_left = int((expires - time.time()) // 86400)
        return True, f"Valid certificate issued by {ca}, expires in {days_left} days"
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message
    except (OSError, ssl.SSLError):
        return None, "HTTPS not reachable"


def _domain_age_days(domain):
    try:
        data = _json_get(
            "https://rdap.org/domain/" + urllib.parse.quote(domain, safe=""),
            headers={"Accept": "application/rdap+json"},
        )
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        pass
    return None


def _format_age(days):
    if days is None:
        return "Unavailable"
    if days < 60:
        return f"{days} days"
    if days < 730:
        return f"{days // 30} months"
    return f"{days // 365} years"


def get_domain_info(host, scheme):
    result = {
        "ip": "Unavailable",
        "location": "Unavailable",
        "organization": "Unavailable",
        "domain_age": "Unavailable",
        "domain_age_days": None,
        "ssl": "Not enabled (HTTP)" if scheme != "https" else "Unavailable",
        "tls_valid": None,
    }

    try:
        ip = host if _is_plain_ip(host) else socket.gethostbyname(host)
        result["ip"] = ip
    except Exception:
        result["ip"] = "Unavailable"
        result["location"] = result["organization"] = "Domain does not resolve"
        return result

    try:
        public = ipaddress.ip_address(result["ip"]).is_global
    except ValueError:
        public = False
    if not public:
        result["location"] = result["organization"] = "Private / non-public address"
        return result

    with ThreadPoolExecutor(max_workers=3) as pool:
        geo = pool.submit(_geolocate, result["ip"])
        tls = pool.submit(_tls_check, host, result["ip"])
        age = None if is_ip_host(host) else pool.submit(_domain_age_days, registrable_domain(host))
        result["location"], result["organization"] = geo.result()
        valid, msg = tls.result()
        result["tls_valid"] = valid
        if valid is True:
            result["ssl"] = msg + ("" if scheme == "https" else " (but this link uses HTTP)")
        elif valid is False:
            result["ssl"] = msg
        else:
            result["ssl"] = "HTTPS not reachable" if scheme == "https" else "Not enabled (HTTP)"
        if age is not None:
            result["domain_age_days"] = age.result()
            result["domain_age"] = _format_age(result["domain_age_days"])
    return result


def _is_plain_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
