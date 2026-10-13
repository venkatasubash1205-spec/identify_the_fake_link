import os
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory

from url_analyzer import analyze_url, is_ip_host
from domain_info import get_domain_info
from threat_checker import get_threat_info

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")

# CORS is only needed if index.html is opened straight from disk (file://).
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass

MAX_URL_LENGTH = 2048


def risk_level(score: int) -> dict:
    if score >= 60:
        return {"level": "High", "verdict": "Potentially Phishing"}
    if score >= 30:
        return {"level": "Medium", "verdict": "Suspicious"}
    return {"level": "Low", "verdict": "Likely Legitimate"}


def valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return "." in host or is_ip_host(host)


@app.get("/")
def home():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    raw_url = str(data.get("url", "")).strip()
    if not raw_url:
        return jsonify({"error": "URL is required."}), 400
    if len(raw_url) > MAX_URL_LENGTH or re.search(r"\s", raw_url):
        return jsonify({"error": "The entered text is not a valid URL."}), 400

    scheme_given = bool(re.match(r"^https?://", raw_url, re.I))
    check_url = raw_url if scheme_given else "https://" + raw_url

    try:
        parsed = urlparse(check_url)
        host = (parsed.hostname or "").lower()
        _ = parsed.port  # raises ValueError on a bad port
    except ValueError:
        return jsonify({"error": "The entered text is not a valid URL."}), 400
    if not valid_host(host):
        return jsonify({"error": "The entered text is not a valid URL."}), 400

    url_result = analyze_url(check_url, scheme_given)
    domain = get_domain_info(host, parsed.scheme)
    threat = get_threat_info(check_url, host, domain)

    score = min(100, url_result["score"] + threat["score"])
    checks = url_result["checks"] + threat["checks"]
    reasons = [c["detail"] for c in checks if c["flagged"]]
    if not reasons:
        reasons = ["No major suspicious URL patterns were detected."]

    return jsonify({
        "url": raw_url,
        "domain": host,
        "ip": domain["ip"],
        "location": domain["location"],
        "organization": domain["organization"],
        "domain_age": domain["domain_age"],
        "ssl": domain["ssl"],
        "score": score,
        **risk_level(score),
        "checks": checks,
        "reasons": reasons,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
