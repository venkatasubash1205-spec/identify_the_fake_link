# Identify the Fake Links (URL Security Analyzer)

Paste a URL and get a 0–100 risk score, a Low / Medium / High verdict, and a
check-by-check security report.

| Score | Level | Meaning |
|-------|--------|---------|
| 0–29 | Low | Likely legitimate |
| 30–59 | Medium | Suspicious |
| 60–100 | High | Potentially phishing |

## What it checks

**URL rules** – HTTPS, IP address instead of domain (incl. decimal/hex IPs), `@` trick,
URL length, subdomains, suspicious keywords, hyphens, encoded characters, dot count,
punycode look-alikes, unusual ports, URL shorteners, abused TLDs, fake "https" in the domain.

**Reputation / network** – brand impersonation (paypa1, paypal.com.evil.net…), local
blacklist (`database/blacklist.txt`), domain age (RDAP), SSL certificate validity,
DNS/IP, geolocation + hosting organisation, optional Google Safe Browsing.

Network lookups are best-effort: if one fails the report shows "Unavailable" and the
URL rules still run. If the Flask backend is down, the page falls back to a
browser-only rule engine.

## Project structure

```text
Identify-the-Fake-Links/
├── frontend/   index.html, style.css, script.js
├── backend/    app.py, url_analyzer.py, domain_info.py, threat_checker.py
├── database/   blacklist.txt
├── tests/      test_app.py
├── requirements.txt, Procfile, render.yaml
```

## Run locally

```bash
pip install -r requirements.txt
python backend/app.py
```

Open **http://127.0.0.1:5000** (Flask serves the frontend too).

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Deploy on Render

1. Push this folder to a GitHub repository.
2. On render.com: **New → Blueprint** (uses `render.yaml`) or **New → Web Service** with
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn --chdir backend app:app --bind 0.0.0.0:$PORT --timeout 60`
3. Optional: add the environment variable `GOOGLE_SAFE_BROWSING_KEY` to enable real
   Google Safe Browsing checks.

## Security notes

- The server only opens connections to **public** IPs (private/localhost targets are skipped).
- The UI renders results with `textContent`, never `innerHTML`.

## Limitations

The score is a heuristic, not proof a site is safe or malicious. For real-world
protection, add threat-intelligence feeds (VirusTotal, Safe Browsing), ML models
and redirect analysis.
