const checkBtn = document.getElementById("checkBtn");
const clearBtn = document.getElementById("clearBtn");
const input = document.getElementById("urlInput");

// Same origin when served by Flask / Render; direct to Flask when opened as a file.
const API_BASE = location.protocol === "file:" ? "http://127.0.0.1:5000" : "";

checkBtn.addEventListener("click", checkURL);
clearBtn.addEventListener("click", clearResult);
input.addEventListener("keydown", e => { if (e.key === "Enter") checkURL(); });
document.querySelectorAll(".chip").forEach(chip =>
    chip.addEventListener("click", () => { input.value = chip.dataset.url; checkURL(); }));

async function checkURL() {
    const url = input.value.trim();
    if (!url) { input.focus(); return; }

    checkBtn.disabled = true;
    checkBtn.textContent = "⏳ Analyzing...";
    try {
        const response = await fetch(API_BASE + "/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        if (!response.ok) { showInvalid(data.error || "Invalid URL"); return; }
        displayResult(data);
    } catch (error) {
        // Backend unreachable: fall back to the in-browser rule engine.
        const local = localAnalyze(url);
        if (local.invalid) showInvalid(local.error); else displayResult(local);
    } finally {
        checkBtn.disabled = false;
        checkBtn.textContent = "🔍 Analyze URL";
    }
}

// ---- Browser-only fallback (subset of the backend rules) ----
function localAnalyze(url) {
    const schemeGiven = /^https?:\/\//i.test(url);
    const check = schemeGiven ? url : "https://" + url;
    let parsed;
    try { parsed = new URL(check); } catch { return { invalid: true, error: "The entered text is not a valid URL." }; }
    const host = parsed.hostname.toLowerCase();
    if (!host.includes(".") || /\s/.test(url)) return { invalid: true, error: "The entered text is not a valid URL." };

    const checks = [];
    let score = 0;
    const add = (label, flagged, points, bad, good) => {
        if (flagged) score += points;
        checks.push({ label, flagged, points: flagged ? points : 0, detail: flagged ? bad : good });
    };

    if (!schemeGiven) add("HTTPS", false, 0, "", "No scheme was typed, so https:// was assumed.");
    else add("HTTPS", parsed.protocol !== "https:", 10, "The URL does not use HTTPS.", "The URL uses HTTPS.");
    add("IP address", /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /^\[.*\]$/.test(host), 25,
        "The URL uses an IP address instead of a domain name.", "A domain name is used.");
    add("@ symbol", /@/.test(check.split("/")[2] || ""), 25, "The URL contains an @ symbol.", "No @ symbol in the address.");
    if (check.length > 200) add("URL length", true, 20, "The URL is extremely long.", "");
    else add("URL length", check.length > 100, 10, "The URL is unusually long.", "URL length is normal.");
    add("Subdomains", host.split(".").length >= 5, 15, "The URL contains many subdomains.", "Subdomain count is normal.");
    const keywords = ["login","signin","verify","verification","password","account","update","secure","security","bank","confirm","claim","free","urgent","wallet","payment"];
    const hay = (host + parsed.pathname + parsed.search).toLowerCase();
    const found = keywords.filter(k => hay.includes(k));
    add("Suspicious keywords", found.length > 0, Math.min(found.length * 5, 20),
        "Suspicious keywords detected: " + found.join(", "), "No phishing-style keywords found.");
    add("Hyphens", (host.match(/-/g) || []).length >= 2, 10, "The domain contains multiple hyphens.", "Hyphen usage is normal.");
    add("Encoded characters", check.includes("%"), 5, "The URL contains encoded characters.", "No encoded characters found.");
    add("Dots", (check.match(/\./g) || []).length > 6, 10, "Unusually large number of dots.", "Number of dots is normal.");
    add("Look-alike characters", host.startsWith("xn--") || host.includes(".xn--"), 20,
        "The domain uses punycode that can imitate real sites.", "The domain uses plain characters.");
    const tld = host.split(".").pop();
    add("Top-level domain", ["tk","ml","ga","cf","gq","xyz","top","click","zip","work","loan","icu","buzz"].includes(tld), 8,
        "The ." + tld + " TLD is frequently abused for phishing.", "The TLD is not on the commonly-abused list.");

    score = Math.min(score, 100);
    const lvl = levelFor(score);
    return {
        url, domain: host,
        ip: "Not available in browser-only mode", location: "Not available", organization: "Not available",
        domain_age: "Not available", ssl: parsed.protocol === "https:" ? "Enabled" : "Not enabled",
        score, level: lvl.level, verdict: lvl.verdict, checks
    };
}

function levelFor(score) {
    if (score >= 60) return { level: "High", verdict: "Potentially Phishing", cls: "danger", bg: "danger-bg", icon: "🔴" };
    if (score >= 30) return { level: "Medium", verdict: "Suspicious", cls: "suspicious", bg: "warning-bg", icon: "🟠" };
    return { level: "Low", verdict: "Likely Legitimate", cls: "safe", bg: "safe-bg", icon: "🟢" };
}

// ---- Rendering (textContent only, never innerHTML, so URLs can't inject markup) ----
function displayResult(data) {
    document.getElementById("result").style.display = "block";
    document.getElementById("urlDisplay").textContent = "URL: " + data.url;
    const set = (id, v) => document.getElementById(id).textContent = v || "-";
    set("domain", data.domain); set("ip", data.ip); set("location", data.location);
    set("organization", data.organization); set("domainAge", data.domain_age); set("ssl", data.ssl);

    const score = Number(data.score);
    const lvl = levelFor(score);
    const title = document.getElementById("resultTitle");
    title.textContent = `${lvl.icon} ${lvl.level} Risk – ${lvl.verdict}`;
    title.className = "result-title " + lvl.cls;
    document.getElementById("score").textContent = `Risk Score: ${score}/100`;
    const progress = document.getElementById("progress");
    progress.style.width = score + "%";
    progress.className = lvl.bg;

    const list = document.getElementById("checks");
    list.innerHTML = "";
    (data.checks || []).forEach(c => {
        const li = document.createElement("li");
        if (c.flagged) li.className = "flagged";
        const icon = document.createElement("span"); icon.className = "icon"; icon.textContent = c.flagged ? "⚠️" : "✅";
        const text = document.createElement("span");
        const b = document.createElement("b"); b.textContent = c.label + ":";
        text.append(b, document.createTextNode(c.detail));
        li.append(icon, text);
        if (c.flagged && c.points) {
            const pts = document.createElement("span"); pts.className = "pts"; pts.textContent = "+" + c.points;
            li.append(pts);
        }
        list.appendChild(li);
    });
    document.getElementById("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function showInvalid(message) {
    document.getElementById("result").style.display = "block";
    const t = document.getElementById("resultTitle");
    t.textContent = "⚠️ Invalid URL"; t.className = "result-title invalid";
    document.getElementById("urlDisplay").textContent = message;
    ["domain","ip","location","organization","domainAge","ssl"].forEach(id => document.getElementById(id).textContent = "-");
    document.getElementById("score").textContent = "Risk Score: N/A";
    document.getElementById("progress").style.width = "0%";
    const list = document.getElementById("checks");
    list.innerHTML = "";
    const li = document.createElement("li"); li.textContent = "Please enter a valid website URL, e.g. https://example.com";
    list.appendChild(li);
}

function clearResult() {
    input.value = "";
    document.getElementById("result").style.display = "none";
    input.focus();
}
