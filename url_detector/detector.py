from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_TERMS = (
    "login", "verify", "account", "secure", "update",
    "password", "banking", "wallet", "confirm", "signin"
)

def extract_url_features(value: str) -> dict:
    raw = value.strip()
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0
    return {
        "url_length": len(candidate),
        "hostname_length": len(host),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "at_symbol": int("@" in parsed.netloc),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "digit_count": sum(ch.isdigit() for ch in candidate),
        "suspicious_term_count": sum(term in candidate.lower() for term in SUSPICIOUS_TERMS),
        "path_length": len(parsed.path),
        "subdomain_count": max(0, host.count(".") - 1),
    }

def analyze_url(value: str) -> dict:
    candidate = value.strip()
    if not candidate:
        return {"input": value, "risk_score": 0, "risk_level": "Unable to assess",
                "summary": "Enter a URL.", "reasons": []}
    features = extract_url_features(candidate)
    score, reasons = 0, []
    if not features["uses_https"]:
        score += 1; reasons.append("The address uses HTTP rather than HTTPS.")
    if features["has_ip"]:
        score += 2; reasons.append("The hostname is an IP address.")
    if features["url_length"] > 100:
        score += 1; reasons.append("The URL is unusually long.")
    if features["dot_count"] >= 3:
        score += 1; reasons.append("The hostname contains several subdomains.")
    if features["at_symbol"]:
        score += 2; reasons.append("The address contains an @ symbol in its authority section.")
    if features["suspicious_term_count"]:
        score += min(2, features["suspicious_term_count"])
        reasons.append("Potentially deceptive terms appear in the URL.")
    level = "High" if score >= 4 else "Medium" if score >= 2 else "Low"
    if not reasons: reasons.append("No configured URL heuristics were triggered.")
    return {"input": candidate, "risk_score": score, "risk_level": level,
            "summary": "Heuristic indicators found; this is not a definitive verdict.",
            "reasons": reasons}
