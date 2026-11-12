def analyze_activity(failed_logins: int, requests_per_minute: int, unique_ips: int) -> dict:
    score, reasons = 0, []
    if failed_logins >= 10:
        score += 2; reasons.append("10 or more failed logins were observed.")
    elif failed_logins >= 5:
        score += 1; reasons.append("Several failed logins were observed.")
    if requests_per_minute >= 300:
        score += 2; reasons.append("Request volume is very high (300+ per minute).")
    elif requests_per_minute >= 100:
        score += 1; reasons.append("Request volume is elevated (100+ per minute).")
    if unique_ips >= 20:
        score += 2; reasons.append("Many source IPs were observed (20+).")
    elif unique_ips >= 8:
        score += 1; reasons.append("An elevated number of source IPs was observed (8+).")
    level = "High" if score >= 3 else "Medium" if score >= 1 else "Low"
    if not reasons: reasons.append("No configured activity thresholds were crossed.")
    return {"risk_score": score, "risk_level": level,
            "summary": "Threshold-based demonstration result, not a security verdict.",
            "reasons": reasons}
