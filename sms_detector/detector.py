import re

def analyze_sms(message: str) -> dict:
    text = message.strip()
    lower = text.lower()
    score, reasons = 0, []
    groups = [
        (("urgent", "immediately", "within 24 hours", "suspended", "blocked"), "Urgency or account-pressure language"),
        (("password", "otp", "pin", "cvv", "verification code"), "Sensitive credential references"),
        (("winner", "won", "prize", "free gift", "claim"), "Prize or reward language"),
        (("payment", "refund", "bank account", "credit card"), "Payment or financial language"),
    ]
    if re.search(r"https?://|www\.", lower):
        score += 2; reasons.append("The message contains a web link.")
    for terms, label in groups:
        found = [term for term in terms if term in lower]
        if found:
            score += 1; reasons.append(f"{label}: {', '.join(found)}.")
    if re.search(r"\b\d{4,8}\b", text):
        score += 1; reasons.append("A short numeric code appears; never share an OTP.")
    level = "High" if score >= 3 else "Medium" if score >= 1 else "Low"
    if not reasons: reasons.append("No configured SMS heuristics were triggered.")
    return {"risk_score": score, "risk_level": level,
            "summary": "Heuristic indicators found; this is not a definitive verdict.",
            "reasons": reasons}
