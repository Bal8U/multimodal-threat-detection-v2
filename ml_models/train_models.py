"""
Train demonstration ML models using a small illustrative dataset generated here.
This dataset is NOT representative of real-world phishing and is not suitable
for production decisions. Replace it with a licensed, documented dataset.
"""
from pathlib import Path
import random
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import URL_FEATURE_NAMES, url_feature_row
from url_detector.detector import extract_url_features

ROOT = Path(__file__).parent
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)

def train_sms():
    safe = [
        "Your appointment is confirmed for tomorrow at ten.",
        "Thanks for attending the meeting. Notes are attached.",
        "Your order has shipped and will arrive Friday.",
        "Your library book is due next week.",
        "The team meeting starts at 3 pm in room five.",
        "Your monthly statement is now available in the official app.",
        "Reminder: your service visit is scheduled for Monday.",
        "Thank you for your payment. Your receipt is ready."
    ]
    phishing = [
        "URGENT your account is blocked verify password immediately at http://fake-login.test",
        "You won a prize claim your free gift now click this link.",
        "Your bank account suspended confirm your OTP and PIN immediately.",
        "Payment failed update your credit card details at www.fake.test",
        "Verify your account now to avoid suspension password required.",
        "Congratulations winner claim reward within 24 hours at http://reward.test",
        "Your refund is pending provide your bank account and verification code.",
        "Security alert login now and confirm your password and OTP."
    ]
    texts = safe * 20 + phishing * 20
    labels = [0] * (len(safe) * 20) + [1] * (len(phishing) * 20)
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=3000)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])
    model.fit(x_train, y_train)
    print("\nSMS model evaluation on held-out synthetic examples:")
    print(classification_report(y_test, model.predict(x_test), target_names=["non-phishing", "phishing"], zero_division=0))
    joblib.dump(model, ARTIFACTS / "sms_model.joblib")

def train_url():
    safe_domains = [
        "https://www.example.com/about", "https://docs.python.org/3/",
        "https://www.wikipedia.org/wiki/Security", "https://www.mozilla.org/en-US/",
        "https://www.kernel.org/doc/", "https://pandas.pydata.org/docs/",
        "https://www.github.com/features", "https://www.anthropic.com/company"
    ]
    suspicious_domains = [
        "http://192.0.2.10/login/verify", "http://secure-account-login.test/update",
        "http://banking-password-confirm.test/signin", "http://free-prize-claim.test/winner",
        "http://account-verify.test/secure/password", "http://198.51.100.8/confirm",
        "http://login-update.test/verify/account", "http://wallet-security.test/otp"
    ]
    rows, labels = [], []
    for _ in range(35):
        for url in safe_domains:
            rows.append([extract_url_features(url)[k] for k in URL_FEATURE_NAMES]); labels.append(0)
        for url in suspicious_domains:
            rows.append([extract_url_features(url)[k] for k in URL_FEATURE_NAMES]); labels.append(1)
    x_train, x_test, y_train, y_test = train_test_split(
        rows, labels, test_size=0.25, random_state=42, stratify=labels
    )
    model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
    model.fit(x_train, y_train)
    print("\nURL model evaluation on held-out synthetic examples:")
    print(classification_report(y_test, model.predict(x_test), target_names=["non-phishing", "phishing"], zero_division=0))
    joblib.dump(model, ARTIFACTS / "url_model.joblib")

def train_anomaly():
    rng = np.random.default_rng(42)
    # Synthetic baseline activity only; no real user/network logs.
    normal = np.column_stack([
        rng.poisson(1.5, 500),
        rng.normal(35, 12, 500).clip(1),
        rng.poisson(2, 500)
    ])
    model = Pipeline([
        ("scale", StandardScaler()),
        ("detector", IsolationForest(contamination=0.05, random_state=42))
    ])
    model.fit(normal)
    joblib.dump(model, ARTIFACTS / "activity_model.joblib")

if __name__ == "__main__":
    train_sms()
    train_url()
    train_anomaly()
    print(f"\nModels saved to: {ARTIFACTS}")
    print("Reminder: these are educational models trained on synthetic examples.")
