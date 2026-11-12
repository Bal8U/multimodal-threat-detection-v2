from pathlib import Path
import joblib
import numpy as np
from .features import url_feature_row

def _load(path):
    try:
        return joblib.load(path) if path.exists() else None
    except Exception:
        return None

def predict_sms_ml(message: str, model_dir: Path) -> dict:
    model = _load(model_dir / "sms_model.joblib")
    if model is None:
        return {"available": False, "message": "ML model not trained yet. Run python -m ml_models.train_models"}
    prediction = int(model.predict([message])[0])
    probability = float(model.predict_proba([message])[0][1])
    return {"available": True, "prediction": "Phishing-like" if prediction else "Non-phishing-like",
            "phishing_probability": round(probability, 3),
            "note": "Demo model trained on synthetic examples; not a real-world verdict."}

def predict_url_ml(url: str, model_dir: Path) -> dict:
    model = _load(model_dir / "url_model.joblib")
    if model is None:
        return {"available": False, "message": "ML model not trained yet. Run python -m ml_models.train_models"}
    prediction = int(model.predict(url_feature_row(url))[0])
    probability = float(model.predict_proba(url_feature_row(url))[0][1])
    return {"available": True, "prediction": "Phishing-like" if prediction else "Non-phishing-like",
            "phishing_probability": round(probability, 3),
            "note": "Demo model trained on synthetic examples; not a real-world verdict."}

def predict_activity_ml(failed: int, rpm: int, ips: int, model_dir: Path) -> dict:
    model = _load(model_dir / "activity_model.joblib")
    if model is None:
        return {"available": False, "message": "ML model not trained yet. Run python -m ml_models.train_models"}
    result = int(model.predict(np.array([[failed, rpm, ips]], dtype=float))[0])
    score = float(model.decision_function(np.array([[failed, rpm, ips]], dtype=float))[0])
    return {"available": True, "prediction": "Anomalous" if result == -1 else "Within learned baseline",
            "anomaly_score": round(score, 4),
            "note": "Demo Isolation Forest trained on synthetic baseline activity."}
