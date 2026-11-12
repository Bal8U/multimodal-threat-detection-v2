from flask import Flask, render_template, request, jsonify
from pathlib import Path
from url_detector.detector import analyze_url
from sms_detector.detector import analyze_sms
from anomaly_detector.detector import analyze_activity
from ml_models.predict import predict_url_ml, predict_sms_ml, predict_activity_ml

app = Flask(__name__)
MODEL_DIR = Path(__file__).parent / "ml_models" / "artifacts"

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/analyze-url")
def url_api():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400
    heuristic = analyze_url(url)
    ml_result = predict_url_ml(url, MODEL_DIR)
    return jsonify({"heuristic": heuristic, "machine_learning": ml_result})

@app.post("/api/analyze-sms")
def sms_api():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Please enter a message."}), 400
    heuristic = analyze_sms(message)
    ml_result = predict_sms_ml(message, MODEL_DIR)
    return jsonify({"heuristic": heuristic, "machine_learning": ml_result})

@app.post("/api/analyze-anomaly")
def anomaly_api():
    data = request.get_json(silent=True) or {}
    try:
        failed = int(data.get("failed_logins", 0))
        rpm = int(data.get("requests_per_minute", 0))
        ips = int(data.get("unique_ips", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Please enter valid whole numbers."}), 400
    if min(failed, rpm, ips) < 0:
        return jsonify({"error": "Values cannot be negative."}), 400
    heuristic = analyze_activity(failed, rpm, ips)
    ml_result = predict_activity_ml(failed, rpm, ips, MODEL_DIR)
    return jsonify({"heuristic": heuristic, "machine_learning": ml_result})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
