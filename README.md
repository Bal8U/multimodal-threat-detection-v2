# Multi-Modal Threat Detection — Complete Project

A local educational cybersecurity prototype combining explainable heuristic checks and three demonstration ML models.

## Modules

1. URL: URL feature extraction + Random Forest classifier.
2. SMS: TF-IDF + Logistic Regression text classifier.
3. Activity: threshold checks + Isolation Forest anomaly detection.

## Setup (Windows PowerShell)

Open this folder in VS Code, then run:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m ml_models.train_models
python app.py
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.

Open http://127.0.0.1:5000 in Chrome.

## Important dataset and model limitations

The training script creates small synthetic, illustrative examples. Its evaluation report is only a software-pipeline demonstration; it is not evidence of real-world phishing accuracy or generalization. Synthetic examples can cause misleadingly high scores. Replace them with a reputable, licensed, representative dataset; split by source/domain/time to prevent leakage; then report precision, recall, F1, confusion matrix, false-positive rate and calibration. Do not use this prototype to make real security decisions.

The application does not contact VirusTotal or any external service. The `.env.example` file is only a placeholder. Do not add API keys or private data to GitHub.

## Suggested next work

- Add unit tests and CI.
- Add an approved public dataset and document its license/provenance.
- Add SQLite audit history with data minimization and retention controls.
- Add optional threat-intelligence integration only after secure API-key handling and user consent.
