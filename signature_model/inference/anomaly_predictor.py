import json
import joblib
import pandas as pd
import numpy as np

MODEL_PATH = "artifacts/anomaly_model_v2_tuned.joblib"
FEATURES_PATH = "config/features_v2.json"


class AnomalyDetector:
    def __init__(self):
        with open(FEATURES_PATH) as f:
            self.features = json.load(f)["features"]

        # Load ONLY the model (no preprocessing pipeline)
        self.model = joblib.load(MODEL_PATH)

    def detect(self, flow: dict):
        # Build DataFrame with correct feature order
        df = pd.DataFrame([flow])[self.features]

        # Inline preprocessing (must match training)
        df = df.fillna(df.median())

        # Isolation Forest anomaly score
        score = self.model.decision_function(df)[0]
        is_anomalous = score < 0

        return {
            "anomaly_score": float(score),
            "is_anomalous": bool(is_anomalous)
        }
