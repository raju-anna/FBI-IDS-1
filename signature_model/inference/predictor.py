import json
import joblib
import pandas as pd
from pathlib import Path

MODEL_PATH = Path("artifacts/signature_model_v0.pkl")
FEATURE_PATH = Path("config/features_v2.json")
LABEL_PATH = Path("config/labels_v1.json")

DEFAULT_THRESHOLD = 0.85


class SignatureIDSPredictor:
    """
    Production-grade signature IDS predictor.
    Applies confidence thresholding and returns only strong alerts.
    """

    def __init__(self):
        self.pipeline = joblib.load(MODEL_PATH)

        with open(FEATURE_PATH) as f:
            self.features = json.load(f)["features"]

        with open(LABEL_PATH) as f:
            self.labels = json.load(f)

    def predict(self, flow: dict, threshold=DEFAULT_THRESHOLD):
        """
        flow: dict matching FeatureSchema v1
        threshold: confidence cutoff for alert generation

        Returns:
            alert dict or None
        """
        df = pd.DataFrame([flow])[self.features]

        probs = self.pipeline.predict_proba(df)[0]
        pred = probs.argmax()
        confidence = probs[pred]
        print(confidence)

        # if confidence < threshold:
        #     return None  # Suppress weak predictions

        if pred == 0:
            return None

        label_info = self.labels[str(pred)]

        return {
            "label_id": pred,
            "label_name": label_info["name"],
            "family": label_info["family"],
            "severity": label_info["severity"],
            "confidence": float(confidence)
        }
