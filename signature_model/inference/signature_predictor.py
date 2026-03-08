import json
import joblib
import numpy as np
import pandas as pd


class SignaturePredictor:

    def __init__(
        self,
        model_path="artifacts/xgb_v1.pkl",
        features_path="config/features.json",
        labels_path="config/labels.json"
    ):

        print("[INFO] Loading signature model...")
        self.model = joblib.load(model_path)

        with open(features_path) as f:
            self.features = json.load(f)["features"]

        with open(labels_path) as f:
            label_cfg = json.load(f)

        self.label_names = label_cfg["label_names"]
        self.label_col = label_cfg["label_column"]

    def predict(self, flow):

        df = pd.DataFrame([flow])
        X = df[self.features].values

        probs = self.model.predict_proba(X)[0]
        label_id = int(np.argmax(probs))
        confidence = float(np.max(probs))

        label_info = self.label_names[str(label_id)]

        return {
            "label_id": label_id,
            "label_name": label_info["name"],
            "family": label_info["name"],
            "confidence": confidence
        }