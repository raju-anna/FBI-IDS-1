import joblib
import pandas as pd
import json
from pathlib import Path

MODEL_PATH = Path("artifacts/anomaly_model_v0.pkl")
FEATURE_PATH = Path("config/features_v1.json")


class AnomalyDetector :

    def __init__(self):
        self.preprocessing, self.model = joblib.load(MODEL_PATH)

        with open(FEATURE_PATH) as f:
            self.features = json.load(f)["features"]

    def detect(self,flow:dict):
        df = pd.DataFrame([flow])[self.features]
        X = self.preprocessing.transform(df)


        score = self.model.decision_function(X)[0]
        is_anamolous = self.model.predict(X)[0] == -1

        return {
            "anomaly_score" : float(score),
            "is_anomalous" : bool(is_anamolous)
        }