import joblib
import json
import pandas as pd

MODEL_PATH = "artifacts/anomaly_model_v2_tuned.joblib"
FEATURES_PATH = "config/features_v2.json"
class AnomalyPredictor:

    def __init__(self):

        # bundle = joblib.load(r"artifacts\iforest_v1.pkl")

        # self.model = bundle["model"]
        # self.features = bundle["features"]
        # self.medians = bundle["medians"]

        with open(FEATURES_PATH) as f:
            self.features = json.load(f)["features"]

        # Load ONLY the model (no preprocessing pipeline)
        self.model = joblib.load(MODEL_PATH)

    def predict(self, flow):

        df = pd.DataFrame([flow])[self.features]

        # apply same preprocessing as training
        # for col in df.columns:
        #     df[col] = df[col].fillna(self.medians.get(col, 0))

        df = df.fillna(df.median())

        score = float(self.model.score_samples(df.values)[0])

        return {
            "anomaly_score": score
        }