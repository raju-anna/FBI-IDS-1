import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

MODEL_PATH = Path("artifacts/signature_model_v0.pkl")
FEATURE_PATH = Path("config/features_v1.json")

pipeline = joblib.load(MODEL_PATH)

with open(FEATURE_PATH) as f:
    feature_names = json.load(f)["features"]

df = pd.read_csv("data/cleaned_data_sampled.csv", on_bad_lines="skip", low_memory=False)

# Enforce schema
X = df[feature_names]

probs = pipeline.predict_proba(X)

print("\n=== ALERT VOLUME VS THRESHOLD ===")
for threshold in [0.7, 0.8, 0.85, 0.9, 0.95]:
    confident = np.max(probs, axis=1) >= threshold
    print(f"Threshold {threshold}: Alerts = {confident.sum()} / {len(confident)}")
