import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import pandas as pd
import numpy as np
from inference.anomaly_predictor import AnomalyDetector

detector = AnomalyDetector()

df = pd.read_csv("data/cleaned_data_sampled.csv", on_bad_lines="skip", low_memory=False)

feature_cols = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Size Avg"
]

# ---- Test 1: CIC Benign ----
benign = df[df["Label"] == 0].sample(50)

benign_results = []
for _, row in benign.iterrows():
    flow = row[feature_cols].to_dict()
    result = detector.detect(flow)
    benign_results.append(result["is_anomalous"])

print("CIC Benign flagged anomalous:", sum(benign_results), "/", len(benign_results))


# ---- Test 2: CIC Attacks ----
attacks = df[df["Label"] != 0].sample(50)

attack_results = []
for _, row in attacks.iterrows():
    flow = row[feature_cols].to_dict()
    result = detector.detect(flow)
    attack_results.append(result["is_anomalous"])

print("CIC Attacks flagged anomalous:", sum(attack_results), "/", len(attack_results))


# ---- Test 3: Weird synthetic flow ----
weird_flow = {
    "Flow Duration": 99999999,
    "Tot Fwd Pkts": 2,
    "Tot Bwd Pkts": 5000,
    "Flow Byts/s": 1,
    "Flow Pkts/s": 999999,
    "Fwd Pkt Len Mean": 9999,
    "Bwd Pkt Len Mean": 1,
    "Pkt Len Std": 999,
    "Pkt Size Avg": 888,
}

weird_result = detector.detect(weird_flow)
print("Weird flow anomalous?:", weird_result)


print("\n[OK] Anomaly detector basic tests complete.")
