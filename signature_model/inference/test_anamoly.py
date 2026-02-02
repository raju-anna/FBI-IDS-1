import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import pandas as pd
from inference.anomaly_predictor import AnomalyDetector

print("\n==============================")
print(" ANOMALY IDS v2 SANITY TEST ")
print("==============================\n")

detector = AnomalyDetector()

df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

with open("config/features_v2.json") as f:
    import json
    FEATURES = json.load(f)["features"]

# ----------------------------
# Test 1: CIC Benign
# ----------------------------
benign = df[df["Label"] == 0].sample(50)

benign_flags = 0
for _, row in benign.iterrows():
    flow = row[FEATURES].to_dict()
    result = detector.detect(flow)
    if result["is_anomalous"]:
        benign_flags += 1

print("Test 1 — CIC Benign")
print("Flagged anomalous:", benign_flags, "/ 50")
print("-" * 50)

# ----------------------------
# Test 2: CIC Attacks
# ----------------------------
attacks = df[df["Label"] != 0].sample(50)

attack_flags = 0
for _, row in attacks.iterrows():
    flow = row[FEATURES].to_dict()
    result = detector.detect(flow)
    if result["is_anomalous"]:
        attack_flags += 1

print("Test 2 — CIC Attacks")
print("Flagged anomalous:", attack_flags, "/ 50")
print("-" * 50)

# ----------------------------
# Test 3: Weird Synthetic Flow
# ----------------------------
weird_flow = {
    "Flow Duration": 99999999,
    "Tot Fwd Pkts": 2,
    "Tot Bwd Pkts": 5000,
    "TotLen Fwd Pkts": 40,
    "TotLen Bwd Pkts": 800000,
    "Flow Byts/s": 1,
    "Flow Pkts/s": 999999,
    "Fwd Pkts/s": 1,
    "Bwd Pkts/s": 999999,
    "Fwd Header Len": 200,
    "Bwd Header Len": 9000,
    "Fwd Seg Size Min": 1,
    "Bwd Seg Size Avg": 2000,
    "Fwd IAT Tot": 99999999,
    "Fwd IAT Mean": 9999999,
    "Fwd IAT Max": 9999999,
    "Fwd IAT Min": 1,
    "Flow IAT Mean": 9999999,
    "Flow IAT Max": 9999999,
    "Flow IAT Min": 1,
    "Init Fwd Win Byts": 65535,
    "Init Bwd Win Byts": 1,
    "Subflow Fwd Pkts": 2,
    "Subflow Bwd Pkts": 5000,
    "Bwd Pkt Len Mean": 1,
    "Bwd Pkt Len Max": 1500,
    "Pkt Len Std": 999,
    "Pkt Len Var": 888888
}

weird_result = detector.detect(weird_flow)

print("Test 3 — Weird Synthetic Flow (OOD)")
print("Expected: Anomalous")
print("Output  :", weird_result)
print("-" * 50)

print("\n[OK] Anomaly IDS v2 tests complete.")
