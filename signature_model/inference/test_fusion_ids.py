import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import pandas as pd
from inference.fusion_ids import FusionIDS

print("\n==============================")
print(" FUSION IDS v2 — FULL TEST SUITE ")
print("==============================\n")

fusion_ids = FusionIDS()

df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

with open("config/features_v2.json") as f:
    import json
    FEATURES = json.load(f)["features"]

# ==================================================
# PART 1 — SINGLE FLOW TESTS
# ==================================================

print("=== PART 1 — SINGLE FLOW TESTS ===\n")

# ----------------------------
# Test 1: CIC Benign
# ----------------------------
benign = df[df["Label"] == 0].sample(1, random_state=42).iloc[0]
benign_flow = benign[FEATURES].to_dict()

benign_alert = fusion_ids.analyze_flow(benign_flow)

print("Test 1 — CIC Benign Flow")
print("Expected: None")
print("Output  :", benign_alert)
print("-" * 50)

# ----------------------------
# Test 2: CIC Attack
# ----------------------------
attack = df[df["Label"] != 0].sample(1, random_state=42).iloc[0]
attack_flow = attack[FEATURES].to_dict()

attack_alert = fusion_ids.analyze_flow(attack_flow)

print("Test 2 — CIC Attack Flow")
print("True Label:", attack["Label"])
print("Expected : SignatureOnly or Signature+Anomaly")
print("Output   :", attack_alert)
print("-" * 50)

# ----------------------------
# Test 3: Weird Synthetic Flow (OOD)
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

weird_alert = fusion_ids.analyze_flow(weird_flow)

print("Test 3 — Weird Synthetic Flow (OOD)")
print("Expected: AnomalyOnly")
print("Output  :", weird_alert)
print("-" * 50)

# ==================================================
# PART 2 — BATCH FUSION TEST
# ==================================================

print("\n=== PART 2 — BATCH FUSION TEST ===\n")

N_BENIGN = 200
N_ATTACK = 200

benign_df = df[df["Label"] == 0].sample(N_BENIGN, random_state=7)
attack_df = df[df["Label"] != 0].sample(N_ATTACK, random_state=7)

batch_df = pd.concat([benign_df, attack_df]).sample(frac=1, random_state=7)

stats = {
    "benign": {
        "None": 0,
        "SignatureOnly": 0,
        "AnomalyOnly": 0,
        "Signature+Anomaly": 0
    },
    "attack": {
        "None": 0,
        "SignatureOnly": 0,
        "AnomalyOnly": 0,
        "Signature+Anomaly": 0
    }
}

for _, row in batch_df.iterrows():
    flow = row[FEATURES].to_dict()
    true_type = "benign" if row["Label"] == 0 else "attack"

    alert = fusion_ids.analyze_flow(flow)

    if alert is None:
        stats[true_type]["None"] += 1
    else:
        fusion_type = alert.get("fusion", "Unknown")
        if fusion_type not in stats[true_type]:
            fusion_type = "Unknown"
        stats[true_type][fusion_type] += 1

# ----------------------------
# Print batch results
# ----------------------------
print("=== Batch Composition ===")
print(f"Benign : {N_BENIGN}")
print(f"Attack : {N_ATTACK}")
print()

print("=== Fusion IDS Behavior on Benign ===")
for k, v in stats["benign"].items():
    print(f"{k:20s}: {v:4d} / {N_BENIGN}")

print("\n=== Fusion IDS Behavior on Attacks ===")
for k, v in stats["attack"].items():
    print(f"{k:20s}: {v:4d} / {N_ATTACK}")

# ----------------------------
# Derived metrics
# ----------------------------
benign_fp = (
    stats["benign"]["SignatureOnly"]
    + stats["benign"]["AnomalyOnly"]
    + stats["benign"]["Signature+Anomaly"]
)

attack_detected = (
    stats["attack"]["SignatureOnly"]
    + stats["attack"]["AnomalyOnly"]
    + stats["attack"]["Signature+Anomaly"]
)

print("\n=== Derived IDS Metrics ===")
print(f"Benign false positives: {benign_fp} / {N_BENIGN}  ({benign_fp / N_BENIGN:.2%})")
print(f"Attack detection rate : {attack_detected} / {N_ATTACK}  ({attack_detected / N_ATTACK:.2%})")

print("\n[OK] Fusion IDS v2 full test suite complete.")
