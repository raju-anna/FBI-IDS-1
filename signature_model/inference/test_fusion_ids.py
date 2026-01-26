import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import pandas as pd
from inference.fusion_ids import FusionIDS

# ----------------------------
# Load Fusion IDS
# ----------------------------
fusion_ids = FusionIDS()

# ----------------------------
# Load CIC dataset
# ----------------------------
df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

feature_cols = [
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkt Len Mean",
    "Bwd Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Size Avg",
]

print("\n==============================")
print(" FUSION IDS SANITY TEST ")
print("==============================\n")

# ----------------------------
# Test 1: CIC Benign Sample
# ----------------------------
benign_sample = df[df["Label"] == 0].sample(1).iloc[0]
benign_flow = benign_sample[feature_cols].to_dict()

benign_alert = fusion_ids.analyze_flow(benign_flow)

print("Test 1 — CIC Benign Flow")
print("Expected: None")
print("Output  :", benign_alert)
print("-" * 50)


# ----------------------------
# Test 2: CIC Attack Sample
# ----------------------------
attack_sample = df[df["Label"] != 0].sample(1).iloc[0]
attack_flow = attack_sample[feature_cols].to_dict()

attack_alert = fusion_ids.analyze_flow(attack_flow)

print("Test 2 — CIC Attack Flow")
print("True Label:", attack_sample["Label"])
print("Expected : Signature+Anomaly or SignatureOnly")
print("Output   :", attack_alert)
print("-" * 50)


# ----------------------------
# Test 3: Weird Synthetic Flow (OOD)
# ----------------------------
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
    "Subflow Fwd Pkts": 2,
    "Subflow Bwd Pkts": 5000
}

weird_alert = fusion_ids.analyze_flow(weird_flow)

print("Test 3 — Weird Synthetic Flow (OOD)")
print("Expected: AnomalyOnly alert")
print("Output  :", weird_alert)
print("-" * 50)


# ----------------------------
# Test 4: Batch Test (Stats)
# ----------------------------
print("\nTest 4 — Batch Fusion Behavior on CIC Samples\n")

sample_df = df.sample(100)

sig_only = 0
anom_only = 0
both = 0
none = 0

for _, row in sample_df.iterrows():
    flow = row[feature_cols].to_dict()
    alert = fusion_ids.analyze_flow(flow)

    if alert is None:
        none += 1
    elif alert.get("fusion") == "SignatureOnly":
        sig_only += 1
    elif alert.get("fusion") == "AnomalyOnly":
        anom_only += 1
    elif alert.get("fusion") == "Signature+Anomaly":
        both += 1

print("Out of 100 random CIC flows:")
print("  None                :", none)
print("  SignatureOnly       :", sig_only)
print("  AnomalyOnly         :", anom_only)
print("  Signature+Anomaly   :", both)

print("\n[OK] Fusion IDS tests complete.")
