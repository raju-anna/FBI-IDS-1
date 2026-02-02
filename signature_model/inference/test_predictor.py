import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import pandas as pd
from inference.predictor import SignatureIDSPredictor

print("\n==============================")
print(" SIGNATURE IDS v2 SANITY TEST ")
print("==============================\n")

sig = SignatureIDSPredictor()

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
benign = df[df["Label"] == 0].sample(1).iloc[0]
benign_flow = benign[FEATURES].to_dict()

benign_result = sig.predict(benign_flow)

print("Test 1 — CIC Benign Flow")
print("Expected: None")
print("Output  :", benign_result)
print("-" * 50)

# ----------------------------
# Test 2: CIC Attack
# ----------------------------
attack = df[df["Label"] != 0].sample(1).iloc[0]
attack_flow = attack[FEATURES].to_dict()

attack_result = sig.predict(attack_flow)

print("Test 2 — CIC Attack Flow")
print("True Label:", attack["Label"])
print("Expected : Signature alert")
print("Output   :", attack_result)
print("-" * 50)

# ----------------------------
# Test 3: Weak Random Flow
# ----------------------------
weak_flow = {f: 0 for f in FEATURES}

weak_result = sig.predict(weak_flow)

print("Test 3 — Weak Zero Flow")
print("Expected: None (low confidence)")
print("Output  :", weak_result)
print("-" * 50)

print("\n[OK] Signature IDS v2 tests complete.")
