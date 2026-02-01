import json
import joblib
import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest

print("\n=================================================")
print(" ANOMALY IDS v2 — FULL GRID TUNING ")
print("=================================================\n")

# ----------------------------
# Load features
# ----------------------------
with open("config/features_v2.json") as f:
    FEATURES = json.load(f)["features"]

# ----------------------------
# Load data
# ----------------------------
df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

# ----------------------------
# Benign & attack splits
# ----------------------------
benign_df = df[df["Label"] == 0]
attack_df = df[df["Label"] != 0]

X_benign = benign_df[FEATURES].copy()
X_benign = X_benign.fillna(X_benign.median())

X_attack = attack_df[FEATURES].copy()
X_attack = X_attack.fillna(X_attack.median())

print("[INFO] Benign samples :", len(X_benign))
print("[INFO] Attack samples :", len(X_attack))

# ----------------------------
# Benign holdout
# ----------------------------
X_benign_holdout = X_benign.sample(2000, random_state=42)

# ----------------------------
# Weird synthetic OOD flows
# ----------------------------
weird_flows = pd.DataFrame([
    {
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
])

# ----------------------------
# Full parameter grid
# ----------------------------
param_grid = {
    "n_estimators": [200, 400, 600],
    "max_samples": [0.5, 0.7, 0.9, 1.0],
    "contamination": [0.03, 0.05, 0.08, 0.10, 0.15],
    "max_features": [0.5, 0.7, 1.0]
}

results = []

total_tests = (
    len(param_grid["n_estimators"]) *
    len(param_grid["max_samples"]) *
    len(param_grid["contamination"]) *
    len(param_grid["max_features"])
)

print(f"[INFO] Total parameter combinations: {total_tests}\n")

test_id = 1

for n_est in param_grid["n_estimators"]:
    for max_samp in param_grid["max_samples"]:
        for contam in param_grid["contamination"]:
            for max_feat in param_grid["max_features"]:

                print(f"[TEST {test_id}/{total_tests}] "
                      f"n_estimators={n_est}, "
                      f"max_samples={max_samp}, "
                      f"contamination={contam}, "
                      f"max_features={max_feat}")

                model = IsolationForest(
                    n_estimators=n_est,
                    max_samples=max_samp,
                    contamination=contam,
                    max_features=max_feat,
                    random_state=42,
                    n_jobs=-1
                )

                model.fit(X_benign)

                # ----------------------------
                # Metrics
                # ----------------------------
                benign_scores = model.decision_function(X_benign)
                benign_flag_rate = (benign_scores < 0).mean()

                holdout_scores = model.decision_function(X_benign_holdout)
                holdout_flag_rate = (holdout_scores < 0).mean()

                attack_scores = model.decision_function(X_attack)
                attack_flag_rate = (attack_scores < 0).mean()

                weird_scores = model.decision_function(weird_flows[FEATURES])
                weird_flag_rate = (weird_scores < 0).mean()

                results.append({
                    "n_estimators": n_est,
                    "max_samples": max_samp,
                    "contamination": contam,
                    "max_features": max_feat,
                    "benign_flag_rate": benign_flag_rate,
                    "holdout_flag_rate": holdout_flag_rate,
                    "attack_flag_rate": attack_flag_rate,
                    "weird_flag_rate": weird_flag_rate
                })

                print(f"  → benign anomaly rate   : {benign_flag_rate:.4f}")
                print(f"  → holdout anomaly rate  : {holdout_flag_rate:.4f}")
                print(f"  → attack anomaly rate   : {attack_flag_rate:.4f}")
                print(f"  → weird anomaly rate    : {weird_flag_rate:.4f}\n")

                test_id += 1

# ----------------------------
# Compile results
# ----------------------------
results_df = pd.DataFrame(results)

# ----------------------------
# Composite score
# ----------------------------
# Target:
#   benign_flag_rate   → ~0.05–0.10
#   holdout close to benign
#   attack_flag_rate   → high
#   weird_flag_rate    → 1.0

results_df["score"] = (
    (results_df["benign_flag_rate"] - 0.08).abs() * 2.0 +
    (results_df["holdout_flag_rate"] - results_df["benign_flag_rate"]).abs() * 1.5 +
    (1 - results_df["attack_flag_rate"]) * 2.5 +
    (1 - results_df["weird_flag_rate"]) * 3.0
)

results_df = results_df.sort_values("score")

print("\n=================================================")
print(" TOP 10 PARAMETER SETTINGS ")
print("=================================================\n")

print(results_df.head(10)[[
    "n_estimators",
    "max_samples",
    "contamination",
    "max_features",
    "benign_flag_rate",
    "holdout_flag_rate",
    "attack_flag_rate",
    "weird_flag_rate",
    "score"
]])

best = results_df.iloc[0]

print("\n=================================================")
print(" SELECTED BEST CONFIG ")
print("=================================================\n")
print(best)

# ----------------------------
# Retrain final model
# ----------------------------
best_model = IsolationForest(
    n_estimators=int(best["n_estimators"]),
    max_samples=best["max_samples"],
    contamination=best["contamination"],
    max_features=best["max_features"],
    random_state=42,
    n_jobs=-1
)

best_model.fit(X_benign)

joblib.dump(best_model, "models/anomaly_model_v2_tuned.joblib")

print("\n[OK] Saved models/anomaly_model_v2_tuned.joblib")
