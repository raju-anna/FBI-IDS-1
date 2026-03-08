"""
preprocessing/step4_feature_selection_and_split.py
====================================================
Final preprocessing step — does everything needed before training:

  Order of operations (intentional — see reasoning in comments):
  1. Load sampled.csv (~1.25M rows, 77 features)
  2. Stratified train / val / test split
  3. SMOTE on train set ONLY (Class 6 WebAttack: 87 -> 5,000)
  4. Feature selection on SMOTE'd train set using:
       - Random Forest importance
       - Mutual Information
       Combined: keep features that score well on EITHER metric
  5. Apply selected features to val and test (drop same columns)
  6. Save data/splits/train.csv, val.csv, test.csv
  7. Save config/features.json (used by all training scripts)

Why this order:
  - Split BEFORE SMOTE: prevents synthetic rows leaking into val/test
  - SMOTE BEFORE feature selection: ensures Class 6 (87 rows) is
    visible to RF probe — otherwise SQL Injection features get ignored
  - Combined RF+MI: RF catches tree-split features, MI catches
    statistical dependencies RF might miss for rare classes

Usage:
    python -m preprocessing.step4_feature_selection_and_split

Input:   data/processed/sampled.csv
Output:  data/splits/train.csv
         data/splits/val.csv
         data/splits/test.csv
         config/features.json
         data/splits/split_report.json
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE
from imblearn.combine import SMOTETomek

# ── Paths ─────────────────────────────────────────────────────────────────────
INPUT_PATH   = Path("data/processed/sampled.csv")
SPLITS_DIR   = Path("data/splits")
REPORT_PATH  = Path("data/splits/split_report.json")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")

SPLITS_DIR.mkdir(parents=True, exist_ok=True)

# ── Config ────────────────────────────────────────────────────────────────────
RANDOM_SEED   = 42
TEST_SIZE     = 0.15      # 15% test
VAL_SIZE      = 0.15      # 15% val (from remaining 85%)

# Conservative SMOTE for WebAttack (87 real samples)
# 1000 synthetic samples — balanced between too few and too many
# 87 -> 1000 is ~11x multiplication, realistic enough to learn from
SMOTE_TARGETS = {
    5: 1_000    # WebAttack: 87 -> 1,000
}

# Feature selection thresholds
# A feature is KEPT if it scores above threshold on RF OR MI
RF_IMPORTANCE_THRESHOLD  = 0.001   # drop features below 0.1% RF importance
MI_THRESHOLD_PERCENTILE  = 10      # drop bottom 10% by MI score

# RF probe config — fast, not the real model
RF_PROBE_ESTIMATORS = 150
RF_PROBE_DEPTH      = 12


def load_label_config():
    with open(LABELS_CFG) as f:
        return json.load(f)


def print_distribution(y, title, label_names):
    counts = pd.Series(y).value_counts().sort_index()
    total  = len(y)
    print(f"\n  {title} ({total:,} samples)")
    print(f"  {'Class':<8} {'Family':<16} {'Count':>10}  {'%':>7}")
    print(f"  {'─'*48}")
    for cls, cnt in counts.items():
        name = label_names[str(cls)]["name"]
        print(f"  {cls:<8} {name:<16} {cnt:>10,}  ({cnt/total*100:.2f}%)")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Load data
# ─────────────────────────────────────────────────────────────────────────────
def load_data(label_col):
    print(f"\n[INFO] Loading {INPUT_PATH}...")
    df = pd.read_csv(INPUT_PATH, low_memory=False)
    print(f"[INFO] Shape: {df.shape}")

    y = df[label_col].values
    X = df.drop(columns=[label_col])

    feature_names = X.columns.tolist()
    print(f"[INFO] Features: {len(feature_names)}")
    return X.values, y, feature_names


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Stratified split
# ─────────────────────────────────────────────────────────────────────────────
def split_data(X, y):
    print(f"\n[INFO] Splitting — test={TEST_SIZE}, val={VAL_SIZE}...")

    # First cut: test set
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y,
        test_size    = TEST_SIZE,
        stratify     = y,
        random_state = RANDOM_SEED,
    )

    # Second cut: val from trainval
    val_size_adj = VAL_SIZE / (1 - TEST_SIZE)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv,
        test_size    = val_size_adj,
        stratify     = y_tv,
        random_state = RANDOM_SEED,
    )

    print(f"  Train : {len(X_train):>10,} rows")
    print(f"  Val   : {len(X_val):>10,} rows")
    print(f"  Test  : {len(X_test):>10,} rows")

    return X_train, X_val, X_test, y_train, y_val, y_test


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Impute NaN then SMOTE on train only
# ─────────────────────────────────────────────────────────────────────────────
def impute_and_smote(X_train, y_train, feature_names, label_names):
    # Impute first — SMOTE cannot handle NaN
    print(f"\n[INFO] Imputing NaN with median...")
    imputer = SimpleImputer(strategy="median")
    X_train = imputer.fit_transform(X_train)

    # Save imputer medians for inference time
    medians = dict(zip(feature_names, imputer.statistics_.tolist()))

    # Check which rare classes are in train
    train_counts = pd.Series(y_train).value_counts()
    smote_needed = {
        cls: target
        for cls, target in SMOTE_TARGETS.items()
        if cls in train_counts.index and train_counts[cls] < target
    }

    if not smote_needed:
        print(f"[INFO] No SMOTE needed — all classes above threshold")
        return X_train, y_train, imputer, medians

    print(f"\n[INFO] Applying SMOTE for rare classes:")
    for cls, target in smote_needed.items():
        name    = label_names[str(cls)]["name"]
        current = train_counts.get(cls, 0)
        print(f"  Class {cls} ({name}): {current} -> {target} samples")

    smote = SMOTE(
        sampling_strategy = smote_needed,
        random_state      = RANDOM_SEED,
        k_neighbors       = min(5, train_counts.get(5, 5) - 1),
    )
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print(f"  After SMOTE — train size: {len(X_train):,}")
    return X_train, y_train, imputer, medians


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Feature selection: RF + Mutual Information
# ─────────────────────────────────────────────────────────────────────────────
def select_features(X_train, y_train, feature_names):
    print(f"\n{'─'*65}")
    print(f"  Feature Selection: RF Importance + Mutual Information")
    print(f"{'─'*65}")

    # ── RF Importance ─────────────────────────────────────────────────────
    print(f"\n[INFO] Running RF importance probe ({RF_PROBE_ESTIMATORS} trees)...")
    rf = RandomForestClassifier(
        n_estimators = RF_PROBE_ESTIMATORS,
        max_depth    = RF_PROBE_DEPTH,
        class_weight = "balanced",
        n_jobs       = -1,
        random_state = RANDOM_SEED,
    )
    rf.fit(X_train, y_train)
    rf_scores = pd.Series(rf.feature_importances_, index=feature_names)

    # ── Mutual Information ────────────────────────────────────────────────
    print(f"[INFO] Computing Mutual Information scores...")
    mi_raw    = mutual_info_classif(
        X_train, y_train,
        discrete_features = False,
        random_state      = RANDOM_SEED,
        n_jobs            = -1,
    )
    mi_scores = pd.Series(mi_raw, index=feature_names)

    # ── Normalize both to [0, 1] for fair comparison ──────────────────────
    rf_norm = rf_scores / rf_scores.max() if rf_scores.max() > 0 else rf_scores
    mi_norm = mi_scores / mi_scores.max() if mi_scores.max() > 0 else mi_scores

    # ── Combined score (average of both) ─────────────────────────────────
    combined = (rf_norm + mi_norm) / 2
    combined = combined.sort_values(ascending=False)

    # ── Selection: keep if above RF threshold OR above MI percentile ──────
    mi_threshold = np.percentile(mi_scores.values, MI_THRESHOLD_PERCENTILE)

    keep_rf = set(rf_scores[rf_scores >= RF_IMPORTANCE_THRESHOLD].index)
    keep_mi = set(mi_scores[mi_scores >= mi_threshold].index)
    selected = sorted(keep_rf | keep_mi, key=lambda f: -combined[f])

    dropped  = [f for f in feature_names if f not in selected]

    print(f"\n  Feature selection results:")
    print(f"  Total features    : {len(feature_names)}")
    print(f"  Kept (RF)         : {len(keep_rf)}")
    print(f"  Kept (MI)         : {len(keep_mi)}")
    print(f"  Final selected    : {len(selected)}  (union of RF + MI)")
    print(f"  Dropped           : {len(dropped)}")

    if dropped:
        print(f"\n  Dropped features:")
        for f in dropped:
            print(f"    - {f:<45} RF={rf_scores[f]:.6f}  MI={mi_scores[f]:.6f}")

    print(f"\n  Top 20 features by combined score:")
    print(f"  {'Feature':<45} {'RF':>8}  {'MI':>8}  {'Combined':>10}")
    print(f"  {'─'*76}")
    for feat in selected[:20]:
        print(f"  {feat:<45} {rf_norm[feat]:>8.4f}  "
              f"{mi_norm[feat]:>8.4f}  {combined[feat]:>10.4f}")

    return selected, dropped, rf_scores, mi_scores, combined


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Save splits and config
# ─────────────────────────────────────────────────────────────────────────────
def save_splits(X_train, X_val, X_test,
                y_train, y_val, y_test,
                selected_features, label_col,
                imputer, medians,
                rf_scores, mi_scores, combined,
                dropped, label_names):

    feat_idx = [i for i, f in enumerate(
        # Need original feature names to index into arrays
        list(range(X_train.shape[1]))
    )]

    # Convert back to DataFrames with selected features only
    # X arrays have ALL features at this point — we need to filter by index
    # selected_features is a list of names, we need their column positions
    # We stored feature_names globally — use combined index
    selected_indices = [list(combined.index).index(f) for f in selected_features]

    def to_df(X, y):
        df = pd.DataFrame(X[:, selected_indices], columns=selected_features)
        df[label_col] = y
        return df

    train_df = to_df(X_train, y_train)
    val_df   = to_df(X_val,   y_val)
    test_df  = to_df(X_test,  y_test)

    train_df.to_csv(SPLITS_DIR / "train.csv", index=False)
    val_df.to_csv(  SPLITS_DIR / "val.csv",   index=False)
    test_df.to_csv( SPLITS_DIR / "test.csv",  index=False)

    print(f"\n[OK] train.csv  -> {len(train_df):>10,} rows  x  {len(selected_features)} features")
    print(f"[OK] val.csv    -> {len(val_df):>10,} rows  x  {len(selected_features)} features")
    print(f"[OK] test.csv   -> {len(test_df):>10,} rows  x  {len(selected_features)} features")

    # ── Save features.json ────────────────────────────────────────────────
    features_cfg = {
        "features":         selected_features,
        "n_features":       len(selected_features),
        "dropped_features": dropped,
        "imputer_medians":  {f: medians[f] for f in selected_features if f in medians},
        "selection_method": "RF_importance + Mutual_Information (union)",
        "rf_importance_threshold": RF_IMPORTANCE_THRESHOLD,
        "mi_threshold_percentile": MI_THRESHOLD_PERCENTILE,
    }
    with open(FEATURES_CFG, "w") as f:
        json.dump(features_cfg, f, indent=2)
    print(f"[OK] features.json -> {FEATURES_CFG}  ({len(selected_features)} features)")

    # ── Save split report ─────────────────────────────────────────────────
    report = {
        "train_rows":       len(train_df),
        "val_rows":         len(val_df),
        "test_rows":        len(test_df),
        "n_features":       len(selected_features),
        "dropped_features": dropped,
        "smote_applied":    SMOTE_TARGETS,
        "train_distribution": train_df[label_col].value_counts().sort_index().to_dict(),
        "val_distribution":   val_df[label_col].value_counts().sort_index().to_dict(),
        "test_distribution":  test_df[label_col].value_counts().sort_index().to_dict(),
        "top_20_features": {
            f: {
                "rf_importance": float(rf_scores[f]),
                "mutual_info":   float(mi_scores[f]),
                "combined":      float(combined[f]),
            }
            for f in selected_features[:20]
        }
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[OK] split_report.json -> {REPORT_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def run():
    label_cfg   = load_label_config()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 4: Feature Selection + Split")
    print(f"{'='*65}")

    # 1. Load
    X, y, feature_names = load_data(label_col)
    print_distribution(y, "Input distribution", label_names)

    # 2. Split
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)
    del X  # free memory

    # Apply imputer to val/test using train fit (before SMOTE changes X_train)
    print(f"\n[INFO] Imputing val and test sets...")
    from sklearn.impute import SimpleImputer
    imputer_for_val_test = SimpleImputer(strategy="median")
    imputer_for_val_test.fit(X_train)  # fit on raw train before SMOTE
    X_val  = imputer_for_val_test.transform(X_val)
    X_test = imputer_for_val_test.transform(X_test)

    # 3. Impute train + SMOTE
    X_train, y_train, imputer, medians = impute_and_smote(
        X_train, y_train, feature_names, label_names
    )
    print_distribution(y_train, "Train after SMOTE", label_names)

    # 4. Feature selection on SMOTE'd train
    selected, dropped, rf_scores, mi_scores, combined = select_features(
        X_train, y_train, feature_names
    )

    # 5. Save everything
    print(f"\n[INFO] Saving splits...")
    save_splits(
        X_train, X_val, X_test,
        y_train, y_val, y_test,
        selected, label_col,
        imputer, medians,
        rf_scores, mi_scores, combined,
        dropped, label_names
    )

    print(f"\n{'='*65}")
    print(f"  ✅  Step 4 complete.")
    print(f"  Next: Phase 2 — run training scripts")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    run()