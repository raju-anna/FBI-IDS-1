import json
import joblib
import pandas as pd
import numpy as np

from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import f1_score, make_scorer

print("\n======================================")
print(" SIGNATURE IDS v2 — GRIDSEARCH TUNING ")
print("======================================\n")

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

X = df[FEATURES]
y = df["Label"]

# ----------------------------
# Train/Validation split
# ----------------------------
X_train, X_val, y_train, y_val = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# ----------------------------
# Pipeline
# ----------------------------
pipe = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("clf", RandomForestClassifier(
        random_state=42,
        n_jobs=-1
    ))
])

# ----------------------------
# Parameter grid
# ----------------------------
param_grid = {
    "clf__n_estimators": [300, 500, 800],
    "clf__max_depth": [15, 25, 35, None],
    "clf__min_samples_leaf": [1, 3, 5, 10],
    "clf__max_features": ["sqrt", 0.5, 0.8],
    "clf__class_weight": ["balanced"]
}

scorer = make_scorer(f1_score, average="macro")

gs = GridSearchCV(
    pipe,
    param_grid,
    scoring=scorer,
    cv=3,
    verbose=2,
    n_jobs=-1
)

# ----------------------------
# Run GridSearch
# ----------------------------
print("[INFO] Starting GridSearchCV...")
gs.fit(X_train, y_train)

print("\n==============================")
print(" BEST GRIDSEARCH RESULT ")
print("==============================")
print("Best params:\n", gs.best_params_)
print("Best CV F1:", gs.best_score_)

# ----------------------------
# Validate best model
# ----------------------------
best_model = gs.best_estimator_

y_val_pred = best_model.predict(X_val)
val_f1 = f1_score(y_val, y_val_pred, average="macro")

print("\n==============================")
print(" VALIDATION PERFORMANCE ")
print("==============================")
print("Validation F1 (macro):", val_f1)

# ----------------------------
# Benign confidence probe
# ----------------------------
probs = best_model.predict_proba(X_val)
max_conf = probs.max(axis=1)

benign_mask = (y_val == 0).values
benign_conf = max_conf[benign_mask]

print("\n==============================")
print(" BENIGN CONFIDENCE PROFILE ")
print("==============================")
print("Mean benign max confidence :", np.mean(benign_conf))
print("95th percentile benign conf:", np.percentile(benign_conf, 95))
print("99th percentile benign conf:", np.percentile(benign_conf, 99))

# ----------------------------
# Save model
# ----------------------------
joblib.dump(best_model, "artifacts/signature_pipeline_v2_tuned.joblib")
print("\n[OK] Saved artifacts/signature_pipeline_v2_tuned.joblib")
