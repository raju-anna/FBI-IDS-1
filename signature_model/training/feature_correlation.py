import pandas as pd
import numpy as np
from sklearn.feature_selection import mutual_info_classif
import os

df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

X = df.drop(columns=["Label"])
y = df["Label"]

# Keep only numeric features
X = X.select_dtypes(include=[np.number])

# Fill NaNs
X = X.fillna(X.median())

print("[INFO] Computing mutual information...")

mi = mutual_info_classif(
    X, y,
    discrete_features=False,
    random_state=42,
    n_jobs=-1
)

mi_scores = pd.Series(mi, index=X.columns)
mi_scores = mi_scores.sort_values(ascending=False)

print("\nTop 30 features by mutual information:\n")
print(mi_scores.head(30))

os.makedirs("analysis", exist_ok=True)
mi_scores.head(40).to_csv("analysis/top_mutual_info.csv")

print("\n[OK] Saved to analysis/top_mutual_info.csv")
