import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

X = df.drop(columns=["Label"])
y = df["Label"]

X = X.select_dtypes(include=[np.number])

X_train, X_val, y_train, y_val = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )

rf.fit(X_train, y_train)

importances = pd.Series(rf.feature_importances_, index=X.columns)
importances = importances.sort_values(ascending=False)

print("\nTop 30 RF Feature Importances:\n")
print(importances.head(30))

importances.head(40).to_csv("analysis/top_rf_importances.csv")
print("\n[OK] Saved to analysis/top_rf_importances.csv")
