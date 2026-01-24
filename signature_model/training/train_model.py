import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import json
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from preprocessing.preprocessing import build_preprocessing_pipeline,sanitize_input

ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)

DATA_PATH = Path("data/cleaned_data_sampled.csv")
FEATURE_PATH = Path("config/features_v1.json")


def load_feature_schema():
    with open(FEATURE_PATH) as f:
        return json.load(f)["features"]
    
def load_data():
    df = pd.read_csv(DATA_PATH,on_bad_lines='skip',low_memory=False)
    print(f"[INFO] Dataset shape: {df.shape}")
    return df

def train():

    df = load_data()

    feature_names = load_feature_schema()

    print("[INFO] Enforcing feature schema...")
    X = df[feature_names]
    y = df["Label"]


    print("[INFO] Train-test split....")
    X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.3,stratify=y,random_state=42)

    preprocessing = build_preprocessing_pipeline()

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )

    pipeline = Pipeline([
        ("preprocess", preprocessing),
        ("classifier", model)
    ])

    print("[INFO] Training model...")
    pipeline.fit(X_train, y_train)

    print("[INFO] Evaluating...")
    y_pred = pipeline.predict(X_test)

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))

    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    model_path = ARTIFACT_DIR / "signature_model_v0.pkl"
    joblib.dump(pipeline, model_path)

    print(f"\n[OK] Model saved to: {model_path}")


if __name__ == "__main__":
    train()
