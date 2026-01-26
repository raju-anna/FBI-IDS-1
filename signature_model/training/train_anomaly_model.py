import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))


import json
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

from preprocessing.preprocessing import build_preprocessing_pipeline, sanitize_input

ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)

DATA_PATH = Path("data/cleaned_data_sampled.csv")
FEATURE_PATH = Path("config/features_v1.json")

def load_feature_schema():
    with open(FEATURE_PATH) as f:
        return json.load(f)["features"]
    
def train_anomaly_model():
    print("[INFO] Loading Dataset")
    df = pd.read_csv(DATA_PATH,on_bad_lines='skip',low_memory=False)

    feature_names = load_feature_schema()

    benign_df = df[df["Label"] == 0]
    print(f"[INFO] Using {len(benign_df)} benign samples for anomaly training")

    X = benign_df[feature_names]
    X = sanitize_input(X)

    print("[INFO] Fitting preprocesing")
    
    preprocessing = build_preprocessing_pipeline()
    X_processed = preprocessing.fit_transform(X)

    print("[INFO] Training Isolation Forest....")
    model = IsolationForest(
        n_estimators=300,
        max_samples=0.8,
        contamination=0.15,
        random_state = 42,
        n_jobs=-1
    )

    model.fit(X_processed)

    joblib.dump((preprocessing, model), ARTIFACT_DIR / "anomaly_model_v0.pkl")
    print("[OK] Anomaly model saved")

if __name__ == "__main__":
    train_anomaly_model()
