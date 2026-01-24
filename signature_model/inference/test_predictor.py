import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import pandas as pd
from inference.predictor import SignatureIDSPredictor

# Load one sample from dataset
df = pd.read_csv("data/cleaned_data_sampled.csv", on_bad_lines="skip", low_memory=False)
sample = df.iloc[0]

flow = {
    "Flow Duration" : 900000,
    "Tot Fwd Pkts": 310,
    "Tot Bwd Pkts": 295,
    "Flow Byts/s" : 155000,
    "Flow Pkts/s" : 670,
    "Fwd Pkt Len Mean" :  85,
    "Bwd Pkt Len Mean" : 90,
    "Pkt Len Std" : 22,
    "Pkt Size Avg" : 88
}

predictor = SignatureIDSPredictor()
alert = predictor.predict(flow)

print(alert)
