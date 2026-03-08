import pandas as pd
from pathlib import Path

SAMPLED_PATH = "data/processed/sampled.csv"
OUT_PATH = "data/test_fusion.csv"

print("Loading sampled dataset...")
df = pd.read_csv(SAMPLED_PATH)

print("Dataset shape:", df.shape)

label_col = "Label"

# split benign / attacks
benign = df[df[label_col] == 0]
attacks = df[df[label_col] != 0]

print("Benign rows :", len(benign))
print("Attack rows :", len(attacks))

# sample balanced test set
benign_sample = benign.sample(500, random_state=42)
attack_sample = attacks.sample(500, random_state=42)

test_df = pd.concat([benign_sample, attack_sample])

# shuffle
test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)

print("Final test set:", test_df.shape)

Path("data/splits").mkdir(exist_ok=True)

test_df.to_csv(OUT_PATH, index=False)

print(f"[OK] Test dataset saved -> {OUT_PATH}")