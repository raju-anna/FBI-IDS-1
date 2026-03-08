"""
scan_labels.py
==============
Run this BEFORE any preprocessing.
Points at your raw CIC-IDS 2018 CSV folder and tells you:
  - Every unique label string in your data
  - Row count per label per file
  - The exact column name used for labels
  - All column names (so we can decide what to drop)

Usage:
    python scan_labels.py --path "C:/path/to/your/cicids2018/folder"
    python scan_labels.py --path "/home/user/datasets/cicids2018"
"""

import argparse
import pandas as pd
from pathlib import Path


def scan(folder: str):
    folder_path = Path(folder)

    if not folder_path.exists():
        print(f"❌ Folder not found: {folder_path.resolve()}")
        return

    csv_files = sorted(folder_path.glob("*.csv"))

    if not csv_files:
        print(f"❌ No CSV files found in: {folder_path.resolve()}")
        return

    print(f"\n{'='*65}")
    print(f"  FusionIDS — Label Scanner")
    print(f"  Folder: {folder_path.resolve()}")
    print(f"  Found {len(csv_files)} CSV file(s)")
    print(f"{'='*65}")

    all_labels   = {}   # label_string → total count across all files
    label_col_name = None

    for csv_path in csv_files:
        print(f"\n{'─'*65}")
        print(f"  FILE: {csv_path.name}")
        print(f"{'─'*65}")

        # Read just first row to get column names fast
        try:
            df_head = pd.read_csv(csv_path, nrows=1, low_memory=False)
        except Exception as e:
            print(f"  ❌ Could not read file: {e}")
            continue

        # Strip column name whitespace — CIC-IDS 2018 has leading spaces
        df_head.columns = df_head.columns.str.strip()
        cols = df_head.columns.tolist()

        print(f"\n  Columns ({len(cols)} total):")
        for i, col in enumerate(cols):
            print(f"    [{i:>2}] {col}")

        # Try to detect the label column
        candidate = None
        for col in cols:
            if col.lower() in ("label", "labels", "class", "attack"):
                candidate = col
                break

        if candidate is None:
            print(f"\n  ⚠ Could not auto-detect label column.")
            print(f"  Please check column names above and note which is the label.")
            continue

        print(f"\n  ✓ Label column detected: '{candidate}'")
        label_col_name = candidate

        # Now read full file — only the label column for speed
        try:
            df = pd.read_csv(
                csv_path,
                usecols=[candidate],
                on_bad_lines="skip",
                low_memory=False,
            )
        except Exception as e:
            print(f"  ❌ Could not read label column: {e}")
            continue

        df[candidate] = df[candidate].astype(str).str.strip()
        counts = df[candidate].value_counts().sort_values(ascending=False)

        print(f"\n  Label distribution ({len(df):,} total rows):")
        print(f"  {'Label':<40} {'Count':>10}  {'%':>7}")
        print(f"  {'─'*60}")
        for label, count in counts.items():
            pct = count / len(df) * 100
            print(f"  {label:<40} {count:>10,}  {pct:>6.2f}%")

        for label, count in counts.items():
            all_labels[label] = all_labels.get(label, 0) + count

    # ── Summary across all files ────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  SUMMARY — All Labels Across All Files")
    print(f"{'='*65}")

    if all_labels:
        total_rows = sum(all_labels.values())
        print(f"\n  {'Label':<40} {'Total':>10}  {'%':>7}")
        print(f"  {'─'*60}")
        for label, count in sorted(all_labels.items(), key=lambda x: -x[1]):
            pct = count / total_rows * 100
            print(f"  {label:<40} {count:>10,}  {pct:>6.2f}%")

        print(f"\n  Total rows   : {total_rows:,}")
        print(f"  Total classes: {len(all_labels)}")
        print(f"  Label column : '{label_col_name}'")

        print(f"\n{'='*65}")
        print(f"  ACTION: Share this output so we can build labels.json")
        print(f"  from YOUR actual data — not assumptions.")
        print(f"{'='*65}\n")
    else:
        print("\n  ⚠ No label data collected. Check warnings above.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path",
        required=True,
        help='Path to folder containing CIC-IDS 2018 CSV files'
    )
    args = parser.parse_args()
    scan(args.path)