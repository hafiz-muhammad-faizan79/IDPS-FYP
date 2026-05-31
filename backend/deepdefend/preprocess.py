"""
preprocess.py
=============
Loads all CICIDS2017 CSV files, combines them, cleans, balances,
and saves a clean training dataset.
"""

import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

DATA_DIR    = "datasets"
OUTPUT_DIR  = "processed"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Map CICIDS2017 labels to our 6 classes ────────────────────
LABEL_MAP = {
    "BENIGN":                              0,
    # DDoS attacks
    "DDoS":                                1,
    "DoS Hulk":                            1,
    "DoS GoldenEye":                       1,
    "DoS slowloris":                       1,
    "DoS Slowhttptest":                    1,
    "Heartbleed":                          1,
    # Port Scan
    "PortScan":                            2,
    # Brute Force
    "FTP-Patator":                         3,
    "SSH-Patator":                         3,
    # Web Attacks
    "Web Attack \x96 Brute Force":         4,
    "Web Attack \x96 XSS":                 4,
    "Web Attack \x96 Sql Injection":       4,
    "Web Attack � Brute Force":        4,
    "Web Attack � XSS":                4,
    "Web Attack � Sql Injection":      4,
    "Web Attack \u00ef\u00bf\u00bd Brute Force":  4,
    "Web Attack \u00ef\u00bf\u00bd XSS":          4,
    "Web Attack \u00ef\u00bf\u00bd Sql Injection":4,
    # Anomaly / Zero-Day
    "Bot":                                 5,
    "Infiltration":                        5,
}

CLASS_NAMES = {0:"BENIGN",1:"DDoS",2:"PortScan",3:"BruteForce",4:"WebAttack",5:"Anomaly"}

# ── Load and combine all CSVs ─────────────────────────────────
print("[PREPROCESS] Loading all CSV files...")
csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
dfs = []
for f in sorted(csv_files):
    print(f"   Loading {f}...")
    df = pd.read_csv(os.path.join(DATA_DIR, f), low_memory=False)
    df.columns = df.columns.str.strip()  # remove whitespace from column names
    dfs.append(df)
combined = pd.concat(dfs, ignore_index=True)
print(f"[PREPROCESS] Combined: {len(combined):,} rows × {len(combined.columns)} columns")

# ── Clean ──────────────────────────────────────────────────────
print("[PREPROCESS] Cleaning data...")
print(f"   Before: {len(combined):,} rows")
combined.replace([np.inf, -np.inf], np.nan, inplace=True)
combined.dropna(inplace=True)
print(f"   After NaN removal: {len(combined):,} rows")

# Map labels
print("[PREPROCESS] Mapping labels...")
print(f"   Unique labels in dataset: {combined['Label'].nunique()}")
print(f"   Sample labels: {combined['Label'].unique()[:10]}")

def smart_label_map(label):
    if pd.isna(label): return None
    s = str(label).strip()
    if s == "BENIGN": return 0
    if s in ("DDoS","DoS Hulk","DoS GoldenEye","DoS slowloris","DoS Slowhttptest","Heartbleed"): return 1
    if s == "PortScan": return 2
    if s in ("FTP-Patator","SSH-Patator"): return 3
    if s.startswith("Web Attack"): return 4   # catches all encoding variants
    if s in ("Bot","Infiltration"): return 5
    return None

print(f"   All unique labels: {list(combined['Label'].unique())}")
combined["label_id"] = combined["Label"].apply(smart_label_map)
combined = combined.dropna(subset=["label_id"])
combined["label_id"] = combined["label_id"].astype(int)
print(f"   After label mapping: {len(combined):,} rows")

# ── Class distribution before balancing ────────────────────────
print("\n[PREPROCESS] Class distribution (before balancing):")
for cls_id, cls_name in CLASS_NAMES.items():
    count = len(combined[combined["label_id"] == cls_id])
    pct   = count / len(combined) * 100 if len(combined) else 0
    print(f"   {cls_id} {cls_name:12s}: {count:>10,} ({pct:5.2f}%)")

# ── Balance classes via undersampling (max 50K per class) ─────
print("\n[PREPROCESS] Balancing classes (max 50,000 per class)...")
MAX_PER_CLASS = 50_000
balanced_dfs = []
for cls_id in CLASS_NAMES:
    subset = combined[combined["label_id"] == cls_id]
    if len(subset) > MAX_PER_CLASS:
        subset = subset.sample(n=MAX_PER_CLASS, random_state=42)
    if len(subset) > 0:
        balanced_dfs.append(subset)
balanced = pd.concat(balanced_dfs, ignore_index=True)
print(f"[PREPROCESS] Balanced dataset: {len(balanced):,} rows")

# ── Drop label string column, keep label_id ───────────────────
balanced = balanced.drop(columns=["Label"])

# ── Save raw balanced dataset ─────────────────────────────────
balanced.to_csv(os.path.join(OUTPUT_DIR, "balanced_dataset.csv"), index=False)
print(f"[PREPROCESS] Saved: {OUTPUT_DIR}/balanced_dataset.csv")

# ── Feature scaling ───────────────────────────────────────────
print("\n[PREPROCESS] Scaling features...")
y = balanced["label_id"].values
X = balanced.drop(columns=["label_id"])

# Keep only numeric columns
X = X.select_dtypes(include=[np.number])
print(f"   Final feature count: {X.shape[1]}")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── Save scaler + processed data ──────────────────────────────
np.save(os.path.join(OUTPUT_DIR, "X_scaled.npy"), X_scaled.astype(np.float32))
np.save(os.path.join(OUTPUT_DIR, "y.npy"), y.astype(np.int32))
joblib.dump(scaler, os.path.join(OUTPUT_DIR, "scaler.pkl"))
joblib.dump(list(X.columns), os.path.join(OUTPUT_DIR, "feature_names.pkl"))

print("\n[PREPROCESS] ✅ Preprocessing complete!")
print(f"   X_scaled.npy:  {X_scaled.shape} ({X_scaled.nbytes/1e6:.1f} MB)")
print(f"   y.npy:         {y.shape}")
print(f"   scaler.pkl:    saved")
print(f"   features:      {X.shape[1]} numeric features")

print("\n[PREPROCESS] Final class distribution:")
for cls_id, cls_name in CLASS_NAMES.items():
    count = (y == cls_id).sum()
    pct   = count / len(y) * 100 if len(y) else 0
    print(f"   {cls_id} {cls_name:12s}: {count:>8,} ({pct:5.2f}%)")
