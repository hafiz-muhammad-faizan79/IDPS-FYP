"""
generate_dataset.py
===================
Generates a hybrid training dataset for DeepDefend CNN+LSTM model.

Features match CICIDS2017 schema (academically standard).
Attack patterns based on real threat signatures.
Normal traffic based on our live captured packets from PostgreSQL.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("[DATASET] Generating hybrid training dataset...")
print("[DATASET] Feature schema: CICIDS2017 compatible (80 → 20 key features)")

# ── Feature columns (subset of CICIDS2017) ────────────────────
FEATURES = [
    "flow_duration",        # microseconds
    "fwd_packets",          # packets sent forward
    "bwd_packets",          # packets sent backward
    "fwd_bytes",            # bytes forward
    "bwd_bytes",            # bytes backward
    "flow_bytes_per_sec",   # bytes/second
    "flow_pkts_per_sec",    # packets/second
    "fwd_pkt_len_mean",     # mean forward packet length
    "bwd_pkt_len_mean",     # mean backward packet length
    "fwd_iat_mean",         # inter-arrival time forward mean
    "bwd_iat_mean",         # inter-arrival time backward mean
    "fin_flag_count",       # FIN flags
    "syn_flag_count",       # SYN flags
    "rst_flag_count",       # RST flags
    "psh_flag_count",       # PSH flags
    "ack_flag_count",       # ACK flags
    "urg_flag_count",       # URG flags
    "down_up_ratio",        # download/upload ratio
    "avg_pkt_size",         # average packet size
    "active_mean",          # mean time flow was active
]

LABELS = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "BruteForce",
    4: "WebAttack",
    5: "Anomaly",
}

N_SAMPLES = {
    0: 15000,   # BENIGN — most traffic is normal
    1: 5000,    # DDoS
    2: 4000,    # PortScan
    3: 3000,    # BruteForce
    4: 2000,    # WebAttack
    5: 2000,    # Anomaly/ZeroDay
}

rows = []

# ── 0. BENIGN traffic ──────────────────────────────────────────
print("[DATASET] Generating BENIGN samples...")
for _ in range(N_SAMPLES[0]):
    rows.append({
        "flow_duration":       random.randint(100_000, 10_000_000),
        "fwd_packets":         random.randint(2, 50),
        "bwd_packets":         random.randint(2, 50),
        "fwd_bytes":           random.randint(100, 50_000),
        "bwd_bytes":           random.randint(100, 50_000),
        "flow_bytes_per_sec":  random.uniform(100, 5000),
        "flow_pkts_per_sec":   random.uniform(1, 50),
        "fwd_pkt_len_mean":    random.uniform(40, 1200),
        "bwd_pkt_len_mean":    random.uniform(40, 1200),
        "fwd_iat_mean":        random.uniform(1000, 500_000),
        "bwd_iat_mean":        random.uniform(1000, 500_000),
        "fin_flag_count":      random.randint(0, 2),
        "syn_flag_count":      random.randint(0, 2),
        "rst_flag_count":      random.randint(0, 1),
        "psh_flag_count":      random.randint(0, 10),
        "ack_flag_count":      random.randint(1, 30),
        "urg_flag_count":      0,
        "down_up_ratio":       random.uniform(0.5, 2.0),
        "avg_pkt_size":        random.uniform(40, 1200),
        "active_mean":         random.uniform(100, 10_000),
        "label":               0,
    })

# ── 1. DDoS ────────────────────────────────────────────────────
print("[DATASET] Generating DDoS samples...")
for _ in range(N_SAMPLES[1]):
    rows.append({
        "flow_duration":       random.randint(1000, 100_000),       # very short flows
        "fwd_packets":         random.randint(500, 10_000),          # massive packet count
        "bwd_packets":         random.randint(0, 5),                 # little response
        "fwd_bytes":           random.randint(50_000, 5_000_000),
        "bwd_bytes":           random.randint(0, 1000),
        "flow_bytes_per_sec":  random.uniform(100_000, 10_000_000),  # very high
        "flow_pkts_per_sec":   random.uniform(1000, 100_000),        # very high
        "fwd_pkt_len_mean":    random.uniform(40, 100),              # small packets
        "bwd_pkt_len_mean":    random.uniform(0, 50),
        "fwd_iat_mean":        random.uniform(10, 500),              # very fast
        "bwd_iat_mean":        random.uniform(0, 100),
        "fin_flag_count":      0,
        "syn_flag_count":      random.randint(100, 10_000),          # massive SYN
        "rst_flag_count":      random.randint(0, 100),
        "psh_flag_count":      random.randint(0, 50),
        "ack_flag_count":      random.randint(0, 100),
        "urg_flag_count":      random.randint(0, 10),
        "down_up_ratio":       random.uniform(0, 0.1),               # almost no response
        "avg_pkt_size":        random.uniform(40, 100),
        "active_mean":         random.uniform(10, 500),
        "label":               1,
    })

# ── 2. Port Scan ───────────────────────────────────────────────
print("[DATASET] Generating PortScan samples...")
for _ in range(N_SAMPLES[2]):
    rows.append({
        "flow_duration":       random.randint(100, 10_000),          # very short
        "fwd_packets":         random.randint(1, 3),                 # minimal packets
        "bwd_packets":         random.randint(0, 2),
        "fwd_bytes":           random.randint(40, 200),              # tiny
        "bwd_bytes":           random.randint(0, 100),
        "flow_bytes_per_sec":  random.uniform(100, 5000),
        "flow_pkts_per_sec":   random.uniform(10, 500),
        "fwd_pkt_len_mean":    random.uniform(40, 80),               # small SYN packets
        "bwd_pkt_len_mean":    random.uniform(0, 60),
        "fwd_iat_mean":        random.uniform(100, 5000),
        "bwd_iat_mean":        random.uniform(0, 1000),
        "fin_flag_count":      0,
        "syn_flag_count":      random.randint(1, 3),                 # SYN probe
        "rst_flag_count":      random.randint(0, 2),
        "psh_flag_count":      0,
        "ack_flag_count":      random.randint(0, 2),
        "urg_flag_count":      0,
        "down_up_ratio":       random.uniform(0, 0.5),
        "avg_pkt_size":        random.uniform(40, 80),
        "active_mean":         random.uniform(10, 1000),
        "label":               2,
    })

# ── 3. Brute Force ─────────────────────────────────────────────
print("[DATASET] Generating BruteForce samples...")
for _ in range(N_SAMPLES[3]):
    rows.append({
        "flow_duration":       random.randint(500_000, 30_000_000),  # sustained
        "fwd_packets":         random.randint(50, 2000),
        "bwd_packets":         random.randint(50, 2000),
        "fwd_bytes":           random.randint(5000, 500_000),
        "bwd_bytes":           random.randint(5000, 500_000),
        "flow_bytes_per_sec":  random.uniform(500, 50_000),
        "flow_pkts_per_sec":   random.uniform(10, 500),
        "fwd_pkt_len_mean":    random.uniform(50, 300),
        "bwd_pkt_len_mean":    random.uniform(50, 300),
        "fwd_iat_mean":        random.uniform(5000, 100_000),
        "bwd_iat_mean":        random.uniform(5000, 100_000),
        "fin_flag_count":      random.randint(0, 5),
        "syn_flag_count":      random.randint(10, 500),              # repeated SYN
        "rst_flag_count":      random.randint(5, 200),               # many resets
        "psh_flag_count":      random.randint(10, 200),
        "ack_flag_count":      random.randint(50, 2000),
        "urg_flag_count":      0,
        "down_up_ratio":       random.uniform(0.8, 1.2),             # symmetric
        "avg_pkt_size":        random.uniform(50, 300),
        "active_mean":         random.uniform(1000, 50_000),
        "label":               3,
    })

# ── 4. Web Attack ──────────────────────────────────────────────
print("[DATASET] Generating WebAttack samples...")
for _ in range(N_SAMPLES[4]):
    rows.append({
        "flow_duration":       random.randint(50_000, 5_000_000),
        "fwd_packets":         random.randint(5, 100),
        "bwd_packets":         random.randint(3, 80),
        "fwd_bytes":           random.randint(500, 100_000),         # large payloads
        "bwd_bytes":           random.randint(500, 200_000),
        "flow_bytes_per_sec":  random.uniform(1000, 100_000),
        "flow_pkts_per_sec":   random.uniform(5, 200),
        "fwd_pkt_len_mean":    random.uniform(200, 1400),            # large packets
        "bwd_pkt_len_mean":    random.uniform(200, 1400),
        "fwd_iat_mean":        random.uniform(10_000, 1_000_000),
        "bwd_iat_mean":        random.uniform(10_000, 1_000_000),
        "fin_flag_count":      random.randint(0, 3),
        "syn_flag_count":      random.randint(1, 5),
        "rst_flag_count":      random.randint(0, 3),
        "psh_flag_count":      random.randint(5, 50),                # lots of PSH
        "ack_flag_count":      random.randint(5, 100),
        "urg_flag_count":      random.randint(0, 2),
        "down_up_ratio":       random.uniform(1.0, 5.0),             # large responses
        "avg_pkt_size":        random.uniform(300, 1400),
        "active_mean":         random.uniform(5000, 200_000),
        "label":               4,
    })

# ── 5. Anomaly / Zero-Day ──────────────────────────────────────
print("[DATASET] Generating Anomaly/Zero-Day samples...")
for _ in range(N_SAMPLES[5]):
    # Random unusual combinations that don't fit normal patterns
    rows.append({
        "flow_duration":       random.randint(1, 1_000_000_000),
        "fwd_packets":         random.randint(0, 50_000),
        "bwd_packets":         random.randint(0, 50_000),
        "fwd_bytes":           random.randint(0, 10_000_000),
        "bwd_bytes":           random.randint(0, 10_000_000),
        "flow_bytes_per_sec":  random.uniform(0, 50_000_000),
        "flow_pkts_per_sec":   random.uniform(0, 500_000),
        "fwd_pkt_len_mean":    random.uniform(0, 1500),
        "bwd_pkt_len_mean":    random.uniform(0, 1500),
        "fwd_iat_mean":        random.uniform(0, 10_000_000),
        "bwd_iat_mean":        random.uniform(0, 10_000_000),
        "fin_flag_count":      random.randint(0, 1000),
        "syn_flag_count":      random.randint(0, 1000),
        "rst_flag_count":      random.randint(0, 1000),
        "psh_flag_count":      random.randint(0, 1000),
        "ack_flag_count":      random.randint(0, 1000),
        "urg_flag_count":      random.randint(0, 100),
        "down_up_ratio":       random.uniform(0, 100),
        "avg_pkt_size":        random.uniform(0, 1500),
        "active_mean":         random.uniform(0, 1_000_000),
        "label":               5,
    })

# ── Add real captured packets from PostgreSQL ──────────────────
print("[DATASET] Loading real captured packets from PostgreSQL...")
try:
    from database import SessionLocal
    from models.network import CapturedPacket
    db = SessionLocal()
    packets = db.query(CapturedPacket).limit(5000).all()
    db.close()
    real_count = 0
    for p in packets:
        rows.append({
            "flow_duration":       100_000,
            "fwd_packets":         1,
            "bwd_packets":         1,
            "fwd_bytes":           p.length,
            "bwd_bytes":           p.length,
            "flow_bytes_per_sec":  p.length * 10,
            "flow_pkts_per_sec":   10,
            "fwd_pkt_len_mean":    p.length,
            "bwd_pkt_len_mean":    p.length,
            "fwd_iat_mean":        100_000,
            "bwd_iat_mean":        100_000,
            "fin_flag_count":      0,
            "syn_flag_count":      1 if p.port in [22, 3389] else 0,
            "rst_flag_count":      0,
            "psh_flag_count":      1,
            "ack_flag_count":      1,
            "urg_flag_count":      0,
            "down_up_ratio":       1.0,
            "avg_pkt_size":        p.length,
            "active_mean":         10_000,
            "label":               1 if p.flagged else 0,
        })
        real_count += 1
    print(f"[DATASET] Added {real_count} real packets from PostgreSQL")
except Exception as e:
    print(f"[DATASET] Could not load real packets: {e}")

# ── Build DataFrame ────────────────────────────────────────────
df = pd.DataFrame(rows)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

# Save
os.makedirs("datasets", exist_ok=True)
df.to_csv("datasets/cyguardian_training_data.csv", index=False)

print(f"\n[DATASET] ✅ Dataset generated successfully!")
print(f"[DATASET] Total samples: {len(df):,}")
print(f"[DATASET] Label distribution:")
for label_id, label_name in LABELS.items():
    count = len(df[df["label"] == label_id])
    pct   = count / len(df) * 100
    print(f"          {label_id} {label_name:12s}: {count:6,} ({pct:.1f}%)")
print(f"[DATASET] Saved to: datasets/cyguardian_training_data.csv")
