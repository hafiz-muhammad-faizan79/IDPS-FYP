"""
deepdefend_engine.py
====================
DeepDefend Real-time Inference Engine

Aggregates live packets into flows, extracts 78 CICIDS2017-compatible
features, and predicts threat class via the trained CNN+LSTM model.
"""

import os
import time
import threading
import numpy as np
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional

# Suppress TF logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

# ── Lazy load to avoid startup delay ──────────────────────────
_model      = None
_scaler     = None
_features   = None
_load_lock  = threading.Lock()

from threat_utils import pick_attacker_ip

CLASS_NAMES = ["BENIGN", "DDoS", "PortScan", "BruteForce", "WebAttack", "Anomaly"]
SEVERITY_MAP = {
    "BENIGN":     "Info",
    "DDoS":       "Critical",
    "PortScan":   "Medium",
    "BruteForce": "High",
    "WebAttack":  "High",
    "Anomaly":    "High",
}

MODEL_PATH   = "deepdefend/models/deepdefend_best.keras"
SCALER_PATH  = "deepdefend/processed/scaler.pkl"
FEATURES_PATH= "deepdefend/processed/feature_names.pkl"


def _load_model():
    """Lazy load the Keras model."""
    global _model, _scaler, _features
    with _load_lock:
        if _model is not None:
            return
        try:
            print("[DEEPDEFEND] Loading trained model...")
            import tensorflow as tf
            import joblib
            _model    = tf.keras.models.load_model(MODEL_PATH)
            _scaler   = joblib.load(SCALER_PATH)
            _features = joblib.load(FEATURES_PATH)
            print(f"[DEEPDEFEND] ✅ Model loaded — {len(_features)} features, 6 classes")
        except Exception as e:
            print(f"[DEEPDEFEND] ❌ Model load failed: {e}")


# ══════════════════════════════════════════════════════════════
# FLOW AGGREGATOR
# ══════════════════════════════════════════════════════════════
class Flow:
    """Represents a network flow (sequence of packets between two endpoints)."""
    __slots__ = (
        "src", "dst", "proto", "port", "start_time", "last_time",
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
        "fwd_pkt_lengths", "bwd_pkt_lengths",
        "fwd_iat", "bwd_iat", "last_fwd_time", "last_bwd_time",
        "fin_count", "syn_count", "rst_count", "psh_count",
        "ack_count", "urg_count", "active_times",
    )

    def __init__(self, src, dst, proto, port):
        self.src             = src
        self.dst             = dst
        self.proto           = proto
        self.port            = port
        self.start_time      = time.time()
        self.last_time       = self.start_time
        self.fwd_packets     = 0
        self.bwd_packets     = 0
        self.fwd_bytes       = 0
        self.bwd_bytes       = 0
        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.fwd_iat         = []
        self.bwd_iat         = []
        self.last_fwd_time   = None
        self.last_bwd_time   = None
        self.fin_count       = 0
        self.syn_count       = 0
        self.rst_count       = 0
        self.psh_count       = 0
        self.ack_count       = 0
        self.urg_count       = 0
        self.active_times    = []

    def add_packet(self, src, length, flags, now):
        """Add a packet to this flow."""
        self.last_time = now

        is_forward = src == self.src
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes   += length
            self.fwd_pkt_lengths.append(length)
            if self.last_fwd_time:
                self.fwd_iat.append((now - self.last_fwd_time) * 1_000_000)
            self.last_fwd_time = now
        else:
            self.bwd_packets += 1
            self.bwd_bytes   += length
            self.bwd_pkt_lengths.append(length)
            if self.last_bwd_time:
                self.bwd_iat.append((now - self.last_bwd_time) * 1_000_000)
            self.last_bwd_time = now

        # TCP flags
        if flags is not None:
            if flags & 0x01: self.fin_count += 1   # FIN
            if flags & 0x02: self.syn_count += 1   # SYN
            if flags & 0x04: self.rst_count += 1   # RST
            if flags & 0x08: self.psh_count += 1   # PSH
            if flags & 0x10: self.ack_count += 1   # ACK
            if flags & 0x20: self.urg_count += 1   # URG

    def to_features(self) -> Dict:
        """Convert flow stats to CICIDS2017-style features (78 columns)."""
        duration = max((self.last_time - self.start_time) * 1_000_000, 1)  # microseconds
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes   = self.fwd_bytes + self.bwd_bytes

        fwd_lens = self.fwd_pkt_lengths or [0]
        bwd_lens = self.bwd_pkt_lengths or [0]
        all_lens = fwd_lens + bwd_lens
        fwd_iat  = self.fwd_iat or [0]
        bwd_iat  = self.bwd_iat or [0]

        # Features matching CICIDS2017 column names (78 features)
        return {
            "Destination Port":              self.port,
            "Flow Duration":                 duration,
            "Total Fwd Packets":             self.fwd_packets,
            "Total Backward Packets":        self.bwd_packets,
            "Total Length of Fwd Packets":   self.fwd_bytes,
            "Total Length of Bwd Packets":   self.bwd_bytes,
            "Fwd Packet Length Max":         max(fwd_lens),
            "Fwd Packet Length Min":         min(fwd_lens),
            "Fwd Packet Length Mean":        np.mean(fwd_lens),
            "Fwd Packet Length Std":         np.std(fwd_lens),
            "Bwd Packet Length Max":         max(bwd_lens),
            "Bwd Packet Length Min":         min(bwd_lens),
            "Bwd Packet Length Mean":        np.mean(bwd_lens),
            "Bwd Packet Length Std":         np.std(bwd_lens),
            "Flow Bytes/s":                  total_bytes / (duration / 1_000_000),
            "Flow Packets/s":                total_packets / (duration / 1_000_000),
            "Flow IAT Mean":                 np.mean(fwd_iat + bwd_iat),
            "Flow IAT Std":                  np.std(fwd_iat + bwd_iat),
            "Flow IAT Max":                  max(fwd_iat + bwd_iat),
            "Flow IAT Min":                  min(fwd_iat + bwd_iat),
            "Fwd IAT Total":                 sum(fwd_iat),
            "Fwd IAT Mean":                  np.mean(fwd_iat),
            "Fwd IAT Std":                   np.std(fwd_iat),
            "Fwd IAT Max":                   max(fwd_iat),
            "Fwd IAT Min":                   min(fwd_iat),
            "Bwd IAT Total":                 sum(bwd_iat),
            "Bwd IAT Mean":                  np.mean(bwd_iat),
            "Bwd IAT Std":                   np.std(bwd_iat),
            "Bwd IAT Max":                   max(bwd_iat),
            "Bwd IAT Min":                   min(bwd_iat),
            "Fwd PSH Flags":                 0,
            "Bwd PSH Flags":                 0,
            "Fwd URG Flags":                 0,
            "Bwd URG Flags":                 0,
            "Fwd Header Length":             self.fwd_packets * 20,
            "Bwd Header Length":             self.bwd_packets * 20,
            "Fwd Packets/s":                 self.fwd_packets / (duration / 1_000_000),
            "Bwd Packets/s":                 self.bwd_packets / (duration / 1_000_000),
            "Min Packet Length":             min(all_lens),
            "Max Packet Length":             max(all_lens),
            "Packet Length Mean":            np.mean(all_lens),
            "Packet Length Std":             np.std(all_lens),
            "Packet Length Variance":        np.var(all_lens),
            "FIN Flag Count":                self.fin_count,
            "SYN Flag Count":                self.syn_count,
            "RST Flag Count":                self.rst_count,
            "PSH Flag Count":                self.psh_count,
            "ACK Flag Count":                self.ack_count,
            "URG Flag Count":                self.urg_count,
            "CWE Flag Count":                0,
            "ECE Flag Count":                0,
            "Down/Up Ratio":                 self.bwd_packets / max(self.fwd_packets, 1),
            "Average Packet Size":           total_bytes / max(total_packets, 1),
            "Avg Fwd Segment Size":          self.fwd_bytes / max(self.fwd_packets, 1),
            "Avg Bwd Segment Size":          self.bwd_bytes / max(self.bwd_packets, 1),
            "Fwd Header Length.1":           self.fwd_packets * 20,
            "Fwd Avg Bytes/Bulk":            0,
            "Fwd Avg Packets/Bulk":          0,
            "Fwd Avg Bulk Rate":             0,
            "Bwd Avg Bytes/Bulk":            0,
            "Bwd Avg Packets/Bulk":          0,
            "Bwd Avg Bulk Rate":             0,
            "Subflow Fwd Packets":           self.fwd_packets,
            "Subflow Fwd Bytes":             self.fwd_bytes,
            "Subflow Bwd Packets":           self.bwd_packets,
            "Subflow Bwd Bytes":             self.bwd_bytes,
            "Init_Win_bytes_forward":        65535,
            "Init_Win_bytes_backward":       65535,
            "act_data_pkt_fwd":              self.fwd_packets,
            "min_seg_size_forward":          20,
            "Active Mean":                   duration / max(total_packets, 1),
            "Active Std":                    0,
            "Active Max":                    duration,
            "Active Min":                    0,
            "Idle Mean":                     0,
            "Idle Std":                      0,
            "Idle Max":                      0,
            "Idle Min":                      0,
        }


# ══════════════════════════════════════════════════════════════
# FLOW MANAGER — global state
# ══════════════════════════════════════════════════════════════
class FlowManager:
    def __init__(self, flow_timeout=5.0):
        self.flows: Dict[str, Flow] = {}
        self.lock = threading.Lock()
        self.flow_timeout = flow_timeout
        self.predictions = deque(maxlen=200)  # last 200 predictions for dashboard
        self.stats = defaultdict(int)         # counts per class

    def _flow_key(self, src, dst, proto, port):
        # Bidirectional key — packet from B→A is part of the same flow as A→B
        endpoints = tuple(sorted([(src, port), (dst, port)]))
        return f"{endpoints[0][0]}:{endpoints[1][0]}:{proto}:{port}"

    def add_packet(self, src, dst, proto, port, length, flags):
        key = self._flow_key(src, dst, proto, port)
        with self.lock:
            if key not in self.flows:
                self.flows[key] = Flow(src, dst, proto, port)
            self.flows[key].add_packet(src, length, flags, time.time())

    def get_expired_flows(self) -> List[Flow]:
        """Return flows that haven't seen a packet in flow_timeout seconds."""
        now = time.time()
        expired = []
        with self.lock:
            for key in list(self.flows.keys()):
                flow = self.flows[key]
                if now - flow.last_time > self.flow_timeout:
                    expired.append(flow)
                    del self.flows[key]
        return expired


flow_manager = FlowManager(flow_timeout=5.0)


# ══════════════════════════════════════════════════════════════
# PREDICTION
# ══════════════════════════════════════════════════════════════
def _predict_flow(flow: Flow):
    """Run a single flow through the model."""
    if _model is None:
        return None
    try:
        feats = flow.to_features()

        # Build feature vector in the exact order the scaler expects
        x = np.array([feats.get(name, 0) for name in _features], dtype=np.float32)

        # Replace inf/nan
        x = np.nan_to_num(x, nan=0.0, posinf=1e9, neginf=-1e9)

        # Scale and reshape
        x_scaled = _scaler.transform(x.reshape(1, -1))
        x_input  = x_scaled.reshape(1, -1, 1)

        # Predict
        probs = _model.predict(x_input, verbose=0)[0]
        cls   = int(np.argmax(probs))
        conf  = float(probs[cls])

        return {
            "class":      CLASS_NAMES[cls],
            "class_id":   cls,
            "confidence": round(conf * 100, 2),
            "severity":   SEVERITY_MAP[CLASS_NAMES[cls]],
            "src":        pick_attacker_ip(flow.src, flow.dst),
            "dst":        flow.dst,
            "proto":      flow.proto,
            "port":       flow.port,
            "packets":    flow.fwd_packets + flow.bwd_packets,
            "bytes":      flow.fwd_bytes + flow.bwd_bytes,
            "duration":   round(flow.last_time - flow.start_time, 2),
            "timestamp":  datetime.now().isoformat(),
        }
    except Exception as e:
        print(f"[DEEPDEFEND] Prediction error: {e}")
        return None


def _process_expired_flows():
    """Background thread — predict expired flows."""
    while True:
        try:
            time.sleep(1)
            expired = flow_manager.get_expired_flows()
            for flow in expired:
                # Skip flows with too few packets
                if flow.fwd_packets + flow.bwd_packets < 2:
                    continue
                pred = _predict_flow(flow)
                if pred:
                    flow_manager.predictions.appendleft(pred)
                    flow_manager.stats[pred["class"]] += 1
                    # Hook into correlation engine
                    if pred["class"] != "BENIGN" and pred["confidence"] > 70:
                        _log_threat(pred)
                        try:
                            from correlation_engine import report_deepdefend_prediction
                            report_deepdefend_prediction(pred["src"], pred["class"], pred["confidence"], pred["severity"])
                        except Exception:
                            pass
                    # Log threats to network log/alert tables
                    if pred["class"] != "BENIGN" and pred["confidence"] > 70:
                        _log_threat(pred)
        except Exception as e:
            print(f"[DEEPDEFEND] Worker error: {e}")


def _log_threat(pred: Dict):
    """Save threat detection to PostgreSQL."""
    try:
        from database import SessionLocal
        from models.network import NetworkAlert, NetworkLog
        db = SessionLocal()

        alert = NetworkAlert(
            severity = pred["severity"],
            src_ip   = pred["src"],
            dst_ip   = pred["dst"],
            message  = f"[DEEPDEFEND AI] {pred['class']} ({pred['confidence']}% confidence)",
            protocol = pred["proto"],
            port     = pred["port"],
        )
        db.add(alert)

        log = NetworkLog(
            status  = "FLAGGED",
            src_ip  = pred["src"],
            event   = "AI_DETECTION",
            result  = "WARNING",
            message = f"AI: {pred['class']} on {pred['proto']}:{pred['port']} ({pred['confidence']}%)",
        )
        db.add(log)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[DEEPDEFEND] DB log error: {e}")


# ══════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════
def add_packet(src, dst, proto, port, length, flags=None):
    """Called from network_monitor for every captured packet."""
    flow_manager.add_packet(src, dst, proto, port, length, flags)


def get_recent_predictions(limit=20):
    """Return recent AI predictions for the dashboard."""
    return list(flow_manager.predictions)[:limit]


def get_stats():
    """Return per-class detection counts."""
    return dict(flow_manager.stats)


def start_deepdefend_engine():
    """Start the inference engine — load model + start background worker."""
    if not os.path.exists(MODEL_PATH):
        print(f"[DEEPDEFEND] ⚠️ Model not found at {MODEL_PATH} — engine disabled")
        return False
    _load_model()
    if _model is None:
        return False
    t = threading.Thread(target=_process_expired_flows, daemon=True)
    t.start()
    print("[DEEPDEFEND] ✅ Engine started — analyzing live flows")
    return True
