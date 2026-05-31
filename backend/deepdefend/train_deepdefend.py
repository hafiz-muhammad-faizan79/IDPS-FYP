"""
train_deepdefend.py
===================
CyGuardian-X — DeepDefend AI Engine Training

Architecture: CNN + LSTM Hybrid Model
- CNN extracts spatial patterns (port/flag combinations indicating attacks)
- LSTM captures temporal sequences (sustained attack patterns)
- Output: 6-class classification

Trains on 168,004 real network flows from CICIDS2017.
"""

import numpy as np
import os
import time
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.utils.class_weight import compute_class_weight
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Conv1D, MaxPooling1D, LSTM, Dense, Dropout,
    BatchNormalization, GlobalAveragePooling1D, Concatenate
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.utils import to_categorical

# ── Reduce TF logs ────────────────────────────────────────────
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
tf.get_logger().setLevel("ERROR")

# ── Config ────────────────────────────────────────────────────
PROCESSED_DIR = "processed"
MODEL_DIR     = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

NUM_CLASSES = 6
CLASS_NAMES = ["BENIGN", "DDoS", "PortScan", "BruteForce", "WebAttack", "Anomaly"]

EPOCHS     = 30
BATCH_SIZE = 256
LR         = 0.001

# ── Load preprocessed data ────────────────────────────────────
print("[TRAIN] Loading preprocessed data...")
X = np.load(os.path.join(PROCESSED_DIR, "X_scaled.npy"))
y = np.load(os.path.join(PROCESSED_DIR, "y.npy"))
print(f"        X shape: {X.shape}")
print(f"        y shape: {y.shape}")
print(f"        Classes: {np.unique(y)}")

# Reshape for CNN (samples, features, channels=1)
X = X.reshape(X.shape[0], X.shape[1], 1)
print(f"        X reshaped: {X.shape}")

# One-hot encode labels
y_cat = to_categorical(y, NUM_CLASSES)

# ── Train/test split ──────────────────────────────────────────
X_train, X_test, y_train, y_test, y_train_int, y_test_int = train_test_split(
    X, y_cat, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n[TRAIN] Split:")
print(f"        Train: {X_train.shape[0]:,} samples")
print(f"        Test:  {X_test.shape[0]:,} samples")

# ── Class weights (to handle imbalance) ───────────────────────
class_weights_arr = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y_train_int),
    y=y_train_int,
)
class_weights = {i: w for i, w in enumerate(class_weights_arr)}
print(f"\n[TRAIN] Class weights:")
for i, name in enumerate(CLASS_NAMES):
    print(f"        {i} {name:12s}: {class_weights.get(i, 1.0):.3f}")

# ══════════════════════════════════════════════════════════════
# MODEL ARCHITECTURE — CNN + LSTM Hybrid
# ══════════════════════════════════════════════════════════════
def build_model(n_features):
    inputs = Input(shape=(n_features, 1), name="packet_features")

    # ── CNN Branch — spatial pattern extraction ───────────────
    conv = Conv1D(64, 3, activation="relu", padding="same", name="conv1")(inputs)
    conv = BatchNormalization()(conv)
    conv = MaxPooling1D(2)(conv)

    conv = Conv1D(128, 3, activation="relu", padding="same", name="conv2")(conv)
    conv = BatchNormalization()(conv)
    conv = MaxPooling1D(2)(conv)

    conv = Conv1D(64, 3, activation="relu", padding="same", name="conv3")(conv)
    conv = BatchNormalization()(conv)

    # ── LSTM Branch — temporal sequence learning ──────────────
    lstm_out = LSTM(64, return_sequences=True, name="lstm1")(conv)
    lstm_out = Dropout(0.3)(lstm_out)
    lstm_out = LSTM(32, name="lstm2")(lstm_out)
    lstm_out = Dropout(0.3)(lstm_out)

    # ── Dense classifier head ─────────────────────────────────
    dense = Dense(64, activation="relu")(lstm_out)
    dense = Dropout(0.4)(dense)
    dense = Dense(32, activation="relu")(dense)
    outputs = Dense(NUM_CLASSES, activation="softmax", name="threat_class")(dense)

    model = Model(inputs=inputs, outputs=outputs, name="DeepDefend_CNN_LSTM")
    model.compile(
        optimizer=Adam(learning_rate=LR),
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model

print("\n[TRAIN] Building DeepDefend CNN+LSTM model...")
model = build_model(X.shape[1])
model.summary()

# ── Callbacks ─────────────────────────────────────────────────
callbacks = [
    EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True, verbose=1),
    ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3, min_lr=1e-6, verbose=1),
    ModelCheckpoint(
        os.path.join(MODEL_DIR, "deepdefend_best.keras"),
        monitor="val_accuracy", save_best_only=True, verbose=1,
    ),
]

# ── Train ─────────────────────────────────────────────────────
print(f"\n[TRAIN] Starting training — {EPOCHS} epochs, batch size {BATCH_SIZE}...")
print(f"[TRAIN] Estimated time: 10-15 minutes on CPU\n")

start = time.time()
history = model.fit(
    X_train, y_train,
    validation_split=0.1,
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    class_weight=class_weights,
    callbacks=callbacks,
    verbose=1,
)
elapsed = time.time() - start
print(f"\n[TRAIN] Training completed in {elapsed/60:.1f} minutes")

# ── Save final model ──────────────────────────────────────────
model.save(os.path.join(MODEL_DIR, "deepdefend_final.keras"))
print(f"[TRAIN] ✅ Model saved: {MODEL_DIR}/deepdefend_final.keras")

# ── Evaluate ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print("[EVAL] Evaluating on test set...")
print("=" * 60)

y_pred = model.predict(X_test, batch_size=BATCH_SIZE, verbose=0)
y_pred_int = np.argmax(y_pred, axis=1)

acc = accuracy_score(y_test_int, y_pred_int)
f1  = f1_score(y_test_int, y_pred_int, average="weighted")

print(f"\n[EVAL] Overall Accuracy: {acc * 100:.2f}%")
print(f"[EVAL] Weighted F1:      {f1 * 100:.2f}%")

print("\n[EVAL] Per-class report:")
print(classification_report(y_test_int, y_pred_int, target_names=CLASS_NAMES, zero_division=0))

print("[EVAL] Confusion Matrix:")
cm = confusion_matrix(y_test_int, y_pred_int)
print(f"{'':12s}  " + "  ".join([f"{n[:6]:>6s}" for n in CLASS_NAMES]))
for i, name in enumerate(CLASS_NAMES):
    row = "  ".join([f"{cm[i, j]:>6d}" for j in range(NUM_CLASSES)])
    print(f"{name:12s}  {row}")

# ── Save metrics ──────────────────────────────────────────────
metrics = {
    "accuracy":   float(acc),
    "f1_score":   float(f1),
    "training_time_min": elapsed / 60,
    "epochs_trained":    len(history.history["loss"]),
    "total_samples":     int(len(y)),
    "test_samples":      int(len(y_test_int)),
    "class_names":       CLASS_NAMES,
    "confusion_matrix":  cm.tolist(),
}
joblib.dump(metrics, os.path.join(MODEL_DIR, "metrics.pkl"))
print(f"\n[TRAIN] ✅ Metrics saved: {MODEL_DIR}/metrics.pkl")
print(f"[TRAIN] ✅ DeepDefend training complete!")
