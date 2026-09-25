"""Random Forest risk engine.

The model answers one question: "how likely is this login to be suspicious?"
It returns P(suspicious) in [0, 1]; the portal turns that into allow / step-up / block.

IMPORTANT: there is no public dataset of your users' login behaviour, so the
initial model is bootstrapped from generated behavioural profiles. Retrain on
real, labelled logs before making claims about operational accuracy.
"""
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

FEATURES = [
    "time_rarity",       # 0..1  how unusual this hour is for this user (login time frequency)
    "failed_attempts",   # count of failed logins in the recent window
    "device_trust",      # 0..1  0.5 for a freshly registered device, rising with successful use
    "location_anomaly",  # 0 = usual network, 1 = new network, 0.3 = not enough history
    "login_velocity",    # logins by this user in the last 10 minutes (incl. this one)
]

FEATURE_LABELS = {
    "time_rarity": "Login time frequency",
    "failed_attempts": "Failed login count",
    "device_trust": "Device trust score",
    "location_anomaly": "Location anomaly",
    "login_velocity": "Login velocity",
}


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def generate_training_data(n: int = 20000, seed: int = 42):
    """Synthetic login population with *graded* risk.

    Features are drawn from a broad population (mostly ordinary logins, a minority of
    night owls, typo bursts, new networks, freshly registered devices). The label is
    then drawn from a noisy risk score, so:
      - one odd signal on its own (e.g. a 3 a.m. login) is only moderately risky,
      - several signals together (odd hour + new network + failed attempts) are very risky,
      - the classes overlap, as they would in real logs.
    The weights below are assumptions, not measurements. Replace this
    function with real labelled logs when you have them.
    """
    rng = np.random.default_rng(seed)
    odd_hour = rng.random(n) < 0.15
    time_rarity = np.where(odd_hour, rng.beta(6, 2, n), rng.beta(2, 7, n))
    failed = np.minimum(rng.poisson(0.5, n) + np.where(rng.random(n) < 0.05, rng.poisson(4, n), 0), 8)
    device_trust = np.clip(rng.beta(4, 2, n) * 0.5 + 0.5, 0.5, 1.0)
    location = rng.choice([0.0, 0.3, 1.0], n, p=[0.85, 0.05, 0.10])
    velocity = 1 + np.minimum(rng.poisson(0.5, n) + np.where(rng.random(n) < 0.05, 3, 0), 8)

    z = (-4.6 + 4.2 * time_rarity + 0.7 * failed + 1.6 * (1 - device_trust)
         + 1.5 * location + 0.35 * (velocity - 1) + rng.normal(0, 0.6, n))
    y = (rng.random(n) < _sigmoid(z)).astype(int)
    X = np.column_stack([time_rarity, failed, device_trust, location, velocity]).astype(float)
    return X, y


def train(n_samples: int = 20000, seed: int = 42, threshold: float = 0.40):
    X, y = generate_training_data(n_samples, seed)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=8,
        min_samples_leaf=15,     # larger leaves give smoother, better-calibrated probabilities
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_tr, y_tr)

    proba = model.predict_proba(X_te)[:, 1]
    pred = (proba >= threshold).astype(int)      # judged at the portal's step-up threshold
    metrics = {
        "algorithm": "RandomForestClassifier (scikit-learn)",
        "trained_on": "generated behavioural baseline",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn": sklearn.__version__,
        "threshold": threshold,
        "positive_rate": round(float(y.mean()), 4),
        "n_train": int(len(y_tr)),
        "n_test": int(len(y_te)),
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision": round(float(precision_score(y_te, pred)), 4),
        "recall": round(float(recall_score(y_te, pred)), 4),
        "f1": round(float(f1_score(y_te, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
        "importances": {f: round(float(v), 4) for f, v in zip(FEATURES, model.feature_importances_)},
    }
    return model, metrics


class RiskModel:
    """Loads the saved Random Forest, or trains one on first run."""

    def __init__(self, model_path: str, metrics_path: str):
        self.model_path = Path(model_path)
        self.metrics_path = Path(metrics_path)
        self._lock = threading.Lock()
        self.model = None
        self.metrics = {}
        if self.model_path.exists() and self.metrics_path.exists():
            self.metrics = json.loads(self.metrics_path.read_text())
            if self.metrics.get("sklearn") == sklearn.__version__:
                self.model = joblib.load(self.model_path)
        if self.model is None:
            self.retrain()

    def retrain(self):
        with self._lock:
            self.model, self.metrics = train()
            joblib.dump(self.model, self.model_path)
            self.metrics_path.write_text(json.dumps(self.metrics, indent=2))

    def predict_risk(self, feats: dict) -> float:
        x = np.array([[float(feats[f]) for f in FEATURES]])
        return float(self.model.predict_proba(x)[0][list(self.model.classes_).index(1)])
