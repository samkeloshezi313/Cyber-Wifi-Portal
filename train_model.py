"""Retrain the Random Forest and print its held-out metrics.

    python train_model.py

Replace ml_engine.generate_training_data() with your real, labelled login logs
before relying on the numbers.
"""
import json

from config import Config
from ml_engine import RiskModel

if __name__ == "__main__":
    model = RiskModel(Config.MODEL_PATH, Config.METRICS_PATH)
    model.retrain()
    print(json.dumps(model.metrics, indent=2))
    print(f"\nSaved to {Config.MODEL_PATH}")
