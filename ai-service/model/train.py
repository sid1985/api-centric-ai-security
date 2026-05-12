"""
Train a sklearn RandomForest classifier on the synthetic traffic data.
Saves model to model/classifier.joblib for use by the inference service.
"""
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from synthetic_data import generate_dataset

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "classifier.joblib")
ENCODER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "label_encoder.joblib")

FEATURE_COLS = ["request_size_kb", "response_time_ms", "anomaly_score", "cpu_load_pct"]
TARGET_COL   = "traffic_type"


def train():
    print("Generating synthetic dataset...")
    df = generate_dataset()

    X = df[FEATURE_COLS].values
    le = LabelEncoder()
    y = le.fit_transform(df[TARGET_COL].values)   # Legitimate=0, Malicious=1

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Test accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    print(f"Model saved → {MODEL_PATH}")
    print(f"Encoder saved → {ENCODER_PATH}")
    return clf, le


if __name__ == "__main__":
    train()
