"""
Synthetic dataset generator: 462 API traffic records matching the paper.
Attack distribution:
  - SQL Injection:     50 records
  - Schema Violation:  60 records
  - Model Inversion:   40 records
  - DDoS:             200 records
  - Legitimate:       112 records
  Total:              462 records
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import uuid
import json
import os

np.random.seed(42)

ATTACK_DISTRIBUTION = {
    "sql_injection":      50,
    "schema_violation":   60,
    "model_inversion":    40,
    "ddos":              200,
    "legitimate":        112,
}

def generate_legitimate(n: int, start_time: datetime) -> list[dict]:
    records = []
    for i in range(n):
        size_kb = np.random.lognormal(mean=1.0, sigma=0.5)
        size_kb = np.clip(size_kb, 0.1, 20.0)
        # Latency loosely linear with payload size + noise
        latency = 40 + size_kb * 0.8 + np.random.normal(0, 5)
        latency = max(10, latency)
        cpu_load = np.random.uniform(10, 35)
        anomaly_score = np.random.uniform(0.0, 1.5)
        records.append({
            "request_id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 0.5)).isoformat(),
            "traffic_type": "Legitimate",
            "attack_type": "none",
            "request_size_kb": round(size_kb, 3),
            "response_time_ms": round(latency, 2),
            "anomaly_score": round(anomaly_score, 3),
            "cpu_load_pct": round(cpu_load, 2),
            "blocked_at_gateway": False,
            "status_code": 200,
            "server_load_impact": "Normal",
        })
    return records


def generate_sql_injection(n: int, start_time: datetime) -> list[dict]:
    records = []
    for i in range(n):
        # SQL injection payloads are typically small but contain long strings
        size_kb = np.random.uniform(0.1, 2.0)
        # Blocked early → near-zero backend latency
        latency = np.random.uniform(2, 8)
        cpu_load = np.random.uniform(5, 15)
        anomaly_score = np.random.uniform(7.0, 10.0)
        records.append({
            "request_id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 0.3)).isoformat(),
            "traffic_type": "Malicious",
            "attack_type": "sql_injection",
            "request_size_kb": round(size_kb, 3),
            "response_time_ms": round(latency, 2),
            "anomaly_score": round(anomaly_score, 3),
            "cpu_load_pct": round(cpu_load, 2),
            "blocked_at_gateway": True,   # 100% blocked
            "status_code": 400,
            "server_load_impact": "Low",
        })
    return records


def generate_schema_violation(n: int, start_time: datetime) -> list[dict]:
    records = []
    for i in range(n):
        size_kb = np.random.uniform(0.05, 5.0)
        # 96.6% blocked → 2 pass through (handled in simulator)
        blocked = i < int(n * 0.966)
        latency = np.random.uniform(2, 12) if blocked else np.random.uniform(30, 80)
        cpu_load = np.random.uniform(5, 20) if blocked else np.random.uniform(20, 60)
        anomaly_score = np.random.uniform(5.0, 9.0)
        records.append({
            "request_id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 0.4)).isoformat(),
            "traffic_type": "Malicious",
            "attack_type": "schema_violation",
            "request_size_kb": round(size_kb, 3),
            "response_time_ms": round(latency, 2),
            "anomaly_score": round(anomaly_score, 3),
            "cpu_load_pct": round(cpu_load, 2),
            "blocked_at_gateway": blocked,
            "status_code": 400 if blocked else 500,
            "server_load_impact": "Low",
        })
    return records


def generate_model_inversion(n: int, start_time: datetime) -> list[dict]:
    records = []
    for i in range(n):
        # Model inversion: payloads look legitimate but probe boundaries
        size_kb = np.random.lognormal(mean=1.2, sigma=0.4)
        size_kb = np.clip(size_kb, 0.5, 15.0)
        blocked = i < int(n * 0.75)
        latency = np.random.uniform(5, 20) if blocked else 40 + size_kb * 0.8 + np.random.normal(0, 5)
        cpu_load = np.random.uniform(10, 30) if blocked else np.random.uniform(30, 70)
        anomaly_score = np.random.uniform(3.0, 7.0)
        records.append({
            "request_id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(seconds=i * 0.8)).isoformat(),
            "traffic_type": "Malicious",
            "attack_type": "model_inversion",
            "request_size_kb": round(size_kb, 3),
            "response_time_ms": round(latency, 2),
            "anomaly_score": round(anomaly_score, 3),
            "cpu_load_pct": round(cpu_load, 2),
            "blocked_at_gateway": blocked,
            "status_code": 429 if blocked else 200,
            "server_load_impact": "Medium",
        })
    return records


def generate_ddos(n: int, start_time: datetime) -> list[dict]:
    records = []
    for i in range(n):
        # DDoS: very high frequency, large volume
        size_kb = np.random.choice([
            np.random.uniform(0.01, 0.5),   # tiny rapid-fire
            np.random.uniform(40, 100),      # large payload bombs
        ], p=[0.6, 0.4])
        blocked = i < int(n * 0.95)
        latency = np.random.uniform(1, 5) if blocked else np.random.uniform(200, 800)
        cpu_load = np.random.uniform(50, 95) if not blocked else np.random.uniform(5, 20)
        anomaly_score = np.random.uniform(6.0, 10.0)
        records.append({
            "request_id": str(uuid.uuid4()),
            "timestamp": (start_time + timedelta(milliseconds=i * 100)).isoformat(),
            "traffic_type": "Malicious",
            "attack_type": "ddos",
            "request_size_kb": round(size_kb, 3),
            "response_time_ms": round(latency, 2),
            "anomaly_score": round(anomaly_score, 3),
            "cpu_load_pct": round(cpu_load, 2),
            "blocked_at_gateway": blocked,
            "status_code": 429 if blocked else 200,
            "server_load_impact": "High",
        })
    return records


def generate_dataset() -> pd.DataFrame:
    start = datetime(2024, 1, 15, 9, 0, 0)
    records = []
    records.extend(generate_legitimate(ATTACK_DISTRIBUTION["legitimate"], start))
    records.extend(generate_sql_injection(ATTACK_DISTRIBUTION["sql_injection"], start + timedelta(minutes=5)))
    records.extend(generate_schema_violation(ATTACK_DISTRIBUTION["schema_violation"], start + timedelta(minutes=10)))
    records.extend(generate_model_inversion(ATTACK_DISTRIBUTION["model_inversion"], start + timedelta(minutes=20)))
    records.extend(generate_ddos(ATTACK_DISTRIBUTION["ddos"], start + timedelta(minutes=30)))
    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate_dataset()
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, "synthetic_traffic_data.csv")
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} records → {out_path}")
    print(df["attack_type"].value_counts())
    print(f"\nBlocked: {df['blocked_at_gateway'].sum()} / {len(df)}")
