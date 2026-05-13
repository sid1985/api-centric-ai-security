"""
Request logger plugin — logs every gateway transaction to SQLite.
Captures: timing, status, attack detection results, forwarded-to-backend flag.
"""
import os
import sqlite3
import time
from pathlib import Path

DB_PATH = os.environ.get("DB_PATH", "/app/logs/gateway.db")


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS gateway_log (
            id                  TEXT PRIMARY KEY,
            timestamp           TEXT NOT NULL,
            client_ip           TEXT,
            method              TEXT,
            path                TEXT,
            request_size_kb     REAL,
            anomaly_score       REAL,
            gateway_decision    TEXT,      -- 'passed' | 'blocked'
            block_reason        TEXT,
            status_code         INTEGER,
            gateway_latency_ms  REAL,      -- time gateway spent (not incl. backend)
            total_latency_ms    REAL,      -- end-to-end
            backend_latency_ms  REAL
        )
    """)
    con.commit()
    con.close()


def log_transaction(row: dict):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT OR IGNORE INTO gateway_log
                (id, timestamp, client_ip, method, path,
                 request_size_kb, anomaly_score,
                 gateway_decision, block_reason, status_code,
                 gateway_latency_ms, total_latency_ms, backend_latency_ms)
            VALUES
                (:id, :timestamp, :client_ip, :method, :path,
                 :request_size_kb, :anomaly_score,
                 :gateway_decision, :block_reason, :status_code,
                 :gateway_latency_ms, :total_latency_ms, :backend_latency_ms)
        """, row)
        con.commit()
        con.close()
    except Exception as e:
        import logging
        logging.getLogger("gateway.logger").warning(f"DB write failed: {e}")
