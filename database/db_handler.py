"""
SQLite Database Management Layer for Malicious URL Detection
============================================================
Handles persistent logging of scanned URLs, threat categories,
risk scores, extracted features, and statistical metrics.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "predictions.db")


def get_db_connection(db_path: str = DEFAULT_DB_PATH):
    """Establish connection to SQLite database with row factory for dictionary access."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH):
    """Initialize database schema and insert initial demo records if empty."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            category TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence REAL NOT NULL,
            features_json TEXT NOT NULL,
            red_flags_json TEXT NOT NULL,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON url_scans(category);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON url_scans(scan_timestamp);")
    conn.commit()

    # Pre-populate sample benchmark scans if table is empty for a populated initial dashboard
    cursor.execute("SELECT COUNT(*) as count FROM url_scans;")
    count = cursor.fetchone()["count"]
    if count == 0:
        demo_records = [
            ("https://github.com/torvalds/linux", "Safe", 5.2, 98.4,
             json.dumps({"url_length": 34, "has_https": 1, "has_ip": 0}),
             json.dumps([])),
            ("https://en.wikipedia.org/wiki/Computer_security", "Safe", 8.0, 96.1,
             json.dumps({"url_length": 47, "has_https": 1, "has_ip": 0}),
             json.dumps([])),
            ("http://paypal-verification-secure-account.com/login.php", "Phishing", 94.5, 95.8,
             json.dumps({"url_length": 55, "has_https": 0, "suspicious_keywords": 3}),
             json.dumps(["Unencrypted HTTP", "Multiple phishing lure keywords", "Suspicious hyphenated brand name"])),
            ("http://192.168.1.100/payload.exe", "Malicious", 98.0, 99.2,
             json.dumps({"url_length": 31, "has_ip": 1, "has_https": 0}),
             json.dumps(["Host is an IP address", "Direct executable binary download (.exe)"])),
            ("http://bit.ly/3x8AbCd", "Suspicious", 48.0, 88.0,
             json.dumps({"url_length": 21, "is_shortened": 1}),
             json.dumps(["Masked destination via URL shortening service", "HTTP protocol"]))
        ]
        cursor.executemany("""
            INSERT INTO url_scans (url, category, risk_score, confidence, features_json, red_flags_json)
            VALUES (?, ?, ?, ?, ?, ?);
        """, demo_records)
        conn.commit()

    conn.close()


def save_scan(url: str, category: str, risk_score: float, confidence: float,
              features: dict, red_flags: list, db_path: str = DEFAULT_DB_PATH) -> int:
    """Save an analyzed URL scan record into the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO url_scans (url, category, risk_score, confidence, features_json, red_flags_json, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        url,
        category,
        round(float(risk_score), 2),
        round(float(confidence), 2),
        json.dumps(features),
        json.dumps(red_flags),
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    inserted_id = cursor.lastrowid
    conn.close()
    return inserted_id


def get_recent_scans(limit: int = 15, db_path: str = DEFAULT_DB_PATH) -> list:
    """Retrieve the most recent URL scans."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, category, risk_score, confidence, features_json, red_flags_json, scan_timestamp
        FROM url_scans
        ORDER BY id DESC
        LIMIT ?;
    """, (limit,))
    rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "url": r["url"],
            "category": r["category"],
            "risk_score": r["risk_score"],
            "confidence": r["confidence"],
            "features": json.loads(r["features_json"]) if r["features_json"] else {},
            "red_flags": json.loads(r["red_flags_json"]) if r["red_flags_json"] else [],
            "timestamp": r["scan_timestamp"]
        })
    conn.close()
    return results


def get_dashboard_stats(db_path: str = DEFAULT_DB_PATH) -> dict:
    """Compute aggregate cybersecurity metrics and category distributions."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total, AVG(risk_score) as avg_risk FROM url_scans;")
    summary = cursor.fetchone()
    total = summary["total"] if summary and summary["total"] else 0
    avg_risk = round(summary["avg_risk"], 1) if summary and summary["avg_risk"] else 0.0

    cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM url_scans
        GROUP BY category;
    """)
    cat_counts = {r["category"]: r["count"] for r in cursor.fetchall()}

    safe_count = cat_counts.get("Safe", 0)
    suspicious_count = cat_counts.get("Suspicious", 0)
    malicious_count = cat_counts.get("Malicious", 0)
    phishing_count = cat_counts.get("Phishing", 0)
    threat_count = malicious_count + phishing_count

    safe_percent = round((safe_count / total * 100), 1) if total > 0 else 0
    suspicious_percent = round((suspicious_count / total * 100), 1) if total > 0 else 0
    threat_percent = round((threat_count / total * 100), 1) if total > 0 else 0

    conn.close()
    return {
        "total_analyzed": total,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "phishing_count": phishing_count,
        "threat_count": threat_count,
        "safe_percentage": safe_percent,
        "suspicious_percentage": suspicious_percent,
        "threat_percentage": threat_percent,
        "avg_risk_score": avg_risk,
        "distribution": {
            "Safe": safe_count,
            "Suspicious": suspicious_count,
            "Malicious": malicious_count,
            "Phishing": phishing_count
        }
    }


def clear_all_history(db_path: str = DEFAULT_DB_PATH):
    """Truncate scan history."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM url_scans;")
    conn.commit()
    conn.close()
