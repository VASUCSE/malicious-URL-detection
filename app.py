"""
Flask Application for Cybersecurity Malicious URL Detection System
==================================================================
Provides REST endpoints and interactive web dashboard for real-time,
isolated static feature extraction and ML threat classification.
CRITICAL: Analyzes URL strings safely WITHOUT making outbound network requests.
"""

import os
import joblib
import numpy as np
from flask import Flask, render_template, request, jsonify

from utils.feature_extraction import extract_url_features, FEATURE_NAMES
from database.db_handler import (
    init_db,
    save_scan,
    get_recent_scans,
    get_dashboard_stats,
    clear_all_history
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "url_model.pkl")


def load_env_file(filepath=os.path.join(BASE_DIR, ".env")):
    """Load key-value environment pairs from .env file if present."""
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except Exception:
            pass


load_env_file()

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.config["JSON_SORT_KEYS"] = False


@app.after_request
def add_security_headers(response):
    """Add defensive HTTP security headers and CORS support."""
    response.headers["Access-Control-Allow-Origin"] = os.environ.get("CORS_ORIGIN", "*")
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# Ensure database is initialized
init_db()

# Load trained Machine Learning model
ml_pipeline = None
if os.path.exists(MODEL_PATH):
    try:
        ml_pipeline = joblib.load(MODEL_PATH)
        print(f"[+] Loaded ML model from {MODEL_PATH}")
    except Exception as e:
        print(f"[!] Warning: Could not load model file ({e}).")
else:
    print(f"[!] Warning: Model file not found at {MODEL_PATH}. Run 'python model/train_model.py' to generate.")

SAMPLE_TEST_URLS = [
    {
        "type": "Safe",
        "url": "https://github.com/torvalds/linux",
        "label": "GitHub Repo (Safe)",
        "badge": "safe"
    },
    {
        "type": "Safe",
        "url": "https://en.wikipedia.org/wiki/Computer_security",
        "label": "Wikipedia Article (Safe)",
        "badge": "safe"
    },
    {
        "type": "Phishing",
        "url": "http://paypal-verification-secure-account.com/login.php",
        "label": "Fake PayPal Login (Phishing)",
        "badge": "phishing"
    },
    {
        "type": "Phishing",
        "url": "http://appleid.apple.com-verify-account.info/auth/login",
        "label": "AppleID Credential Stealer",
        "badge": "phishing"
    },
    {
        "type": "Malicious",
        "url": "http://192.168.1.100/payload.exe",
        "label": "Raw IP Malware Drop (Malicious)",
        "badge": "malicious"
    },
    {
        "type": "Malicious",
        "url": "http://45.33.32.156/shell.bin",
        "label": "Raw IP Shell Drop (Malicious)",
        "badge": "malicious"
    },
    {
        "type": "Suspicious",
        "url": "http://bit.ly/3x8AbCd",
        "label": "Shortened Link (Suspicious)",
        "badge": "suspicious"
    },
    {
        "type": "Suspicious",
        "url": "http://paypal.com@attacker-controlled-server.net/login",
        "label": "@ Symbol Spoof (Suspicious)",
        "badge": "suspicious"
    }
]


def calculate_risk_and_category(features_dict: dict):
    """
    Compute category, probability distribution, and 0-100% Risk Score.
    Uses trained ML model if available, with a resilient heuristic fallback.
    """
    red_flags = features_dict.get("red_flags", [])
    raw_vector = features_dict.get("feature_vector", [])

    if ml_pipeline is not None and "model" in ml_pipeline:
        model = ml_pipeline["model"]
        label_map = ml_pipeline.get("label_map", {
            0: "Safe", 1: "Suspicious", 2: "Malicious", 3: "Phishing"
        })
        x = np.array(raw_vector).reshape(1, -1)
        pred_idx = int(model.predict(x)[0])
        probabilities = model.predict_proba(x)[0]

        # Probability distribution dict
        classes = list(model.classes_)
        prob_dict = {}
        for c, p in zip(classes, probabilities):
            cat_name = label_map.get(c, str(c))
            prob_dict[cat_name] = round(float(p) * 100, 1)

        category = label_map.get(pred_idx, "Suspicious")
        confidence = round(float(max(probabilities)) * 100, 1)

        p_safe = prob_dict.get("Safe", 0.0) / 100.0
        p_suspicious = prob_dict.get("Suspicious", 0.0) / 100.0
        p_malicious = prob_dict.get("Malicious", 0.0) / 100.0
        p_phishing = prob_dict.get("Phishing", 0.0) / 100.0

        # Weighted calibrated risk formula
        base_risk = (p_suspicious * 45.0) + (p_malicious * 96.0) + (p_phishing * 92.0)

        # Fine adjustments based on high-severity static red flags
        if features_dict.get("detailed_features", {}).get("has_ip", {}).get("value") == "Detected":
            base_risk = max(base_risk, 85.0)
            if category == "Safe":
                category = "Malicious"
        if "@" in features_dict.get("url", ""):
            base_risk = max(base_risk, 60.0)
            if category == "Safe":
                category = "Suspicious"

        # Cap between 0 and 100
        risk_score = round(min(100.0, max(0.0, base_risk)), 1)
        if category == "Safe":
            risk_score = min(risk_score, 24.0)

    else:
        # Fallback heuristic engine if model file is rebuilding
        score = 5.0
        for flag in red_flags:
            score += 20.0
        risk_score = round(min(100.0, max(0.0, score)), 1)
        confidence = 80.0
        if risk_score >= 75:
            category = "Malicious"
        elif risk_score >= 50:
            category = "Phishing"
        elif risk_score >= 25:
            category = "Suspicious"
        else:
            category = "Safe"
        prob_dict = {
            "Safe": 85.0 if category == "Safe" else 10.0,
            "Suspicious": 80.0 if category == "Suspicious" else 15.0,
            "Malicious": 90.0 if category == "Malicious" else 5.0,
            "Phishing": 88.0 if category == "Phishing" else 10.0
        }

    # Derive Risk Level
    if risk_score <= 25:
        risk_level = "Low Risk"
        recommendation = "Safe to access. No significant threat vectors or anomalous lexical patterns were identified."
    elif risk_score <= 55:
        risk_level = "Moderate Risk"
        recommendation = "Exercise caution. URL contains masking mechanisms, redirects, or unusual domain characteristics."
    elif risk_score <= 80:
        risk_level = "High Risk"
        recommendation = "Potentially deceptive destination. High probability of credential harvesting or phishing activity."
    else:
        risk_level = "Critical Threat"
        recommendation = "Do not navigate to this address. Attributes strongly correspond with malware delivery or active cyber exploitation."

    return {
        "category": category,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "probabilities": prob_dict,
        "recommendation": recommendation
    }


@app.route("/")
def index():
    """Render main cybersecurity dashboard."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze_url():
    """
    Safely inspect and classify a submitted URL.
    STRICT SECURITY GUARANTEE: Does NOT make outbound network connections or visit the URL.
    """
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    # Input validation
    if not url:
        return jsonify({
            "success": False,
            "error": "URL cannot be empty. Please provide a valid URL string to analyze."
        }), 400

    if len(url) > 2048:
        return jsonify({
            "success": False,
            "error": "URL exceeds maximum permissible length (2048 characters)."
        }), 400

    # Reject unsupported / non-web / dangerous URI schemes
    lower_url = url.lower()
    dangerous_schemes = (
        "javascript:", "data:", "file:", "blob:", "vbscript:",
        "about:", "chrome:", "intent:", "ftp:"
    )
    for scheme in dangerous_schemes:
        if lower_url.startswith(scheme):
            return jsonify({
                "success": False,
                "error": f"Unsupported or dangerous URI scheme '{scheme}'. Only web URLs (HTTP, HTTPS, or domain names) are supported for security analysis."
            }), 400

    # 1. Feature Extraction (Isolated lexical analysis)
    try:
        features_result = extract_url_features(url)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to extract URL features: {str(e)}"
        }), 500

    # 2. ML Prediction & Risk Calculation
    try:
        assessment = calculate_risk_and_category(features_result)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Machine learning inference failed: {str(e)}"
        }), 500

    # 3. Persist scan log into SQLite
    try:
        scan_id = save_scan(
            url=url,
            category=assessment["category"],
            risk_score=assessment["risk_score"],
            confidence=assessment["confidence"],
            features=features_result["detailed_features"],
            red_flags=features_result["red_flags"]
        )
    except Exception as e:
        scan_id = None
        print(f"[!] Warning: Failed to save scan into SQLite ({e})")

    response_payload = {
        "success": True,
        "scan_id": scan_id,
        "url": url,
        "hostname": features_result.get("hostname", ""),
        "category": assessment["category"],
        "risk_score": assessment["risk_score"],
        "risk_level": assessment["risk_level"],
        "confidence": assessment["confidence"],
        "probabilities": assessment["probabilities"],
        "recommendation": assessment["recommendation"],
        "red_flags": features_result["red_flags"],
        "detailed_features": features_result["detailed_features"],
        "keywords_found": features_result.get("keywords_found", []),
        "disclaimer": "Educational cybersecurity detection system. Statically analyzed without visiting target URL. Machine learning predictions are probabilistic."
    }

    return jsonify(response_payload)


@app.route("/api/history", methods=["GET"])
def get_history():
    """Retrieve recent scans from SQLite database."""
    try:
        limit = request.args.get("limit", default=15, type=int)
        scans = get_recent_scans(limit=limit)
        return jsonify({"success": True, "history": scans})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieve aggregate statistics for dashboard metric cards and Chart.js."""
    try:
        stats = get_dashboard_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/clear-history", methods=["POST"])
def clear_history():
    """Clear all logged scan history."""
    try:
        clear_all_history()
        stats = get_dashboard_stats()
        return jsonify({"success": True, "message": "History cleared successfully", "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sample-urls", methods=["GET"])
def get_sample_urls():
    """Provide curated sample URLs for convenient testing and student presentations."""
    return jsonify({"success": True, "samples": SAMPLE_TEST_URLS})


@app.errorhandler(404)
def handle_404(e):
    """Clean JSON or HTML response for missing routes."""
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "API route not found"}), 404
    return render_template("index.html"), 404


@app.errorhandler(500)
def handle_500(e):
    """Clean JSON response for unexpected internal errors."""
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal server error"}), 500
    return render_template("index.html"), 500


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    print("\n" + "=" * 60)
    print("🛡️  MALICIOUS URL DETECTION SYSTEM (CYBERSECURITY LAB)")
    print("   Engine: Isolated Static Lexical Feature Extractor + Scikit-Learn")
    print("   Database: SQLite (database/predictions.db)")
    print(f"   Dashboard: http://{host}:{port}")
    print("=" * 60 + "\n")
    app.run(host=host, port=port, debug=debug)

