"""
Integration tests for Flask REST API endpoints and error handlers.
Validates URL analysis, statistics, history logging, and input validation.
"""

import unittest
import json
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app


class TestFlaskAPI(unittest.TestCase):

    def setUp(self):
        """Configure test client."""
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_index_route(self):
        """GET / must render the dashboard HTML."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Malicious URL Detection System", response.data)
        self.assertIn(b"ISOLATED ENGINE", response.data)

    def test_analyze_valid_safe_url(self):
        """POST /api/analyze with legitimate URL should return Safe classification."""
        payload = {"url": "https://en.wikipedia.org/wiki/Computer_security"}
        response = self.client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["category"], "Safe")
        self.assertLessEqual(data["risk_score"], 25.0)
        self.assertIn("probabilities", data)
        self.assertIn("detailed_features", data)

    def test_analyze_empty_url_validation(self):
        """POST /api/analyze with empty input must return 400 Bad Request."""
        payload = {"url": "   "}
        response = self.client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("error", data)

    def test_analyze_unsupported_dangerous_scheme(self):
        """POST /api/analyze with javascript: or data: must return 400 Bad Request."""
        payload = {"url": "javascript:alert(document.cookie)"}
        response = self.client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Unsupported or dangerous URI scheme", data["error"])

    def test_analyze_data_uri_scheme(self):
        """POST /api/analyze with data: scheme must return 400 Bad Request."""
        payload = {"url": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}
        response = self.client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])

    def test_get_statistics_endpoint(self):
        """GET /api/stats must return aggregate telemetry data."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("stats", data)
        self.assertIn("total_analyzed", data["stats"])
        self.assertIn("distribution", data["stats"])

    def test_get_scan_history_endpoint(self):
        """GET /api/history must return recent scan list."""
        response = self.client.get("/api/history?limit=5")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIsInstance(data["history"], list)

    def test_get_sample_urls_endpoint(self):
        """GET /api/sample-urls must return preset test dataset."""
        response = self.client.get("/api/sample-urls")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(len(data["samples"]), 4)

    def test_api_404_handler(self):
        """GET to nonexistent API route must return 404 JSON."""
        response = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertFalse(data["success"])


if __name__ == "__main__":
    unittest.main()
