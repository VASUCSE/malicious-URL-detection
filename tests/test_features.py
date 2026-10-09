"""
Unit tests for isolated static feature extraction engine.
Tests lexical analysis, Shannon entropy, and security indicator heuristics.
"""

import unittest
import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.feature_extraction import (
    extract_url_features,
    calculate_entropy,
    FEATURE_NAMES
)


class TestFeatureExtraction(unittest.TestCase):

    def test_feature_vector_length(self):
        """Feature vector must strictly match the 18 defined FEATURE_NAMES."""
        res = extract_url_features("https://www.google.com")
        self.assertEqual(len(res["feature_vector"]), len(FEATURE_NAMES))
        self.assertEqual(len(res["feature_vector"]), 18)

    def test_safe_https_domain(self):
        """Verify standard HTTPS domain parsing."""
        res = extract_url_features("https://github.com/torvalds/linux")
        self.assertEqual(res["detailed_features"]["has_https"]["value"], "Yes (Encrypted)")
        self.assertEqual(res["detailed_features"]["has_ip"]["value"], "None (Domain Name)")
        self.assertEqual(res["detailed_features"]["has_at_symbol"]["value"], "No")
        self.assertEqual(res["detailed_features"]["is_shortened"]["value"], "No")

    def test_raw_ip_address_detection(self):
        """Detect raw IP hostnames and flag as high-risk anomalies."""
        res = extract_url_features("http://192.168.1.100/payload.exe")
        self.assertEqual(res["detailed_features"]["has_ip"]["value"], "Detected")
        self.assertTrue(any("explicit IP address" in flag for flag in res["red_flags"]))

    def test_at_symbol_credential_spoofing(self):
        """Detect @ symbol userinfo credential disguises."""
        res = extract_url_features("http://paypal.com@attacker-site.com/login")
        self.assertEqual(res["detailed_features"]["has_at_symbol"]["value"], "Yes")
        self.assertTrue(any("@" in flag for flag in res["red_flags"]))

    def test_url_shortener_detection(self):
        """Identify known shortening services."""
        res = extract_url_features("http://bit.ly/3x8AbCd")
        self.assertEqual(res["detailed_features"]["is_shortened"]["value"], "Yes")
        self.assertTrue(any("shortening service" in flag for flag in res["red_flags"]))

    def test_suspicious_phishing_keywords(self):
        """Identify phishing lures (login, verify, account, secure)."""
        res = extract_url_features("http://secure-paypal-verify-account.com/login.php")
        self.assertGreaterEqual(len(res["keywords_found"]), 3)
        self.assertIn("login", res["keywords_found"])
        self.assertIn("verify", res["keywords_found"])
        self.assertIn("account", res["keywords_found"])

    def test_shannon_entropy_calculation(self):
        """Shannon entropy must be 0 for empty or repetitive single char strings."""
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaaa"), 0.0)
        
        # Random DGA-like string must exhibit high entropy (> 3.5)
        dga_str = "x9q7z1m4k2v8p0w3"
        self.assertGreater(calculate_entropy(dga_str), 3.5)

    def test_all_18_detailed_features_present(self):
        """Ensure all 18 detailed features are present in detailed_features dictionary."""
        res = extract_url_features("https://sub.example.com:8080/path/to/page?param=1#anchor")
        det = res["detailed_features"]
        expected_keys = [
            "url_length", "num_dots", "num_hyphens", "num_special_chars",
            "num_digits", "has_https", "has_ip", "num_subdomains",
            "suspicious_keywords", "is_shortened", "has_at_symbol",
            "redirect_pattern", "entropy", "consecutive_hyphens",
            "domain_length", "path_length", "query_length", "has_port"
        ]
        for key in expected_keys:
            self.assertIn(key, det, f"Missing detailed feature: {key}")


if __name__ == "__main__":
    unittest.main()
