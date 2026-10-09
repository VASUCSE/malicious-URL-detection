"""
Cybersecurity Feature Extraction Engine for URL Analysis
=========================================================
Performs safe, isolated lexical and structural analysis of URLs.
CRITICAL: This module NEVER makes outbound network requests or visits the target URL.
"""

import math
import re
from urllib.parse import urlparse, parse_qs

# Known URL shortener services commonly leveraged to mask destination URLs
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "bl.ink",
    "shorte.st", "v.gd", "tr.im", "s.id", "soo.gd", "snipurl.com"
}

# Suspicious keywords frequently observed in phishing lures and attack payloads
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "banking",
    "secure", "security", "wallet", "paypal", "ebayisapi", "webscr", "password",
    "confirm", "authenticate", "billing", "credential", "recovery", "bonus",
    "crypto", "support", "token", "validate", "suspension", "alert", "appleid",
    "netflix", "microsoft", "google", "facebook", "unlock", "passcode"
]

# Sensitive TLDs often correlated with low-cost disposable malicious campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "country", "kim", "cricket", "link",
    "gq", "cf", "tk", "ml", "ga", "rest", "cam", "fit", "monster", "surf"
}

FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "num_digits",
    "has_https",
    "has_ip",
    "num_subdomains",
    "suspicious_keywords_count",
    "is_shortened",
    "has_at_symbol",
    "redirect_pattern",
    "entropy",
    "domain_length",
    "path_length",
    "query_length",
    "has_port",
    "consecutive_hyphens"
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to identify high randomness/obfuscation (e.g., DGA domains)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url_string: str) -> dict:
    """
    Extract comprehensive lexical and structural security features from a URL string.
    Ensures safe parsing without contacting the remote endpoint.
    """
    cleaned_url = url_string.strip() if url_string else ""
    original_url = cleaned_url
    
    # Check original protocol
    has_https = 1 if original_url.lower().startswith("https://") else 0
    
    # Prepend scheme if absent solely for reliable RFC-compliant parsing
    parse_target = original_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_target):
        parse_target = "http://" + parse_target
        
    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        netloc = parsed.netloc.lower()
    except Exception:
        hostname = ""
        path = ""
        query = ""
        netloc = ""
        
    # 1. URL Length
    url_length = len(original_url)
    
    # 2. Dots & Hyphens
    num_dots = original_url.count(".")
    num_hyphens = original_url.count("-")
    
    # 3. Special Characters
    special_chars = re.findall(r"[^a-zA-Z0-9]", original_url)
    num_special_chars = len(special_chars)
    
    # 4. Digits
    num_digits = sum(1 for c in original_url if c.isdigit())
    
    # 5. IP Address Usage
    # Check standard IPv4 regex or hex/numeric encoded IPs in hostname
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    has_ip = 0
    if hostname:
        if re.match(ipv4_pattern, hostname):
            has_ip = 1
        elif hostname.startswith("[") and hostname.endswith("]"):  # IPv6
            has_ip = 1
        elif hostname.replace(".", "").isdigit():
            has_ip = 1
            
    # 6. Subdomain Count
    # Break hostname by dots
    host_parts = [p for p in hostname.split(".") if p]
    if has_ip:
        num_subdomains = 0
    elif len(host_parts) > 2:
        # e.g., sub.domain.co.uk or sub.domain.com
        num_subdomains = max(0, len(host_parts) - 2)
    else:
        num_subdomains = 0
        
    # 7. Suspicious Keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in original_url.lower()]
    suspicious_keywords_count = len(found_keywords)
    
    # 8. URL Shortening Services
    is_shortened = 1 if (hostname in KNOWN_SHORTENERS or any(hostname.endswith("." + s) for s in KNOWN_SHORTENERS)) else 0
    
    # 9. @ Symbol Detection (often disguises actual host in browsers)
    has_at_symbol = 1 if "@" in original_url else 0
    
    # 10. Redirect Patterns (// in path or redirect parameter indicators)
    has_double_slash_path = 1 if "//" in path else 0
    redirect_indicators = ["redirect=", "url=", "next=", "dest=", "target=", "r="]
    has_redirect_param = 1 if any(ind in query.lower() for ind in redirect_indicators) else 0
    redirect_pattern = 1 if (has_double_slash_path or has_redirect_param) else 0
    
    # 11. Shannon Entropy
    entropy = calculate_entropy(original_url)
    
    # 12. Structural Lengths
    domain_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    
    # 13. Port Specification
    has_port = 0
    if ":" in netloc and not (hostname.startswith("[") and netloc.endswith("]")):
        # Check if non-default port is present
        try:
            if parsed.port and parsed.port not in [80, 443]:
                has_port = 1
        except Exception:
            pass
            
    # 14. Consecutive Hyphens (e.g., pay--pal spoofing)
    consecutive_hyphens = 1 if "--" in original_url else 0
    
    # Vector for machine learning model (matches FEATURE_NAMES strictly)
    feature_vector = [
        url_length,
        num_dots,
        num_hyphens,
        num_special_chars,
        num_digits,
        has_https,
        has_ip,
        num_subdomains,
        suspicious_keywords_count,
        is_shortened,
        has_at_symbol,
        redirect_pattern,
        entropy,
        domain_length,
        path_length,
        query_length,
        has_port,
        consecutive_hyphens
    ]
    
    # Detailed diagnostic inspection dictionary with status ratings for the frontend UI
    detailed_features = {
        "url_length": {
            "name": "URL Length",
            "value": url_length,
            "status": "danger" if url_length > 100 else ("warning" if url_length > 65 else "normal"),
            "description": "Excessively long URLs are often used to conceal malicious subdomains or inject obfuscated tokens."
        },
        "num_dots": {
            "name": "Dot Count",
            "value": num_dots,
            "status": "danger" if num_dots >= 4 else ("warning" if num_dots == 3 else "normal"),
            "description": "Multiple dots indicate deep subdomain nesting or deceptive domain chaining."
        },
        "num_hyphens": {
            "name": "Hyphen Count",
            "value": num_hyphens,
            "status": "danger" if num_hyphens >= 4 else ("warning" if num_hyphens >= 2 else "normal"),
            "description": "Attackers frequently use hyphens (e.g. paypal-security-login) for brand spoofing."
        },
        "num_special_chars": {
            "name": "Special Characters",
            "value": num_special_chars,
            "status": "warning" if num_special_chars > 12 else "normal",
            "description": "High special character counts often indicate encoded payloads or complex evasion strings."
        },
        "num_digits": {
            "name": "Numeric Digits",
            "value": num_digits,
            "status": "warning" if num_digits > 15 else "normal",
            "description": "High digit counts appear in automated tracking strings, hex encoding, and botnet domains."
        },
        "has_https": {
            "name": "HTTPS Usage",
            "value": "Yes (Encrypted)" if has_https == 1 else "No (Cleartext HTTP)",
            "status": "normal" if has_https == 1 else "warning",
            "description": "Lack of HTTPS indicates unencrypted transport, although modern phishing sites also acquire free certificates."
        },
        "has_ip": {
            "name": "IP Address Host",
            "value": "Detected" if has_ip == 1 else "None (Domain Name)",
            "status": "danger" if has_ip == 1 else "normal",
            "description": "Direct IP hostnames bypass domain reputation filters and are heavily associated with malware C2 servers."
        },
        "num_subdomains": {
            "name": "Subdomain Count",
            "value": num_subdomains,
            "status": "danger" if num_subdomains >= 3 else ("warning" if num_subdomains == 2 else "normal"),
            "description": "Excessive subdomains mimic authoritative brands on attacker-controlled roots."
        },
        "suspicious_keywords": {
            "name": "Suspicious Keywords",
            "value": f"{suspicious_keywords_count} ({', '.join(found_keywords)})" if found_keywords else "0 detected",
            "status": "danger" if suspicious_keywords_count >= 2 else ("warning" if suspicious_keywords_count == 1 else "normal"),
            "description": "Credentials, banking, and urgency-based keywords typical in phishing social engineering."
        },
        "is_shortened": {
            "name": "URL Shortener",
            "value": "Yes" if is_shortened == 1 else "No",
            "status": "warning" if is_shortened == 1 else "normal",
            "description": "Shortening services mask true destination endpoints and evade visual inspection."
        },
        "has_at_symbol": {
            "name": "@ Symbol Present",
            "value": "Yes" if has_at_symbol == 1 else "No",
            "status": "danger" if has_at_symbol == 1 else "normal",
            "description": "The '@' character causes browsers to treat preceding text as user credentials and navigate to the trailing host."
        },
        "redirect_pattern": {
            "name": "Redirect Pattern",
            "value": "Detected" if redirect_pattern == 1 else "None",
            "status": "danger" if redirect_pattern == 1 else "normal",
            "description": "Unvalidated open redirect patterns or double slash ('//') paths used in multi-stage phishing flows."
        },
        "entropy": {
            "name": "Shannon Entropy",
            "value": entropy,
            "status": "danger" if entropy > 4.5 else ("warning" if entropy > 4.0 else "normal"),
            "description": "Measures string randomness. High entropy suggests algorithmic generation (DGA) or encrypted payload names."
        },
        "consecutive_hyphens": {
            "name": "Consecutive Hyphens",
            "value": "Yes" if consecutive_hyphens == 1 else "No",
            "status": "danger" if consecutive_hyphens == 1 else "normal",
            "description": "Multiple dashes ('--') often simulate legitimate brand naming conventions."
        },
        "domain_length": {
            "name": "Domain Length",
            "value": domain_length,
            "status": "warning" if domain_length > 30 else "normal",
            "description": "Length of the target domain/host. Unusually long hostnames are common in spoofing."
        },
        "path_length": {
            "name": "Path Length",
            "value": path_length,
            "status": "warning" if path_length > 60 else "normal",
            "description": "Deep or complex URL paths often conceal redirection scripts or obfuscated subfolders."
        },
        "query_length": {
            "name": "Query Length",
            "value": query_length,
            "status": "warning" if query_length > 80 else "normal",
            "description": "Length of URL query parameters (?key=val). Long queries often transmit encoded payloads."
        },
        "has_port": {
            "name": "Non-Standard Port",
            "value": "Detected" if has_port == 1 else "Standard (80/443)",
            "status": "danger" if has_port == 1 else "normal",
            "description": "Explicit non-standard TCP ports (e.g. :8080, :8888) frequently indicate rogue staging servers."
        }
    }
    
    # Identify key security red flags for instant display
    red_flags = []
    if has_ip == 1:
        red_flags.append("Host is an explicit IP address instead of a legitimate domain name.")
    if has_at_symbol == 1:
        red_flags.append("Contains '@' symbol, a common tactic to obscure the true destination hostname.")
    if is_shortened == 1:
        red_flags.append("Utilizes a known URL shortening service masking the actual destination.")
    if redirect_pattern == 1:
        red_flags.append("Exhibits redirect parameters or anomalous double-slash path patterns.")
    if found_keywords:
        red_flags.append(f"Contains security-sensitive lure keywords: {', '.join(found_keywords)}.")
    if num_subdomains >= 2:
        red_flags.append(f"Multiple subdomain levels ({num_subdomains}) indicative of domain spoofing.")
    if url_length > 85:
        red_flags.append(f"Anomalously long URL string ({url_length} characters).")
    if consecutive_hyphens == 1:
        red_flags.append("Contains consecutive hyphens ('--') frequently observed in typosquatting.")
    if has_https == 0:
        red_flags.append("Uses unencrypted HTTP protocol.")
    if entropy > 4.2:
        red_flags.append(f"High information entropy ({entropy}), suggesting randomized or DGA components.")
        
    return {
        "url": original_url,
        "hostname": hostname,
        "feature_vector": feature_vector,
        "feature_names": FEATURE_NAMES,
        "detailed_features": detailed_features,
        "red_flags": red_flags,
        "keywords_found": found_keywords
    }
