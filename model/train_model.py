"""
Machine Learning Training Pipeline for Malicious URL Detection
=============================================================
Extracts features across a multi-class dataset of URLs and trains
a Random Forest Classifier to distinguish:
  0: Safe URL
  1: Suspicious URL
  2: Malicious URL
  3: Phishing URL

Saves the trained model and metadata to 'model/url_model.pkl'.
"""

import os
import sys
import random
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# Add parent directory to sys.path so utils can be imported
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from utils.feature_extraction import extract_url_features, FEATURE_NAMES

LABEL_MAP = {
    0: "Safe",
    1: "Suspicious",
    2: "Malicious",
    3: "Phishing"
}

# --- Core Curated URL Datasets ---

SAFE_URLS = [
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://github.com/torvalds/linux",
    "https://github.com/features/actions",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://stackoverflow.com/questions/tagged/python",
    "https://stackoverflow.com/users/profile/12345",
    "https://aws.amazon.com/console/",
    "https://aws.amazon.com/ec2/pricing/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.python.org/3/tutorial/index.html",
    "https://edition.cnn.com/world/europe",
    "https://www.nytimes.com/section/technology",
    "https://www.apple.com/iphone-15-pro/",
    "https://www.apple.com/shop/buy-mac",
    "https://www.linkedin.com/in/cyber-analyst",
    "https://www.linkedin.com/feed/",
    "https://www.reddit.com/r/cybersecurity/",
    "https://www.reddit.com/r/programming/",
    "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
    "https://medium.com/@cyberresearch/url-analysis-guide",
    "https://archive.org/details/texts",
    "https://www.mit.edu/admissions/",
    "https://www.stanford.edu/research/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.bbc.com/news/technology",
    "https://www.reuters.com/markets/",
    "https://www.nationalgeographic.com/environment",
    "https://www.quora.com/topic/Information-Security",
    "https://www.nasa.gov/missions/",
    "https://pypi.org/project/scikit-learn/",
    "https://pypi.org/project/flask/",
    "https://hub.docker.com/_/python",
    "https://www.salesforce.com/products/what-is-salesforce/",
    "https://stripe.com/docs/api",
    "https://zoom.us/join",
    "https://slack.com/workspace",
    "https://www.imdb.com/title/tt0133093/",
    "https://www.khanacademy.org/computing",
    "https://coursera.org/learn/machine-learning",
    "https://weather.com/weather/today/l/USNY0996",
    "https://www.bloomberg.com/technology",
    "https://www.target.com/c/electronics",
    "https://www.walmart.com/browse/clothing",
    "https://www.nike.com/running",
    "https://www.adobe.com/products/photoshop.html",
    "https://www.cisco.com/c/en/us/products/security.html",
    "https://www.oracle.com/cloud/",
    "https://www.ted.com/talks"
]

SUSPICIOUS_URLS = [
    "http://bit.ly/3x8AbCd",
    "https://tinyurl.com/free-gift-card-win2024",
    "http://cutt.ly/bank-security-notice",
    "http://rb.gy/9x21za",
    "http://is.gd/verify_credentials_now",
    "http://buff.ly/account_verification_portal",
    "http://adf.ly/29381928/bonus",
    "http://ow.ly/user-login-prompt",
    "http://paypal.com@attacker-controlled-server.net/login",
    "http://google.com@phish-gateway.org/accounts/auth",
    "http://microsoft.com@malicious-redirect-hub.top/security",
    "http://bankofamerica.com@login-spoof.xyz/portal",
    "http://secure--portal--login.xyz/validate",
    "http://chase--verify--identity.top/account",
    "http://paypal--security--alert.click/confirm",
    "http://free-crypto-giveaway-winner.xyz/?claim=1&user=88412",
    "http://update-browser-now.tk/flash_installer.exe",
    "http://win-iphone-today-free.buzz/claim_reward",
    "http://account-recovery-system.pw/?id=8848123&session=991",
    "http://login-service-auth.kim:8000/test-portal",
    "http://portal.auth.sec.domain.co.xyz/verify",
    "http://unusual-domain-name-service-provider.top/login",
    "http://redirect-link-system.xyz//external?url=http://unsafe-node.org",
    "http://s.id/urgent-security-action",
    "http://v.gd/paypal_verify_doc",
    "http://tiny.cc/prize-claimer",
    "http://bl.ink/special-crypto-bonus",
    "http://shorte.st/83910/token-gift",
    "http://sub1.sub2.sub3.suspicious-hub.top/check",
    "http://suspicious-promo-giveaway.monster/win?token=928401",
    "http://fast-cash-reward.cricket/claim",
    "http://crypto-airdrop-exclusive.country/connect-wallet",
    "http://login-alert-notice.cf/verify.html",
    "http://account-update-warning.gq/login",
    "http://urgent-notice-suspended.ml/appeal",
    "http://verify-identity-doc.ga/view",
    "http://customer-support-desk.fit/ticket?id=99281",
    "http://unlocked-rewards-vault.cam/prize",
    "http://survey-winner-selection.rest/start",
    "http://instant-bonus-payout.surf/claim"
]

MALICIOUS_URLS = [
    "http://192.168.1.100/payload.exe",
    "http://45.33.32.156/shell.bin",
    "http://185.220.101.5/botnet/gate.php",
    "http://104.244.78.11:8080/dropper.sh",
    "http://89.208.107.12/update/win32_setup.exe",
    "http://217.182.197.8/miner/xmrig.exe",
    "http://193.106.191.22/trojan/loader.bin",
    "http://194.26.29.112:4444/c2_beacon",
    "http://178.62.204.101/malware/keylogger.zip",
    "http://91.92.109.15/payloads/ransomware.exe",
    "http://45.142.214.19/stealer/logs_collector.php",
    "http://195.123.245.9:6667/irc_bot",
    "http://103.151.125.10/rev_shell.pl",
    "http://185.196.8.24/injectors/dll_inject.dll",
    "http://77.91.100.27/rat/remcos_builder.exe",
    "http://194.165.16.11/darkcomet/stub.exe",
    "http://x93jf92mzk0a1l.biz/payload.dll",
    "http://dga-malware-c2-984219.ru/upload?client=4810",
    "http://qzk29smflk39alxz.org/beacon?interval=60",
    "http://m9z8y7x6w5v4u3t.info/downloader.scr",
    "http://trojan-server-drop.xyz/update.zip",
    "http://ransomware-dist-node-88.top/encrypt.bin",
    "http://evil-c2-node.ddns.net:4444/rev_shell",
    "http://exploit-kit-landing-page.xyz/flash_exploit.html",
    "http://zero-day-payload-drop.biz/shellcode.bin",
    "http://rootkit-installer-cdn.ru/driver.sys",
    "http://infostealer-gate-panel.top/post_passwords.php",
    "http://redline-stealer-collector.xyz/api/logs",
    "http://lockbit-affiliate-portal.su/ransom_note.hta",
    "http://cobaltstrike-teamserver-node.biz:50050/submit",
    "http://metasploit-payload-host.ru:8443/meterpreter.elf",
    "http://botnet-command-center-99.org/sync.php?cmd=ddos",
    "http://mirai-scanner-infector.cc/bins/mirai.arm7",
    "http://banking-trojan-zeus-variant.xyz/config.bin",
    "http://backdoor-access-daemon.info:9999/admin_exec",
    "http://spyware-keystroke-logger.biz/send_data.cgi",
    "http://cryptominer-pool-stealth.top/stratum/tcp",
    "http://worm-autorun-spreader.ru/payload_v2.bat",
    "http://agent-tesla-exfiltrate.xyz/smtp_send.php",
    "http://quasar-rat-controller.net:8888/gate"
]

PHISHING_URLS = [
    "http://paypal-verification-secure-account.com/login.php",
    "http://appleid.apple.com-verify-account.info/auth/login",
    "https://secure-login-wellsfargo-update.com/signin/credentials",
    "http://chase-bank-verify-identity.xyz/login/verify.html",
    "http://netflix-billing-update-required.top/account/payment",
    "http://microsoft-online-security-verify.com/login/auth",
    "http://accounts.google.com.security-alert-user-login.com/checkpoint",
    "http://bankofamerica-online-service.click/portal/login",
    "http://secure.paypal.com.webscr.security-notice.net/login/confirm",
    "http://signin.ebay.com.ebayisapi.dll.account-update.info/login",
    "http://instagram-security-badge-verify.xyz/login/checkpoint",
    "http://facebook-security-checkpoint-appeal.club/auth/checkpoint",
    "http://amazon-account-suspension-alert.com/signin/update_billing",
    "http://binance-login-security-authentication.xyz/verify/wallet",
    "http://metamask-extension-recovery-seed-phrase.top/wallet/connect",
    "http://coinbase-account-restricted-action.com/signin/verify",
    "http://dropbox-shared-document-review.xyz/login/credentials",
    "http://office365-password-expiration-warning.top/owa/auth",
    "http://dhl-package-tracking-confirm-address.click/delivery",
    "http://fedex-delivery-pending-reschedule.xyz/tracking/verify",
    "http://usps-package-customs-fee-payment.top/pay/confirm",
    "http://irs-tax-refund-direct-deposit-form.club/submit/ssn",
    "http://gov-stimulus-check-application-verify.xyz/login",
    "http://citibank-card-compromised-alert.net/secure/signin",
    "http://hsbc-security-token-generator-sync.com/banking/logon",
    "http://barclays-online-banking-auth-device.xyz/login",
    "http://santander-account-upgrade-mandatory.top/portal",
    "http://att-yahoo-mail-quota-exceeded-fix.com/login.jsp",
    "http://aol-mail-reactivate-dormant-account.xyz/verify",
    "http://linkedin-invitation-message-view.top/login/connect",
    "http://twitter-blue-badge-apply-free.xyz/auth/twitter",
    "http://steam-trade-gift-card-community.club/trade/login",
    "http://roblox-free-robux-generator-login.xyz/account",
    "http://epicgames-fortnite-vbucks-claim.top/login/epic",
    "http://discord-nitro-gift-claim-free.click/nitro/verify",
    "http://telegram-web-login-sms-code.xyz/auth/session",
    "http://whatsapp-web-scan-qr-code-sync.club/login",
    "http://walmart-survey-gift-card-claim.top/redeem/login",
    "http://target-rewards-redemption-verify.xyz/account/bonus",
    "http://uber-driver-payout-account-verify.click/login"
]


def generate_augmented_dataset():
    """
    Synthesize realistic variations and combinations to augment the training set,
    ensuring robust generalization across real-world attacks.
    """
    urls = []
    labels = []
    
    # Add base curated datasets
    for u in SAFE_URLS:
        urls.append(u)
        labels.append(0)  # Safe
        
    for u in SUSPICIOUS_URLS:
        urls.append(u)
        labels.append(1)  # Suspicious
        
    for u in MALICIOUS_URLS:
        urls.append(u)
        labels.append(2)  # Malicious
        
    for u in PHISHING_URLS:
        urls.append(u)
        labels.append(3)  # Phishing

    # Safe URL Generators
    safe_roots = [
        "https://www.wikipedia.org", "https://github.com", "https://stackoverflow.com",
        "https://docs.microsoft.com", "https://cloud.google.com", "https://developer.apple.com",
        "https://www.nature.com", "https://www.sciencedirect.com", "https://www.coursera.org",
        "https://www.udemy.com", "https://gitlab.com", "https://bitbucket.org",
        "https://www.etsy.com", "https://www.pinterest.com", "https://www.kaggle.com"
    ]
    safe_paths = [
        "/docs/overview", "/library/reference/v2", "/questions/show/84920",
        "/projects/open-source/release", "/learn/machine-learning/module-4",
        "/article/2024/03/scientific-discovery", "/category/electronics/smartphones",
        "/search?q=open+standards&page=2", "/api/v1/documentation/getting-started",
        "/downloads/stable/release-notes.html", "/help/faq/account-settings"
    ]
    for root in safe_roots:
        for path in safe_paths[:6]:
            urls.append(f"{root}{path}")
            labels.append(0)

    # Phishing URL Generators (combine spoofed brands, lure keywords, and free TLDs)
    phish_brands = ["paypal", "appleid", "chase", "wellsfargo", "netflix", "microsoft365", "binance", "coinbase"]
    phish_actions = ["login-verify", "account-update", "billing-confirm", "security-alert", "identity-check"]
    phish_tlds = [".com", ".net", ".xyz", ".top", ".club", ".click"]
    for brand in phish_brands:
        for action in phish_actions:
            for tld in phish_tlds[:3]:
                url = f"http://{brand}-{action}-portal{tld}/signin.php?session_id={random.randint(10000, 99999)}"
                urls.append(url)
                labels.append(3)

    # Malicious URL Generators (IPs with raw binaries, malware endpoints, C2 beacons)
    raw_ips = [
        "194.87.139.", "185.156.73.", "45.141.87.", "193.32.162.", "89.248.165.",
        "109.237.103.", "185.220.101.", "91.240.118."
    ]
    mal_payloads = [
        "/win32/agent.exe", "/dropper/x64_payload.bin", "/bot/beacon.php",
        "/miner/setup.zip", "/rootkit/installer.scr", "/gate.php?bot_id=12984",
        "/shell/backdoor.py", "/cmd.exe", "/loader.dll", "/stealer/data.bin"
    ]
    for ip_base in raw_ips:
        for i in range(2, 6):
            ip = f"{ip_base}{i * 15}"
            for payload in mal_payloads[:4]:
                port = random.choice(["", ":8080", ":4444", ":9001", ":8443"])
                urls.append(f"http://{ip}{port}{payload}")
                labels.append(2)

    # Suspicious URL Generators (excessive subdomains, URL shorteners, redirect params)
    shorteners = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co"]
    for s in shorteners:
        for i in range(10):
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
            urls.append(f"http://{s}/{token}")
            labels.append(1)

    for i in range(15):
        urls.append(f"http://user.auth.secure.login.service.cloud.host{i}.top/verify")
        labels.append(1)
        urls.append(f"http://example.org//redirect?dest=http://attacker-node-{i}.xyz/token")
        labels.append(1)

    return urls, labels


def train_and_save_model(output_path: str = None):
    """
    Extract features, train Random Forest, evaluate metrics, and serialize model.
    """
    if output_path is None:
        output_path = os.path.join(CURRENT_DIR, "url_model.pkl")

    print("[*] Generating and compiling training dataset...")
    urls, raw_labels = generate_augmented_dataset()
    print(f"[+] Total URLs in dataset: {len(urls)}")

    print("[*] Extracting security features for all URLs (Safe Lexical Analysis)...")
    X = []
    y = np.array(raw_labels)

    for url in urls:
        feat_result = extract_url_features(url)
        X.append(feat_result["feature_vector"])

    X = np.array(X)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")
    print("[*] Training Random Forest Classifier (120 estimators, balanced weights)...")

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=3,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n================ MODEL EVALUATION ================")
    print(f"Model Accuracy: {acc * 100:.2f}%\n")
    print("Classification Report:")
    target_names = [LABEL_MAP[i] for i in sorted(LABEL_MAP.keys())]
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Feature Importance
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("Top Feature Importances:")
    for idx in sorted_idx[:8]:
        print(f"  - {FEATURE_NAMES[idx]}: {importances[idx] * 100:.2f}%")
    print("===================================================\n")

    # Package model metadata
    model_payload = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "label_map": LABEL_MAP,
        "accuracy": float(acc),
        "classes": list(clf.classes_)
    }

    # Ensure model directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model_payload, output_path)
    print(f"[+] Successfully serialized trained model to:\n    {output_path}")

    # Run quick sanity verification
    test_samples = [
        ("https://github.com/torvalds/linux", "Safe"),
        ("http://paypal-verification-secure-account.com/login.php", "Phishing"),
        ("http://192.168.1.100/payload.exe", "Malicious"),
        ("http://bit.ly/3x8AbCd", "Suspicious")
    ]
    print("\nSanity Check on Test Samples:")
    for test_url, expected in test_samples:
        feat = extract_url_features(test_url)
        vector = np.array(feat["feature_vector"]).reshape(1, -1)
        pred_idx = clf.predict(vector)[0]
        proba = clf.predict_proba(vector)[0]
        predicted_label = LABEL_MAP[pred_idx]
        print(f"  - URL: {test_url[:45]:<45} | Predicted: {predicted_label:<10} (Expected: {expected}) | Confidence: {max(proba)*100:.1f}%")

    return clf, acc


if __name__ == "__main__":
    train_and_save_model()
