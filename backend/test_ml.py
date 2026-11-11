"""
Test suite for QR Shield Module 2: AI-based Phishing URL Detection.
"""

import os
import sys
import warnings

# Suppress harmless runtime parallel warnings from scikit-learn on Python 3.14
warnings.filterwarnings("ignore", category=UserWarning)

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.ml.feature_extractor import extract_url_features_dict, extract_url_features_vector, FEATURE_NAMES
from app.ml.predictor import predict_url, get_model_bundle


def test_feature_extraction():
    print("\n[Test 1] Testing Feature Extractor on Diverse URLs...")

    # Case A: Standard secure university URL
    url_a = "https://example-university.edu/student-portal"
    f_a = extract_url_features_dict(url_a)
    assert f_a["is_https"] == 1
    assert f_a["having_ip"] == 0
    assert f_a["is_shortened"] == 0
    assert f_a["subdomain_count"] == 0
    print(f"  --> Case A (Standard): dots={f_a['count_dots']}, len={f_a['url_length']}, https={f_a['is_https']}")

    # Case B: Deceptive domain containing sensitive keywords
    url_b = "http://secure-paypal-login.com/verify.php?token=998877"
    f_b = extract_url_features_dict(url_b)
    assert f_b["keyword_in_domain"] == 1
    assert f_b["is_https"] == 0
    assert f_b["count_equal_signs"] == 1
    assert f_b["count_question_marks"] == 1
    print(f"  --> Case B (Deceptive domain): keyword_in_domain={f_b['keyword_in_domain']}, https={f_b['is_https']}")

    # Case C: Raw IP address URL
    url_c = "http://192.168.0.55/admin.php"
    f_c = extract_url_features_dict(url_c)
    assert f_c["having_ip"] == 1
    assert f_c["is_https"] == 0
    print(f"  --> Case C (IP Address): having_ip={f_c['having_ip']}")

    # Case D: URL Shortener
    url_d = "https://bit.ly/xyz123"
    f_d = extract_url_features_dict(url_d)
    assert f_d["is_shortened"] == 1
    print(f"  --> Case D (Shortener): is_shortened={f_d['is_shortened']}")

    # Verify vector extraction matches 14 features
    vec = extract_url_features_vector(url_a)
    assert len(vec) == 14
    print("  --> Vector extraction shape: 14/14 features aligned.")
    print("  --> PASSED: Feature extraction functions properly.")


def test_model_bundle_integrity():
    print("\n[Test 2] Testing Trained Model Bundle Integrity...")
    bundle = get_model_bundle()
    assert "model" in bundle
    assert "metrics" in bundle
    assert "feature_names" in bundle
    assert len(bundle["feature_names"]) == 14

    metrics = bundle["metrics"]
    print(f"  --> Model accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f"  --> Model precision: {metrics['precision'] * 100:.2f}%")
    print(f"  --> Model recall:    {metrics['recall'] * 100:.2f}%")
    print(f"  --> Model F1-score:  {metrics['f1_score'] * 100:.2f}%")
    print(f"  --> Confusion Matrix: {metrics['confusion_matrix']}")
    assert metrics["accuracy"] >= 0.90, "Expected accuracy to be at least 90%"
    print("  --> PASSED: Model bundle verified.")


def test_legitimate_url_predictions():
    print("\n[Test 3] Testing Classification on Known Legitimate URLs...")
    legit_samples = [
        "https://www.google.com/search?q=information+security",
        "https://github.com/explore",
        "https://en.wikipedia.org/wiki/Random_forest",
        "https://stackoverflow.com/questions",
        "https://www.coursera.org/learn/cryptography"
    ]

    for url in legit_samples:
        result = predict_url(url)
        print(f"  --> URL: {url[:45]:<45} => Pred: {result['prediction']:<10} Conf: {result['confidence_percentage']}% Risk: {result['risk_level']}")
        assert result["prediction"] == "Legitimate", f"Expected Legitimate, got {result['prediction']} for {url}"

    print("  --> PASSED: All legitimate test URLs classified correctly.")


def test_phishing_url_predictions():
    print("\n[Test 4] Testing Classification on High-Risk Phishing URLs...")
    phishing_samples = [
        "http://192.168.1.100/paypal-update-account/security-check/login.php?session=92840294829048",
        "http://allegro.pl-7252f5626152652oferta02092827392.cfd",
        "http://secure-banking-verification-update.com.verify-user-security.ru/account-login/",
        "http://netflix-account-verify-billing.suspicious-domain-fake.tk/confirm.html?token=3901928"
    ]

    for url in phishing_samples:
        result = predict_url(url)
        print(f"  --> URL: {url[:50]:<50} => Pred: {result['prediction']:<10} Conf: {result['confidence_percentage']}% Risk: {result['risk_level']}")
        assert result["prediction"] == "Phishing", f"Expected Phishing, got {result['prediction']} for {url}"

    print("  --> PASSED: All phishing test URLs classified correctly.")


def test_security_rules_and_warnings():
    print("\n[Test 5] Testing Security Rule Warnings Generation...")
    # URL with raw IP and no HTTPS
    ip_url = "http://10.0.0.1/auth/login"
    res = predict_url(ip_url)
    assert any("raw numeric IP" in w for w in res["warnings"]), "Expected raw IP warning"
    assert any("plain HTTP" in w for w in res["warnings"]), "Expected plain HTTP warning"
    print(f"  --> Captured expected warnings: {res['warnings']}")

    # URL with URL Shortener
    short_url = "https://bit.ly/secure-login"
    res_short = predict_url(short_url)
    assert any("shortening service" in w for w in res_short["warnings"]), "Expected shortener warning"
    print(f"  --> Captured expected warnings: {res_short['warnings']}")

    print("  --> PASSED: Security rule warnings generated accurately.")


def test_case_insensitive_url_parsing():
    print("\n[Test 6] Testing Case-Insensitive Scheme & Hostname Parsing...")

    expected_feature_names = [
        "url_length",
        "domain_length",
        "having_ip",
        "count_dots",
        "count_hyphens",
        "count_at",
        "count_question_marks",
        "count_equal_signs",
        "count_slashes",
        "count_digits",
        "subdomain_count",
        "is_https",
        "is_shortened",
        "keyword_in_domain",
    ]
    assert FEATURE_NAMES == expected_feature_names, "FEATURE_NAMES order or entries changed unexpectedly!"

    u_lower = "https://example.com/path"
    u_upper = "HTTPS://EXAMPLE.COM/PATH"
    u_mixed_https = "HtTpS://Example.Com/Path"
    u_mixed_http = "HTTP://Example.Com/Path"
    u_lower_http = "http://example.com/path"

    f_lower = extract_url_features_dict(u_lower)
    f_upper = extract_url_features_dict(u_upper)
    f_mixed_https = extract_url_features_dict(u_mixed_https)
    f_mixed_http = extract_url_features_dict(u_mixed_http)
    f_lower_http = extract_url_features_dict(u_lower_http)

    # All HTTPS variants must produce identical features and vectors
    assert f_lower == f_upper == f_mixed_https, (
        f"Mismatch among HTTPS case variants:\n  lower={f_lower}\n  upper={f_upper}\n  mixed={f_mixed_https}"
    )
    assert extract_url_features_vector(u_lower) == extract_url_features_vector(u_upper)
    assert extract_url_features_vector(u_lower) == extract_url_features_vector(u_mixed_https)

    # Hostname 'example.com' has domain_length=11 (not 5 for misparsed 'https')
    assert f_upper["domain_length"] == len("example.com") == 11
    assert f_upper["is_https"] == 1
    assert f_upper["count_slashes"] == 3

    # HTTP variants must match each other identically
    assert f_mixed_http == f_lower_http, (
        f"Mismatch between HTTP case variants:\n  mixed={f_mixed_http}\n  lower={f_lower_http}"
    )
    assert extract_url_features_vector(u_mixed_http) == extract_url_features_vector(u_lower_http)
    assert f_mixed_http["domain_length"] == len("example.com") == 11
    assert f_mixed_http["is_https"] == 0
    assert f_mixed_http["count_slashes"] == 3

    # Compare HTTP vs HTTPS: identical except url_length (4 vs 5 scheme chars) and is_https (0 vs 1)
    for name in FEATURE_NAMES:
        if name in {"url_length", "is_https"}:
            continue
        assert f_mixed_http[name] == f_lower[name], f"Unexpected difference on feature '{name}'"

    # Verify uppercase shortener & audit QR URL parse hostname properly
    f_short_upper = extract_url_features_dict("HTTPS://BIT.LY/XYZ")
    assert f_short_upper["domain_length"] == len("bit.ly")
    assert f_short_upper["is_shortened"] == 1
    assert f_short_upper["is_https"] == 1

    f_st4_upper = extract_url_features_dict("HTTPS://ST4.CH/Q/D8DCU3UD3206105X7EF79DKV")
    f_st4_lower = extract_url_features_dict("https://st4.ch/q/d8dcu3ud3206105x7ef79dkv")
    assert f_st4_upper == f_st4_lower
    assert f_st4_upper["domain_length"] == len("st4.ch") == 6

    print("  --> PASSED: Uppercase, lowercase, and mixed-case HTTP/HTTPS URLs extract identical hostname features.")


if __name__ == "__main__":
    print("=" * 65)
    print("RUNNING AUTOMATED TESTS: MODULE 2 (AI URL PHISHING DETECTION)")
    print("=" * 65)
    test_feature_extraction()
    test_model_bundle_integrity()
    test_legitimate_url_predictions()
    test_phishing_url_predictions()
    test_security_rules_and_warnings()
    test_case_insensitive_url_parsing()
    print("\n" + "=" * 65)
    print("ALL MODULE 2 TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)
