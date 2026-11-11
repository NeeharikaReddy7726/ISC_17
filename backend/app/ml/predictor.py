"""
Prediction engine for QR Shield.
Loads the pre-trained Random Forest model and classifies incoming URLs.
"""

import os
import joblib
import warnings
import numpy as np

# Suppress harmless parallel user warnings
warnings.filterwarnings("ignore", category=UserWarning)
from typing import Dict, Any
from app.ml.feature_extractor import (
    extract_url_features_dict,
    extract_url_features_vector,
    FEATURE_NAMES
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, "phishing_rf_model.joblib")

# Global cache for the loaded model bundle
_MODEL_BUNDLE = None


def get_model_bundle() -> Dict[str, Any]:
    """Loads and caches the model bundle from disk."""
    global _MODEL_BUNDLE
    if _MODEL_BUNDLE is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Trained model not found at {MODEL_PATH}. "
                "Please run train_model.py first."
            )
        _MODEL_BUNDLE = joblib.load(MODEL_PATH)
    return _MODEL_BUNDLE


def predict_url(url: str) -> Dict[str, Any]:
    """
    Classifies a given URL as 'Legitimate' or 'Phishing'.

    SAFETY GUARANTEE:
    This function performs strictly local string-based evaluation.
    It DOES NOT send any HTTP requests, establish connections,
    or visit the target URL.

    Parameters:
        url: The URL string extracted from a QR code.

    Returns:
        dict containing:
            - url: Input URL string
            - prediction: 'Legitimate' or 'Phishing'
            - confidence_percentage: Model confidence (e.g. 96.5)
            - phishing_probability: Probability score between 0.0 and 1.0
            - risk_level: 'Safe', 'Suspicious', or 'High Risk'
            - features: Dictionary of the 14 extracted numerical features
            - warnings: List of specific security red flags detected
    """
    bundle = get_model_bundle()
    model = bundle["model"]

    # 1. Extract lexical features
    features_dict = extract_url_features_dict(url)
    features_vec = [float(features_dict[name]) for name in FEATURE_NAMES]

    # 2. Model inference (Random Forest prediction & probabilities)
    input_array = np.array([features_vec])
    raw_pred = model.predict(input_array)[0]  # 0 = Legitimate, 1 = Phishing
    probabilities = model.predict_proba(input_array)[0]

    prob_legitimate = float(probabilities[0])
    prob_phishing = float(probabilities[1])

    # 3. Determine base prediction label
    prediction_label = "Phishing" if raw_pred == 1 else "Legitimate"
    confidence = max(prob_legitimate, prob_phishing) * 100.0

    # 4. Security rule evaluation (detect red flags for suspicious warnings)
    warnings = []
    if features_dict["having_ip"] == 1:
        warnings.append("URL uses a raw numeric IP address instead of a standard domain name.")
    if features_dict["is_shortened"] == 1:
        warnings.append("URL uses a URL shortening service, hiding the true destination.")
    if features_dict["count_at"] > 0:
        warnings.append("URL contains the '@' symbol, often used to obscure actual hostnames.")
    if features_dict["subdomain_count"] >= 3:
        warnings.append("URL contains an unusually high number of subdomains (domain nesting).")
    if features_dict["keyword_in_domain"] == 1:
        warnings.append("Domain contains deceptive authentication/security keywords (e.g., login, verify, account, secure).")
    if features_dict["is_https"] == 0:
        warnings.append("URL does not use HTTPS encryption (plain HTTP).")

    # 5. Risk Level categorization (Safe / Suspicious / High Risk)
    if prediction_label == "Phishing":
        risk_level = "High Risk"
    elif 0.35 <= prob_phishing < 0.50 or (len(warnings) >= 2 and prob_phishing >= 0.25):
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"

    return {
        "url": url,
        "prediction": prediction_label,
        "confidence_percentage": round(confidence, 2),
        "phishing_probability": round(prob_phishing, 4),
        "risk_level": risk_level,
        "features": features_dict,
        "warnings": warnings
    }
