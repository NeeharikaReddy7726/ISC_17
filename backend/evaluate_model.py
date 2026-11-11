"""
Read-Only Real-World Evaluation Script for QR Shield's Random Forest Model.

Evaluates the existing pre-trained model (`app/ml/phishing_rf_model.joblib`) via
`app/ml/predictor.py` against 20 test URLs:
  - 10 manually selected, canonical legitimate institutional/documentation URLs.
  - 10 active, verified phishing URLs obtained from OpenPhish (`https://openphish.com/feed.txt`)
    on 2026-11-11, selected specifically to have ZERO domain overlap with `dataset.csv`.

SAFETY & INTEGRITY GUARANTEES:
- Strictly read-only: does NOT modify the model, dataset, features, or config.
- Zero network calls: does NOT visit, open, resolve, or crawl any evaluated URL.
- Unbiased metrics: reports accuracy, precision, recall, F1-score, confusion matrix,
  false positives, and false negatives directly from actual predictor outputs.
"""

import os
import sys
import warnings
import pandas as pd
import tldextract
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# Suppress harmless parallel user warnings from scikit-learn
warnings.filterwarnings("ignore", category=UserWarning)

# Ensure backend directory is importable
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.ml.predictor import predict_url

DATASET_PATH = os.path.join(BACKEND_DIR, "app", "ml", "dataset.csv")
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

# ---------------------------------------------------------------------------
# 10 Manually Selected Well-Known Legitimate URLs (with explicit justification)
# ---------------------------------------------------------------------------
LEGITIMATE_TEST_URLS = [
    {
        "url": "https://www.nist.gov/cyberframework",
        "source": "Manual selection — U.S. NIST (.gov) official Cybersecurity Framework portal",
    },
    {
        "url": "https://owasp.org/www-project-top-ten/",
        "source": "Manual selection — Official OWASP Foundation Top Ten security documentation",
    },
    {
        "url": "https://docs.python.org/3/library/urllib.parse.html",
        "source": "Manual selection — Official Python Software Foundation standard library docs",
    },
    {
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP",
        "source": "Manual selection — Official Mozilla MDN Web Docs HTTP reference",
    },
    {
        "url": "https://scikit-learn.org/stable/modules/ensemble.html",
        "source": "Manual selection — Official Scikit-learn documentation on ensemble classifiers",
    },
    {
        "url": "https://fastapi.tiangolo.com/tutorial/",
        "source": "Manual selection — Official FastAPI framework tutorial documentation",
    },
    {
        "url": "https://en.wikipedia.org/wiki/Phishing",
        "source": "Manual selection — Official Wikimedia Foundation Wikipedia encyclopedia article",
    },
    {
        "url": "https://www.ietf.org/standards/rfcs/",
        "source": "Manual selection — Official Internet Engineering Task Force (IETF) RFC standards page",
    },
    {
        "url": "https://www.stanford.edu/academics/",
        "source": "Manual selection — Official Stanford University (.edu) academics portal",
    },
    {
        "url": "https://github.com/fastapi/fastapi/releases",
        "source": "Manual selection — Official GitHub repository releases page for FastAPI",
    },
]

# ---------------------------------------------------------------------------
# 10 Verified Phishing URLs from OpenPhish (https://openphish.com/feed.txt)
# Collected on 2026-11-11; PhishTank public CSV returned HTTP 429 rate-limit.
# All 10 have unseen registrable root domains relative to backend/app/ml/dataset.csv.
# ---------------------------------------------------------------------------
PHISHING_TEST_URLS = [
    {
        "url": "https://s4w.in/SpeoA",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "https://bakepectin-6n.responsivewebsitebuilder.io/site/73b75dbc/sbb?preview=true&insitepreview=true&dm_device=desktop",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "http://roblox.com.ss/communities/5203849233/TwinnyGROUP",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "https://officedrive.abneycapitallp.uk/?amp;e=aW5mb0B3YW5kZXJ3ZWdtYXJraWVydW5nLmNo&v=421137",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "https://slipmat.it/wp-admin/js/widgets/",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "http://b3f4.imtoken.2027web3.xyz/",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "http://tokieninn-cdn18-hk79.homes/",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "https://whatsapp.m-ashraf.com/",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "https://csmgroup.blu-foods.com/login?method=signin&mode=secure&client_id=db30ed6-53592-41922-0d22-aaab5901c&privacy=on&sso_reload=true&redirect_urI=https%3A%2F%2Flogin.microsoftonline.com%2F",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
    {
        "url": "http://employeecenters.com/concluded.php?k=2cc703c14f9b2454ca84a31e6d6a15d7",
        "source": "OpenPhish verified feed (https://openphish.com/feed.txt, snapshot 2026-11-11)",
    },
]


def get_root_domain(url: str) -> str:
    ext = _TLD_EXTRACTOR(str(url).strip())
    return (ext.top_domain_under_public_suffix or ext.domain or "unknown").lower()


def run_evaluation():
    print("=" * 80)
    print("QR SHIELD: READ-ONLY REAL-WORLD MODEL EVALUATION")
    print("=" * 80)

    # Read-only dataset overlap check
    train_df = pd.read_csv(DATASET_PATH)
    train_urls = set(train_df["url"].astype(str).str.strip())
    train_roots = set(train_df["url"].apply(get_root_domain))

    evaluation_cases = []
    for entry in LEGITIMATE_TEST_URLS:
        evaluation_cases.append({"actual_label": "Legitimate", "y_true": 0, **entry})
    for entry in PHISHING_TEST_URLS:
        evaluation_cases.append({"actual_label": "Phishing", "y_true": 1, **entry})

    y_true = []
    y_pred = []
    false_positives = []
    false_negatives = []

    print("\n[1] Per-URL Predictions (using app.ml.predictor.predict_url):")
    print("-" * 80)

    exact_url_overlap = 0
    legit_root_overlap = 0
    phish_root_overlap = 0

    for idx, case in enumerate(evaluation_cases, 1):
        url = case["url"]
        actual = case["actual_label"]
        root = get_root_domain(url)

        if url in train_urls:
            exact_url_overlap += 1
        if root in train_roots:
            if actual == "Legitimate":
                legit_root_overlap += 1
            else:
                phish_root_overlap += 1

        res = predict_url(url)
        predicted = res["prediction"]
        conf = res["confidence_percentage"]
        risk = res["risk_level"]
        is_correct = predicted == actual

        y_true.append(case["y_true"])
        y_pred.append(1 if predicted == "Phishing" else 0)

        status_str = "CORRECT"
        if not is_correct:
            if actual == "Legitimate":
                status_str = "INCORRECT (FALSE POSITIVE)"
                false_positives.append({**case, "result": res, "root": root})
            else:
                status_str = "INCORRECT (FALSE NEGATIVE)"
                false_negatives.append({**case, "result": res, "root": root})

        print(f"[{idx:02d}] URL:        {url}")
        print(f"     Source:     {case['source']}")
        print(f"     Actual:     {actual:<10} | Predicted: {predicted:<10} | Correct: {status_str}")
        print(f"     Confidence: {conf:.2f}%     | Risk Level: {risk:<10} | Root in dataset.csv: {'Yes' if root in train_roots else 'No'}")
        print("-" * 80)

    # Metrics calculation
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("\n[2] Dataset Overlap Verification (Read-Only):")
    print(f"  - Exact URL overlap with dataset.csv:            {exact_url_overlap} / 20")
    print(f"  - Legitimate root-domain overlap with Tranco:    {legit_root_overlap} / 10")
    print(f"  - Phishing root-domain overlap with PhishTank:   {phish_root_overlap} / 10")

    print("\n[3] Aggregate Evaluation Metrics (20 Real-World URLs):")
    print("=" * 56)
    print(f"  Accuracy:  {acc * 100:.2f}%  ({sum(t == p for t, p in zip(y_true, y_pred))}/20)")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print("=" * 56)

    print("\n[4] Confusion Matrix:")
    print("                 Predicted Legit   Predicted Phish")
    print(f"  Actual Legit:  [ TN: {tn:<5} ]     [ FP: {fp:<5} ]")
    print(f"  Actual Phish:  [ FN: {fn:<5} ]     [ TP: {tp:<5} ]")

    print("\n[5] Misclassification Analysis:")
    print(f"  False Positives (Legitimate flagged as Phishing): {len(false_positives)}")
    for item in false_positives:
        r = item["result"]
        print(f"    - {item['url']}")
        print(f"      Conf={r['confidence_percentage']}%, PhishProb={r['phishing_probability']}, Risk={r['risk_level']}")
        print(f"      Features={r['features']}")

    print(f"\n  False Negatives (Phishing missed as Legitimate):  {len(false_negatives)}")
    for item in false_negatives:
        r = item["result"]
        print(f"    - {item['url']}")
        print(f"      Conf={r['confidence_percentage']}%, PhishProb={r['phishing_probability']}, Risk={r['risk_level']}")
        print(f"      Features={r['features']}")


if __name__ == "__main__":
    run_evaluation()
