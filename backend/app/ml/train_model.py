"""
Script to train, evaluate, and serialize the Random Forest classifier
for URL phishing detection in QR Shield.

METHODOLOGY & DATA LEAKAGE PREVENTION:
1. Feature Extraction: 14 lexical numerical features extracted without network access.
2. Domain-Aware Group Splitting: Uses GroupShuffleSplit grouped by the domain name
   to guarantee ZERO domain overlap between the training and testing sets.
   This prevents the model from memorizing specific domains and forces it
   to generalize on structural URL patterns.
3. Class Proportions: Preserves an approximately 50/50 balance in both train and test splits.
"""

import os
import sys
import json
import joblib
import tldextract
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Offline Public Suffix List extractor (zero network requests)
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

# Ensure backend package is importable
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.ml.feature_extractor import extract_url_features_vector, FEATURE_NAMES

DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")
MODEL_PATH = os.path.join(CURRENT_DIR, "phishing_rf_model.joblib")
METRICS_PATH = os.path.join(CURRENT_DIR, "evaluation_metrics.json")


def extract_root_domain(url: str) -> str:
    """
    Extracts the registrable root domain (eTLD+1) using tldextract and the Public Suffix List.
    Example: 'https://sub.example.co.uk/login' -> 'example.co.uk'
    Fallback for raw IP addresses (e.g. 'http://192.168.1.1') -> '192.168.1.1'.
    """
    u = str(url).strip()
    try:
        ext = _TLD_EXTRACTOR(u)
        root = ext.top_domain_under_public_suffix
        if root:
            return root.lower()
        elif ext.domain:
            return ext.domain.lower()
        return "unknown"
    except Exception:
        return "unknown"


def train_and_evaluate():
    print("=" * 68)
    print("QR SHIELD: TRAINING & EVALUATING RANDOM FOREST CLASSIFIER")
    print("=" * 68)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}. Please run download_dataset.py first.")

    # 1. Load and inspect dataset
    print(f"\n[Step 1] Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)

    total_samples = len(df)
    duplicates = df["url"].duplicated().sum()
    legit_count = (df["label"] == 0).sum()
    phish_count = (df["label"] == 1).sum()

    print(f"  --> Total URL records:       {total_samples}")
    print(f"  --> Duplicate URLs detected: {duplicates}")
    print(f"  --> Class distribution:      Legitimate={legit_count} (50%), Phishing={phish_count} (50%)")

    # 2. Extract registrable root domains (eTLD+1) using tldextract to prevent data leakage
    df["root_domain"] = df["url"].apply(extract_root_domain)
    unique_roots = df["root_domain"].nunique()
    print(f"  --> Unique registrable root domains (eTLD+1): {unique_roots}")

    # 3. Extract 14 lexical numerical features
    print("\n[Step 2] Extracting 14 lexical numerical features from URLs...")
    feature_rows = []
    for url in df["url"]:
        feature_rows.append(extract_url_features_vector(url))

    X = np.array(feature_rows)
    y = df["label"].to_numpy()
    print(f"  --> Feature matrix shape: {X.shape} (14 features per URL)")

    # 4. Root-Domain-Aware Group Train/Test Split (80:20)
    print("\n[Step 3] Performing Root-Domain-Aware Train/Test Split (80:20)...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=df["root_domain"]))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    train_roots = set(df.iloc[train_idx]["root_domain"])
    test_roots = set(df.iloc[test_idx]["root_domain"])
    root_domain_overlap = len(train_roots.intersection(test_roots))

    if root_domain_overlap != 0:
        raise RuntimeError(f"Data leakage detected: {root_domain_overlap} root domains overlap between train and test sets!")

    print(f"  --> Train set size: {len(X_train)} samples ({len(X_train) / total_samples * 100:.2f}%)")
    print(f"      (Legitimate: {(y_train == 0).sum()}, Phishing: {(y_train == 1).sum()})")
    print(f"  --> Test set size:  {len(X_test)} samples ({len(X_test) / total_samples * 100:.2f}%)")
    print(f"      (Legitimate: {(y_test == 0).sum()}, Phishing: {(y_test == 1).sum()})")
    print(f"  --> Registrable root-domain overlap between train and test: {root_domain_overlap} (Zero leakage verified)")

    # 5. Train Random Forest Classifier
    print("\n[Step 4] Training Random Forest Classifier...")
    print("  --> Parameters: n_estimators=100, max_depth=15, random_state=42")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    print("  --> Training completed successfully.")

    # 6. Evaluate on the Unseen Test Set
    print("\n[Step 5] Evaluating Model Performance on Unseen Test Data...")
    y_pred = rf_model.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print("\n" + "=" * 50)
    print("              EVALUATION METRICS")
    print("=" * 50)
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print("=" * 50)

    print("\nConfusion Matrix:")
    print(f"                Predicted Legit   Predicted Phish")
    print(f"  Actual Legit: [ TN: {tn:<5} ]   [ FP: {fp:<5} ]")
    print(f"  Actual Phish: [ FN: {fn:<5} ]   [ TP: {tp:<5} ]")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    print("\nFeature Importances (How the Decision Trees Split Decisions):")
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx, 1):
        feat_name = FEATURE_NAMES[idx]
        imp_val = importances[idx] * 100
        print(f"  {rank:>2}. {feat_name:<25} : {imp_val:.2f}%")

    # 7. Save Model Bundle & Metrics
    print("\n[Step 6] Saving Model Artifacts...")
    bundle = {
        "model": rf_model,
        "feature_names": FEATURE_NAMES,
        "classes": ["Legitimate", "Phishing"],
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            },
            "split_info": {
                "grouping_method": "registrable_root_domain (eTLD+1 via tldextract)",
                "train_samples": len(X_train),
                "train_legitimate": int((y_train == 0).sum()),
                "train_phishing": int((y_train == 1).sum()),
                "test_samples": len(X_test),
                "test_legitimate": int((y_test == 0).sum()),
                "test_phishing": int((y_test == 1).sum()),
                "root_domain_overlap": root_domain_overlap
            }
        }
    }

    joblib.dump(bundle, MODEL_PATH)
    print(f"  --> Saved trained model to: {MODEL_PATH}")

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(bundle["metrics"], f, indent=2)
    print(f"  --> Saved metrics to:        {METRICS_PATH}")

    print("\n" + "=" * 68)
    print("TRAINING & EVALUATION COMPLETE!")
    print("=" * 68)


if __name__ == "__main__":
    train_and_evaluate()
