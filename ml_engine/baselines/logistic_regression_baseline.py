import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

from ml_engine.anomaly_detection.isolation_forest import AnomalyDetector


def compute_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positive_rate": round(fpr, 4),
    }


def run_baseline_comparison(X: np.ndarray, y: np.ndarray) -> dict:
    """
    X: feature matrix, y: ground-truth binary labels (1 = malicious/anomalous).
    Trains a Logistic Regression baseline and compares against our
    Isolation Forest anomaly detector on the same held-out test split.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    # --- Baseline: Logistic Regression (supervised) ---
    log_reg = LogisticRegression(max_iter=1000, class_weight="balanced")
    log_reg.fit(X_train, y_train)
    lr_preds = log_reg.predict(X_test)
    lr_metrics = compute_metrics(y_test, lr_preds)

    # --- Our model: Isolation Forest (unsupervised) ---
    detector = AnomalyDetector()
    detector.fit(X_train)  # trains WITHOUT labels, unlike logistic regression
    if_raw_preds = detector.predict(X_test)
    if_preds = (if_raw_preds == -1).astype(int)  # -1 = anomaly -> 1
    if_metrics = compute_metrics(y_test, if_preds)

    return {
        "logistic_regression_baseline": lr_metrics,
        "isolation_forest_ours": if_metrics,
        "note": (
            "Logistic Regression is supervised (uses labels during training); "
            "Isolation Forest is unsupervised and still competitive, which matters "
            "because real-world traffic often lacks complete attack labels."
        ),
    }


def print_comparison_table(results: dict):
    print(f"{'Metric':<22}{'Logistic Regression':<22}{'Isolation Forest (ours)':<22}")
    print("-" * 66)
    for metric in ["precision", "recall", "f1", "false_positive_rate"]:
        lr_val = results["logistic_regression_baseline"][metric]
        if_val = results["isolation_forest_ours"][metric]
        print(f"{metric:<22}{lr_val:<22}{if_val:<22}")
    print()
    print(results["note"])
    