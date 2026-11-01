"""Evaluation metrics for phishing classifiers.

All metrics treat *phishing* as the positive class (label 1).
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)


def choose_threshold(y_true: np.ndarray, scores: np.ndarray, target_precision: float = 0.95) -> tuple[float, str]:
    """Pick a decision threshold on *validation* data.

    Strategy: the lowest threshold whose precision is at least
    ``target_precision`` (maximising recall under a precision floor, because a
    false "phishing" label erodes user trust). If no threshold reaches the
    floor, fall back to the threshold maximising F1.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    # precision/recall have one more element than thresholds.
    precision, recall = precision[:-1], recall[:-1]
    ok = np.where(precision >= target_precision)[0]
    if ok.size:
        best = ok[np.argmax(recall[ok])]
        return float(thresholds[best]), f"max-recall-at-precision>={target_precision:.2f}"
    f1 = np.where(precision + recall > 0, 2 * precision * recall / np.maximum(precision + recall, 1e-12), 0)
    best = int(np.argmax(f1))
    return float(thresholds[best]), "max-f1 (precision target unreachable)"


def compute_metrics(
    y_true: np.ndarray, scores: np.ndarray, threshold: float, curve_points: int = 50
) -> dict[str, object]:
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=float)
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y_true)) == 2

    curve: list[dict[str, float]] = []
    if both_classes:
        p, r, t = precision_recall_curve(y_true, scores)
        idx = np.linspace(0, len(t) - 1, num=min(curve_points, len(t))).astype(int) if len(t) else []
        curve = [
            {"threshold": round(float(t[i]), 4), "precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4)}
            for i in idx
        ]

    return {
        "n": len(y_true),
        "positives": int(y_true.sum()),
        "threshold": round(float(threshold), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "average_precision": round(float(average_precision_score(y_true, scores)), 4) if both_classes else None,
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4) if both_classes else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "pr_curve": curve,
    }


def format_report(metrics: dict[str, object], title: str) -> str:
    cm: dict[str, int] = metrics["confusion_matrix"]  # type: ignore[assignment]
    lines = [
        f"== {title} ==",
        f"samples: {metrics['n']}  (phishing: {metrics['positives']})",
        f"threshold: {metrics['threshold']}",
        f"precision: {metrics['precision']}  recall: {metrics['recall']}  F1: {metrics['f1']}",
        f"false-positive rate: {metrics['false_positive_rate']}",
        f"average precision (PR-AUC): {metrics['average_precision']}  ROC-AUC: {metrics['roc_auc']}",
        "confusion matrix (rows = actual, cols = predicted):",
        "                 pred legit   pred phish",
        f"  actual legit   {cm['tn']:>10}   {cm['fp']:>10}",
        f"  actual phish   {cm['fn']:>10}   {cm['tp']:>10}",
    ]
    return "\n".join(lines)
