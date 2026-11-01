"""Reproducible training pipeline.

Steps
-----
1. Load + clean the labelled CSV (:mod:`phishguard.ml.preprocessing`).
2. Extract features with the scan-time feature extractor.
3. Split **by registered domain** (``GroupShuffleSplit``) so URLs from the same
   domain never appear in both training and evaluation data, or
   **chronologically** when a timestamp column is supplied. Random row-level
   splits leak near-duplicate URLs and inflate scores.
4. Fit two baselines with class-imbalance handling (``class_weight``):
   logistic regression (scaled) and a random forest. Select by validation
   average precision.
5. Choose the decision threshold on the validation split only.
6. Evaluate exactly once on the untouched test split.
7. Save ``<version>.joblib`` and ``<version>.json`` (metadata, metrics,
   provenance, SHA-256).

Nothing here downloads data: the dataset must be obtained separately (see
``datasets/README.md``).
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from phishguard.detector.url_features import NUMERIC_FEATURE_NAMES
from phishguard.ml.evaluate import choose_threshold, compute_metrics
from phishguard.ml.model_metadata import ModelMetadata, feature_set_version, metadata_path_for, sha256_file
from phishguard.ml.preprocessing import PreparedDataset, clean, featurize, load_labelled_csv

logger = logging.getLogger(__name__)

MIN_ROWS = 200
MIN_PER_CLASS = 50


@dataclass
class TrainingConfig:
    dataset_path: Path
    output_dir: Path
    url_col: str = "url"
    label_col: str = "label"
    phishing_value: str = "1"
    time_col: str | None = None
    assume_scheme: str | None = "http"
    seed: int = 42
    test_size: float = 0.15
    val_size: float = 0.15
    target_precision: float = 0.95
    dataset_name: str = "unspecified"
    dataset_source: str = "unspecified"
    dataset_license: str = "unspecified"
    max_rows: int | None = None


@dataclass
class Split:
    train: np.ndarray
    val: np.ndarray
    test: np.ndarray
    strategy: str


def split_dataset(data: PreparedDataset, cfg: TrainingConfig) -> Split:
    n = len(data.y)
    if data.times is not None and data.times.notna().all():
        order = np.argsort(data.times.to_numpy())
        n_test = int(n * cfg.test_size)
        n_val = int(n * cfg.val_size)
        train = order[: n - n_test - n_val]
        val = order[n - n_test - n_val : n - n_test]
        test = order[n - n_test :]
        strategy = "chronological"
    else:
        idx = np.arange(n)
        outer = GroupShuffleSplit(n_splits=1, test_size=cfg.test_size, random_state=cfg.seed)
        trainval, test = next(outer.split(idx, data.y, data.groups))
        inner_size = cfg.val_size / (1.0 - cfg.test_size)
        inner = GroupShuffleSplit(n_splits=1, test_size=inner_size, random_state=cfg.seed + 1)
        tr, va = next(inner.split(trainval, data.y[trainval], data.groups[trainval]))
        train, val = trainval[tr], trainval[va]
        strategy = "grouped-by-registered-domain"

    for name, part in (("train", train), ("validation", val), ("test", test)):
        classes = set(np.unique(data.y[part]).tolist())
        if classes != {0, 1}:
            raise ValueError(
                f"The {name} split does not contain both classes; the dataset is too small "
                "or too unbalanced for a meaningful evaluation."
            )
    if strategy.startswith("grouped"):
        overlap = set(data.groups[train]) & set(data.groups[test])
        if overlap:  # pragma: no cover - guaranteed by GroupShuffleSplit
            raise RuntimeError("Domain leakage detected between train and test splits.")
    return Split(train=train, val=val, test=test, strategy=strategy)


def candidate_models(seed: int) -> dict[str, Any]:
    return {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed)),
            ]
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        ),
    }


def train(cfg: TrainingConfig) -> tuple[Path, ModelMetadata]:
    raw = load_labelled_csv(cfg.dataset_path, cfg.url_col, cfg.label_col, cfg.phishing_value, cfg.time_col)
    if cfg.max_rows and len(raw) > cfg.max_rows:
        raw = raw.sample(n=cfg.max_rows, random_state=cfg.seed)
    cleaned, clean_report = clean(raw, cfg.assume_scheme)
    data = featurize(cleaned)

    if len(data.y) < MIN_ROWS or min(data.y.sum(), len(data.y) - data.y.sum()) < MIN_PER_CLASS:
        raise ValueError(
            f"Not enough usable data to train: {len(data.y)} rows "
            f"({int(data.y.sum())} phishing). Need at least {MIN_ROWS} rows and {MIN_PER_CLASS} per class."
        )

    split = split_dataset(data, cfg)
    X, y = data.X, data.y

    results: dict[str, dict[str, object]] = {}
    fitted: dict[str, Any] = {}
    for name, model in candidate_models(cfg.seed).items():
        model.fit(X.iloc[split.train], y[split.train])
        val_scores = model.predict_proba(X.iloc[split.val])[:, 1]
        ap = float(average_precision_score(y[split.val], val_scores))
        results[name] = {"validation_average_precision": round(ap, 4)}
        fitted[name] = model
        logger.info("%s validation AP=%.4f", name, ap)

    best_name = max(results, key=lambda k: results[k]["validation_average_precision"])  # type: ignore[arg-type,return-value]
    best = fitted[best_name]

    val_scores = best.predict_proba(X.iloc[split.val])[:, 1]
    threshold, strategy = choose_threshold(y[split.val], val_scores, cfg.target_precision)
    test_scores = best.predict_proba(X.iloc[split.test])[:, 1]

    metrics = {
        "validation": compute_metrics(y[split.val], val_scores, threshold),
        "test": compute_metrics(y[split.test], test_scores, threshold),
    }

    now = datetime.now(UTC)
    version = f"pg-{best_name.replace('_', '')}-{now.strftime('%Y%m%d%H%M%S')}"
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = cfg.output_dir / f"{version}.joblib"
    joblib.dump(best, model_path)

    metadata = ModelMetadata(
        model_version=version,
        created_at=now.isoformat(timespec="seconds"),
        algorithm=best_name,
        feature_names=list(NUMERIC_FEATURE_NAMES),
        feature_set_version=feature_set_version(),
        threshold=round(threshold, 6),
        threshold_strategy=strategy,
        artifact_sha256=sha256_file(model_path),
        calibrated=False,
        random_seed=cfg.seed,
        dataset={
            "name": cfg.dataset_name,
            "source": cfg.dataset_source,
            "license": cfg.dataset_license,
            "file": cfg.dataset_path.name,
            "file_sha256": sha256_file(cfg.dataset_path),
            "cleaning": clean_report,
            "featurization": data.report,
        },
        split={
            "strategy": split.strategy,
            "train": len(split.train),
            "validation": len(split.val),
            "test": len(split.test),
            "test_positive_rate": round(float(y[split.test].mean()), 4),
        },
        metrics=metrics,
        candidates=results,
        environment={
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    )
    metadata.save(metadata_path_for(model_path))
    return model_path, metadata
