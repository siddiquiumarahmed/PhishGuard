"""Evaluate a trained PhishGuard model on another labelled dataset.

Use data the model has not seen - ideally collected *after* the training data -
to measure how performance holds up over time:

    python scripts/evaluate_model.py --model ml_artifacts/<version>.joblib --dataset datasets/newer.csv

The model's integrity (SHA-256) and feature-set version are verified before it
is loaded, exactly as the web application does.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from phishguard.detector.url_features import NUMERIC_FEATURE_NAMES
from phishguard.ml.evaluate import compute_metrics, format_report
from phishguard.ml.predict import MLStatus, ModelPredictor
from phishguard.ml.preprocessing import clean, featurize, load_labelled_csv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--url-col", default="url")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--phishing-value", default="1")
    parser.add_argument("--report", type=Path, default=None, help="Optional JSON output path")
    args = parser.parse_args(argv)

    predictor = ModelPredictor(args.model)
    status = predictor.status()
    if status.status != MLStatus.OK:
        print(f"Model unavailable: {status.detail}", file=sys.stderr)
        return 1
    loaded = predictor.loaded_model()
    if loaded is None:
        print("Model could not be loaded.", file=sys.stderr)
        return 1
    model, meta = loaded

    frame, report = clean(load_labelled_csv(args.dataset, args.url_col, args.label_col, args.phishing_value))
    data = featurize(frame)
    if len(np.unique(data.y)) < 2:
        print("The evaluation dataset must contain both phishing and legitimate URLs.", file=sys.stderr)
        return 1
    scores = model.predict_proba(data.X[list(NUMERIC_FEATURE_NAMES)])[:, 1]
    metrics = compute_metrics(data.y, scores, meta.threshold)

    print(f"Model {meta.model_version} on {args.dataset.name}")
    print(format_report(metrics, "Evaluation"))
    print("Note: if this dataset overlaps the training data (same source or period), these numbers are optimistic.")
    if args.report:
        args.report.write_text(
            json.dumps(
                {
                    "model_version": meta.model_version,
                    "dataset": args.dataset.name,
                    "cleaning": report,
                    "featurization": data.report,
                    "metrics": metrics,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
