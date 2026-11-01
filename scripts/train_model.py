"""Train and evaluate a PhishGuard URL classifier.

Example (after preparing data, see datasets/README.md):

    python scripts/train_model.py --dataset datasets/phiusiil.csv \
        --dataset-name "PhiUSIIL Phishing URL Dataset" --license "CC BY 4.0" \
        --source https://archive.ics.uci.edu/dataset/967

The metrics printed are computed on a held-out, domain-disjoint test split of
*your* dataset. They describe performance on that dataset only and will not
transfer unchanged to real-world traffic.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishguard.ml.evaluate import format_report
from phishguard.ml.train import TrainingConfig, train


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", type=Path, required=True, help="CSV with url,label columns")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "ml_artifacts")
    parser.add_argument("--url-col", default="url")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--phishing-value", default="1")
    parser.add_argument("--time-col", default=None, help="Optional timestamp column for a chronological split")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--target-precision", type=float, default=0.95)
    parser.add_argument("--max-rows", type=int, default=None, help="Optional random subsample (for quick runs)")
    parser.add_argument("--dataset-name", default="unspecified")
    parser.add_argument("--license", default="unspecified")
    parser.add_argument("--source", default="unspecified")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not args.dataset.is_file():
        print(f"Dataset not found: {args.dataset}. See datasets/README.md.", file=sys.stderr)
        return 2

    provenance = args.dataset.with_suffix(".provenance.json")
    name, license_, source = args.dataset_name, args.license, args.source
    if provenance.is_file() and name == "unspecified":
        prov = json.loads(provenance.read_text(encoding="utf-8"))
        name, license_, source = prov.get("name", name), prov.get("license", license_), prov.get("source_url", source)

    cfg = TrainingConfig(
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        url_col=args.url_col,
        label_col=args.label_col,
        phishing_value=args.phishing_value,
        time_col=args.time_col,
        seed=args.seed,
        target_precision=args.target_precision,
        dataset_name=name,
        dataset_license=license_,
        dataset_source=source,
        max_rows=args.max_rows,
    )
    try:
        model_path, meta = train(cfg)
    except ValueError as exc:
        print(f"Training failed: {exc}", file=sys.stderr)
        return 1

    print()
    print(f"Model: {meta.model_version} ({meta.algorithm}), split: {meta.split['strategy']}")
    print(f"Candidates (validation average precision): {meta.candidates}")
    print(format_report(meta.metrics["validation"], "Validation (threshold chosen here)"))  # type: ignore[arg-type]
    print()
    print(format_report(meta.metrics["test"], "Held-out test split"))  # type: ignore[arg-type]
    print()
    print(f"Saved {model_path}")
    try:
        shown = model_path.relative_to(ROOT)
    except ValueError:
        shown = model_path
    print(f"To use it, set ML_MODEL_PATH={shown.as_posix()} in .env and restart PhishGuard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
