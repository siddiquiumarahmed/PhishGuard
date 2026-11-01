"""Convert raw phishing/benign data into PhishGuard's training format.

Output: a CSV with columns ``url,label`` (label 1 = phishing, 0 = legitimate)
plus a ``<output>.provenance.json`` file recording where the data came from.

Two input modes:

1. A labelled CSV (e.g. PhiUSIIL)::

       python scripts/prepare_dataset.py --input datasets/raw/PhiUSIIL_Phishing_URL_Dataset.csv \
           --url-col URL --label-col label --phishing-value 0 \
           --source-name "PhiUSIIL Phishing URL Dataset" --license "CC BY 4.0" \
           --source-url https://archive.ics.uci.edu/dataset/967 --output datasets/phiusiil.csv

2. Two plain-text lists, one URL per line::

       python scripts/prepare_dataset.py --phishing-list datasets/raw/phish.txt \
           --benign-list datasets/raw/benign.txt --source-name "..." --license "..." \
           --output datasets/combined.csv

No network access is performed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_list(path: Path) -> list[str]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, help="Labelled CSV file")
    parser.add_argument("--url-col", default="url")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--phishing-value", default="1", help="Label value meaning phishing (PhiUSIIL: 0)")
    parser.add_argument("--phishing-list", type=Path, help="Text file of phishing URLs")
    parser.add_argument("--benign-list", type=Path, help="Text file of legitimate URLs")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-name", required=True, help="Dataset name, for provenance")
    parser.add_argument("--license", required=True, help="Dataset licence, for provenance")
    parser.add_argument("--source-url", default="", help="Where the data was obtained")
    args = parser.parse_args(argv)

    rows: list[tuple[str, int]] = []
    inputs: list[dict[str, str]] = []
    if args.input:
        import pandas as pd

        from phishguard.ml.preprocessing import load_labelled_csv

        frame: pd.DataFrame = load_labelled_csv(args.input, args.url_col, args.label_col, args.phishing_value)
        rows.extend(zip(frame["url"].tolist(), frame["label"].astype(int).tolist(), strict=True))
        inputs.append({"file": args.input.name, "sha256": _sha256(args.input)})
    elif args.phishing_list and args.benign_list:
        rows.extend((u, 1) for u in _read_list(args.phishing_list))
        rows.extend((u, 0) for u in _read_list(args.benign_list))
        for p in (args.phishing_list, args.benign_list):
            inputs.append({"file": p.name, "sha256": _sha256(p)})
    else:
        parser.error("Provide --input, or both --phishing-list and --benign-list.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    phishing = sum(label for _, label in rows)
    provenance = {
        "name": args.source_name,
        "license": args.license,
        "source_url": args.source_url,
        "prepared_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "inputs": inputs,
        "rows": len(rows),
        "phishing": phishing,
        "legitimate": len(rows) - phishing,
        "label_convention": "1 = phishing, 0 = legitimate",
        "output_sha256": _sha256(args.output),
    }
    prov_path = args.output.with_suffix(".provenance.json")
    prov_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"Wrote {len(rows)} rows ({phishing} phishing) to {args.output}")
    print(f"Provenance: {prov_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
