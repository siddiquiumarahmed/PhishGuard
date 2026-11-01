"""Dataset loading, cleaning and feature extraction for model training.

The *same* :func:`phishguard.detector.url_features.extract_features` used at
scan time produces the training matrix, so there is a single feature
implementation.

Expected input: a CSV with at least a URL column and a label column. Column
names and the value meaning "phishing" are configurable because public
datasets disagree (PhiUSIIL, for example, uses ``label = 0`` for phishing).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from phishguard.detector.url_features import NUMERIC_FEATURE_NAMES, extract_features
from phishguard.detector.url_parser import URLValidationError, parse_url

TRAINING_MAX_URL_LENGTH = 8192


@dataclass
class PreparedDataset:
    X: pd.DataFrame
    y: np.ndarray
    groups: np.ndarray
    times: pd.Series | None
    urls: pd.Series
    report: dict[str, object] = field(default_factory=dict)


def load_labelled_csv(
    path: Path,
    url_col: str = "url",
    label_col: str = "label",
    phishing_value: str = "1",
    time_col: str | None = None,
) -> pd.DataFrame:
    """Load a CSV into a frame with columns ``url``, ``label`` (1 = phishing) and optional ``time``."""
    frame = pd.read_csv(path, dtype=str, keep_default_na=False, on_bad_lines="skip")
    missing = [c for c in (url_col, label_col, time_col) if c and c not in frame.columns]
    if missing:
        raise ValueError(
            f"Column(s) not found in dataset: {', '.join(missing)}. "
            f"Available: {', '.join(map(str, frame.columns[:30]))}"
        )
    out = pd.DataFrame(
        {
            "url": frame[url_col].astype(str),
            "label": (frame[label_col].astype(str).str.strip() == str(phishing_value)).astype(int),
        }
    )
    if time_col:
        out["time"] = pd.to_datetime(frame[time_col], errors="coerce", utc=True)
    return out


def clean(frame: pd.DataFrame, assume_scheme: str | None = "http") -> tuple[pd.DataFrame, dict[str, int]]:
    """Strip, de-duplicate and drop label conflicts. Returns the frame and a report."""
    report: dict[str, int] = {"rows_in": len(frame)}
    frame = frame.copy()
    frame["url"] = frame["url"].str.strip()
    frame = frame[frame["url"] != ""]
    report["dropped_empty"] = report["rows_in"] - len(frame)

    if assume_scheme:
        no_scheme = ~frame["url"].str.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
        frame.loc[no_scheme, "url"] = assume_scheme + "://" + frame.loc[no_scheme, "url"]
        report["scheme_added"] = int(no_scheme.sum())

    before = len(frame)
    frame = frame.drop_duplicates(subset=["url", "label"])
    report["dropped_duplicates"] = before - len(frame)

    conflicted = frame.groupby("url")["label"].nunique()
    conflict_urls = set(conflicted[conflicted > 1].index)
    before = len(frame)
    frame = frame[~frame["url"].isin(conflict_urls)]
    report["dropped_label_conflicts"] = before - len(frame)
    report["rows_out"] = len(frame)
    return frame.reset_index(drop=True), report


def featurize(frame: pd.DataFrame) -> PreparedDataset:
    """Parse each URL and extract numeric features; unparseable rows are dropped and counted."""
    rows: list[list[float]] = []
    labels: list[int] = []
    groups: list[str] = []
    urls: list[str] = []
    times: list[object] = []
    rejected: dict[str, int] = {}
    has_time = "time" in frame.columns

    for record in frame.itertuples(index=False):
        try:
            parsed = parse_url(record.url, max_length=TRAINING_MAX_URL_LENGTH)
        except URLValidationError as exc:
            rejected[exc.code] = rejected.get(exc.code, 0) + 1
            continue
        features = extract_features(parsed)
        rows.append([features.numeric[n] for n in NUMERIC_FEATURE_NAMES])
        labels.append(int(record.label))
        groups.append(parsed.registrable_domain or parsed.host_ascii)
        urls.append(parsed.normalized)
        if has_time:
            times.append(record.time)

    X = pd.DataFrame(rows, columns=list(NUMERIC_FEATURE_NAMES), dtype=float)
    y = np.asarray(labels, dtype=int)
    report: dict[str, object] = {
        "featurized_rows": len(X),
        "rejected_by_parser": rejected,
        "phishing": int(y.sum()),
        "legitimate": int(len(y) - y.sum()),
        "distinct_domains": len(set(groups)),
    }
    return PreparedDataset(
        X=X,
        y=y,
        groups=np.asarray(groups),
        times=pd.Series(times) if has_time else None,
        urls=pd.Series(urls),
        report=report,
    )
