"""ML pipeline tests on a small *synthetic* dataset.

These tests check that the pipeline runs end to end, prevents domain leakage,
records metadata and degrades safely. The synthetic data is trivially
separable, so any metrics produced here say nothing about real-world accuracy.
"""

from __future__ import annotations

import json
import random

import numpy as np
import pandas as pd
import pytest

from phishguard.detector.url_features import extract_features
from phishguard.detector.url_parser import parse_url
from phishguard.ml.evaluate import choose_threshold, compute_metrics
from phishguard.ml.model_metadata import ModelMetadata, feature_set_version, metadata_path_for
from phishguard.ml.predict import MLStatus, ModelPredictor
from phishguard.ml.preprocessing import clean, featurize, load_labelled_csv
from phishguard.ml.train import TrainingConfig, split_dataset, train

WORDS = [
    "alpha",
    "harbor",
    "maple",
    "orbit",
    "quartz",
    "willow",
    "cobalt",
    "ember",
    "summit",
    "tundra",
    "violet",
    "zephyr",
    "bramble",
    "canyon",
    "delta",
    "fable",
    "glacier",
    "lumen",
    "nectar",
    "prairie",
]
BRANDS = ["paypal", "microsoft", "netflix", "amazon", "apple"]


def synthetic_rows(n_domains: int = 120, seed: int = 7) -> list[tuple[str, int, str]]:
    rng = random.Random(seed)
    rows = []
    for i in range(n_domains):
        word = rng.choice(WORDS)
        domain = f"{word}{i}.example"
        for page in ("", "about", f"blog/{rng.randint(1, 999)}"):
            rows.append((f"https://www.{domain}/{page}", 0, f"2026-0{1 + i % 6}-01"))
        brand = rng.choice(BRANDS)
        bad = f"{brand}-secure-{rng.choice(['login', 'verify', 'update'])}{i}.test"
        for path in ("signin", "account/verify", "webscr?cmd=_login"):
            rows.append((f"http://{brand}.com.{bad}/{path}", 1, f"2026-0{1 + i % 6}-15"))
    return rows


@pytest.fixture()
def dataset(tmp_path):
    path = tmp_path / "synthetic.csv"
    pd.DataFrame(synthetic_rows(), columns=["url", "label", "seen"]).to_csv(path, index=False)
    return path


@pytest.fixture()
def trained(tmp_path, dataset):
    cfg = TrainingConfig(
        dataset_path=dataset,
        output_dir=tmp_path / "artifacts",
        dataset_name="synthetic-test",
        dataset_license="test-only",
        dataset_source="generated in tests",
        seed=1,
    )
    return train(cfg)


def test_load_respects_label_convention(dataset, tmp_path):
    frame = load_labelled_csv(dataset)
    assert set(frame["label"]) == {0, 1}
    flipped = load_labelled_csv(dataset, phishing_value="0")
    assert (flipped["label"] == 1 - frame["label"]).all()
    with pytest.raises(ValueError, match="Column"):
        load_labelled_csv(dataset, url_col="URL")


def test_clean_removes_duplicates_conflicts_and_adds_scheme():
    frame = pd.DataFrame(
        {
            "url": [
                "example.com/a",
                "http://example.com/a",
                "https://x.example/",
                "https://x.example/",
                " ",
                "https://c.example/",
            ],
            "label": [0, 0, 1, 1, 0, 1],
        }
    )
    frame = pd.concat([frame, pd.DataFrame({"url": ["https://c.example/"], "label": [0]})])
    cleaned, report = clean(frame)
    assert report["scheme_added"] == 1
    assert report["dropped_duplicates"] == 2
    assert report["dropped_label_conflicts"] == 2
    assert "https://c.example/" not in set(cleaned["url"])


def test_featurize_uses_scan_time_features_and_drops_invalid():
    urls = ["https://ok.example/", "ftp://bad.example/", "http://999.1.1.1/"]
    frame = pd.DataFrame({"url": urls, "label": [0, 1, 1]})
    data = featurize(frame)
    assert len(data.X) == 1
    assert data.report["rejected_by_parser"] == {"unsupported_scheme": 1, "invalid_ip": 1}
    expected = extract_features(parse_url("https://ok.example/")).numeric
    assert list(data.X.iloc[0]) == list(expected.values())


def test_grouped_split_has_no_domain_overlap(dataset, tmp_path):
    cleaned, _ = clean(load_labelled_csv(dataset))
    data = featurize(cleaned)
    split = split_dataset(data, TrainingConfig(dataset_path=dataset, output_dir=tmp_path))
    assert split.strategy == "grouped-by-registered-domain"
    groups = data.groups
    assert not set(groups[split.train]) & set(groups[split.test])
    assert not set(groups[split.train]) & set(groups[split.val])
    assert len(split.train) + len(split.val) + len(split.test) == len(data.y)


def test_chronological_split_when_time_column_given(dataset, tmp_path):
    cleaned, _ = clean(load_labelled_csv(dataset, time_col="seen"))
    data = featurize(cleaned)
    split = split_dataset(data, TrainingConfig(dataset_path=dataset, output_dir=tmp_path, time_col="seen"))
    assert split.strategy == "chronological"
    assert data.times[split.train].max() <= data.times[split.test].min()


def test_training_produces_versioned_artifact_and_metadata(trained):
    model_path, meta = trained
    assert model_path.is_file() and metadata_path_for(model_path).is_file()
    loaded = ModelMetadata.load(metadata_path_for(model_path))
    assert loaded.model_version == meta.model_version
    assert loaded.feature_set_version == feature_set_version()
    assert loaded.calibrated is False
    assert loaded.dataset["name"] == "synthetic-test" and loaded.dataset["license"] == "test-only"
    assert loaded.split["strategy"] == "grouped-by-registered-domain"
    assert 0.0 <= loaded.threshold <= 1.0
    for part in ("validation", "test"):
        m = loaded.metrics[part]
        assert {"precision", "recall", "f1", "confusion_matrix", "average_precision", "pr_curve"} <= set(m)
    assert set(loaded.candidates) == {"logistic_regression", "random_forest"}


def test_training_is_reproducible(tmp_path, dataset):
    cfg = {"dataset_path": dataset, "dataset_name": "s", "seed": 3}
    _, a = train(TrainingConfig(output_dir=tmp_path / "a", **cfg))
    _, b = train(TrainingConfig(output_dir=tmp_path / "b", **cfg))
    assert a.metrics["test"]["confusion_matrix"] == b.metrics["test"]["confusion_matrix"]
    assert a.threshold == b.threshold


def test_predictor_end_to_end(trained):
    model_path, _ = trained
    predictor = ModelPredictor(model_path)
    assert predictor.status().status == MLStatus.OK
    result = predictor.predict(extract_features(parse_url("http://paypal.com.paypal-secure-login9.test/signin")))
    assert result.status == MLStatus.OK and 0.0 <= result.score <= 1.0
    assert result.model_version and result.to_dict()["score_label"].startswith("Uncalibrated")


def test_missing_model_is_unavailable(tmp_path):
    assert ModelPredictor(None).status().status == MLStatus.UNAVAILABLE
    assert (
        ModelPredictor(tmp_path / "nope.joblib").predict(extract_features(parse_url("https://example.com/"))).status
        == MLStatus.UNAVAILABLE
    )


def test_disabled_model(trained):
    assert ModelPredictor(trained[0], enabled=False).status().status == MLStatus.DISABLED


def test_tampered_model_is_refused(trained):
    model_path, _ = trained
    with model_path.open("ab") as fh:
        fh.write(b"tamper")
    result = ModelPredictor(model_path).status()
    assert result.status == MLStatus.ERROR and "integrity" in result.detail


def test_feature_set_mismatch_is_refused(trained):
    model_path, _ = trained
    meta_path = metadata_path_for(model_path)
    data = json.loads(meta_path.read_text())
    data["feature_set_version"] = "fs-old"
    meta_path.write_text(json.dumps(data))
    assert ModelPredictor(model_path).status().status == MLStatus.INCOMPATIBLE


def test_missing_metadata(trained):
    model_path, _ = trained
    metadata_path_for(model_path).unlink()
    assert ModelPredictor(model_path).status().status == MLStatus.UNAVAILABLE


def test_too_small_dataset_rejected(tmp_path):
    path = tmp_path / "tiny.csv"
    pd.DataFrame({"url": ["https://a.example/", "https://b.example/"], "label": [0, 1]}).to_csv(path, index=False)
    with pytest.raises(ValueError, match="Not enough"):
        train(TrainingConfig(dataset_path=path, output_dir=tmp_path))


def test_threshold_selection_and_metrics():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.6, 0.55, 0.7, 0.8, 0.9])
    threshold, strategy = choose_threshold(y, scores, target_precision=1.0)
    assert threshold == pytest.approx(0.7) and strategy.startswith("max-recall")
    m = compute_metrics(y, scores, threshold)
    assert m["precision"] == 1.0 and m["recall"] == 0.75
    assert m["confusion_matrix"] == {"tn": 4, "fp": 0, "fn": 1, "tp": 3}
