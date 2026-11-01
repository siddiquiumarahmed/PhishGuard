# Dataset and model

**No model ships with PhishGuard, and no accuracy figures are claimed.** The pipeline is implemented and tested on synthetic data; you train a real model by supplying a legitimate dataset. Until then the application runs on rules (and any configured reputation services) and reports that the ML component was not used.

## Recommended dataset

**PhiUSIIL Phishing URL Dataset** (Prasad & Chandra, 2024), UCI Machine Learning Repository, dataset 967.

* Licence: Creative Commons Attribution 4.0 (CC BY 4.0). Attribution is required if you redistribute derived work.
* Size: 235,795 URLs (134,850 legitimate, 100,945 phishing).
* File: `PhiUSIIL_Phishing_URL_Dataset.csv`; URL column `URL`, label column `label`.
* **Label convention: `1` = legitimate, `0` = phishing.** Pass `--phishing-value 0` when preparing it.
* Known bias: legitimate URLs are mostly site home pages while phishing URLs often have paths, so URL length and path depth separate the classes more easily than in real traffic. Expect lower performance on real-world links than on the held-out split.

Download it manually from https://archive.ics.uci.edu/dataset/967 and place the CSV in `datasets/raw/`. PhishGuard never downloads data itself.

### Alternatives

* **PhishTank** verified-online feed (phishing only; requires accepting PhishTank's terms) combined with legitimate URLs you collect yourself.
* **OpenPhish** community feed (phishing only; check its terms).
* Legitimate URLs: build them from your own browsing history exports or a site list such as Tranco. Domain lists produce home-page-only URLs, which reintroduces the bias above, so prefer real page URLs.

Record where every file came from; `prepare_dataset.py` writes a provenance file next to its output.

## Preparing data

```powershell
python scripts\prepare_dataset.py --input datasets\raw\PhiUSIIL_Phishing_URL_Dataset.csv `
    --url-col URL --label-col label --phishing-value 0 `
    --source-name "PhiUSIIL Phishing URL Dataset" --license "CC BY 4.0" `
    --source-url https://archive.ics.uci.edu/dataset/967 --output datasets\phiusiil.csv
```

Or from two text files (one URL per line):

```powershell
python scripts\prepare_dataset.py --phishing-list datasets\raw\phish.txt --benign-list datasets\raw\benign.txt `
    --source-name "My collection 2026-10" --license "internal" --output datasets\combined.csv
```

The output is `url,label` with `1 = phishing`, plus `<name>.provenance.json` (source, licence, input hashes, row counts).

## Training

```powershell
python scripts\train_model.py --dataset datasets\phiusiil.csv
```

Add `--max-rows 40000` for a quicker first run. Feature extraction is pure Python and processes very roughly a few thousand URLs per second, so the full PhiUSIIL file takes minutes.

What the pipeline does (`phishguard/ml/train.py`):

1. **Cleaning** (`preprocessing.clean`): trims, drops empty rows and exact duplicates, removes URLs labelled both ways, adds `http://` to scheme-less rows (training only; the scanner never guesses schemes).
2. **Features**: the scan-time `extract_features()` produces the 47-feature vector. Rows the parser rejects are dropped and counted by reason.
3. **Leakage-resistant split**: 70 / 15 / 15 using `GroupShuffleSplit` grouped by **registered domain**, so no domain appears in both training and evaluation data. If a timestamp column is supplied (`--time-col`), a **chronological** split is used instead (train on older data, test on newer). Random row-level splits are not used.
4. **Class imbalance**: `class_weight="balanced"` (logistic regression) and `"balanced_subsample"` (random forest).
5. **Model selection**: both baselines are trained; the one with the higher **validation** average precision is kept.
6. **Threshold**: chosen on the validation split as the threshold with the highest recall whose precision is at least `--target-precision` (default 0.95); if unreachable, the F1-maximising threshold. The test split is not used for any decision.
7. **Evaluation**: precision, recall, F1, false-positive rate, confusion matrix, average precision (PR-AUC), ROC-AUC and a sampled precision-recall curve, for validation and test splits.
8. **Artifacts**: `ml_artifacts/<version>.joblib` and `<version>.json` with version, timestamp, algorithm, feature names, feature-set version, threshold and strategy, SHA-256 of the artifact, dataset name/licence/source/file hash, cleaning report, split sizes, metrics, candidates, random seed and library versions.

Seeds are fixed (`--seed`, default 42), so the same data and environment reproduce the same model and metrics.

## Using the model

```text
ML_MODEL_PATH=ml_artifacts/<version>.joblib
```

Restart PhishGuard. Before loading, the app checks that the metadata exists, that the feature-set version matches the running code, and that the artifact's SHA-256 matches the metadata. Any failure leaves the scanner running on rules, and the scan report shows why the model was not used.

The score shown is the classifier's `predict_proba` output. It is **not calibrated** and is labelled "uncalibrated model score, not a probability". The model alone can raise a verdict to *Suspicious* at most and never lowers a rule-based verdict.

## Re-evaluating and retraining

Evaluate on newer data the model has not seen:

```powershell
python scripts\evaluate_model.py --model ml_artifacts\<version>.joblib --dataset datasets\newer.csv --report reports\eval.json
```

Retrain when performance on newer data drops, when the feature extractor changes (the app refuses models with a different feature-set version), or when you add data. Keep old artifacts and their JSON for comparison; never load a `.joblib` from an untrusted source, because joblib files can execute code when loaded.

## Interpreting results honestly

* Test-split numbers describe *this dataset*, not the internet.
* A domain-grouped split is harder than a random split; expect lower, more realistic numbers.
* Report the dataset, split strategy and threshold together with any figure you quote.
