# Datasets

This folder holds training data. **Nothing here is committed** (see `.gitignore`), and PhishGuard never downloads data automatically.

Suggested layout:

```
datasets/
├── raw/                         # files exactly as downloaded
│   └── PhiUSIIL_Phishing_URL_Dataset.csv
├── phiusiil.csv                 # output of scripts/prepare_dataset.py (url,label; 1 = phishing)
└── phiusiil.provenance.json     # source, licence, input hashes, counts
```

## Getting the recommended dataset

1. Open https://archive.ics.uci.edu/dataset/967 (PhiUSIIL Phishing URL Dataset, CC BY 4.0).
2. Download the ZIP and extract `PhiUSIIL_Phishing_URL_Dataset.csv` into `datasets/raw/`.
3. Convert it (note: in this dataset **label 0 means phishing**):

```powershell
python scripts\prepare_dataset.py --input datasets\raw\PhiUSIIL_Phishing_URL_Dataset.csv `
    --url-col URL --label-col label --phishing-value 0 `
    --source-name "PhiUSIIL Phishing URL Dataset" --license "CC BY 4.0" `
    --source-url https://archive.ics.uci.edu/dataset/967 --output datasets\phiusiil.csv
```

Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning.* Computers & Security 136, 103545. Dataset: UCI Machine Learning Repository.

See `docs/dataset_and_model.md` for alternatives, known biases and the full training procedure.

## Handling rules

* Treat phishing URLs as live hazards: never open them in a browser.
* Keep licence and source information with every file (the provenance JSON does this).
* Do not share prepared datasets unless the source licence allows it.
