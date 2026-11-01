# Model artifacts

`scripts/train_model.py` writes trained models here:

```
ml_artifacts/
├── pg-randomforest-20261020120000.joblib   # the model (a pickle; trusted local files only)
└── pg-randomforest-20261020120000.json     # metadata: metrics, threshold, dataset, SHA-256, feature set
```

To use a model, set `ML_MODEL_PATH=ml_artifacts/<name>.joblib` in `.env` and restart PhishGuard.

Before loading, PhishGuard verifies that the JSON exists, that its `feature_set_version` matches the running code, and that the `.joblib` SHA-256 matches `artifact_sha256`. If any check fails, scanning continues without the model and the report says why.

**Never place a `.joblib` file from an untrusted source here.** Loading a joblib/pickle file can execute arbitrary code.

No model is included with PhishGuard, and none of its documentation claims accuracy figures. Metrics for a model you train are in its JSON file.
