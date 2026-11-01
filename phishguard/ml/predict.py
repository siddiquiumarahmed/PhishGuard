"""Model inference with safe fallback.

The model is optional. If the configured artifact is missing, fails its
integrity check, was trained on a different feature layout, or raises during
prediction, an :class:`MLResult` with a non-OK status is returned and scanning
continues with rule-based detection.

Security note: joblib artifacts are pickles and can execute code when loaded.
PhishGuard only loads artifacts from the local path configured by the operator
and verifies their SHA-256 against the metadata file written at training time.
Never place model files from untrusted sources in ``ml_artifacts/``.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import joblib

from phishguard.detector.url_features import NUMERIC_FEATURE_NAMES, URLFeatures
from phishguard.ml.model_metadata import ModelMetadata, feature_set_version, metadata_path_for, sha256_file

logger = logging.getLogger(__name__)


class MLStatus(StrEnum):
    OK = "ok"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass
class MLResult:
    status: MLStatus
    score: float | None = None
    threshold: float | None = None
    flagged: bool = False
    model_version: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "score": None if self.score is None else round(self.score, 4),
            "threshold": None if self.threshold is None else round(self.threshold, 4),
            "flagged": self.flagged,
            "model_version": self.model_version,
            "detail": self.detail,
            "score_label": "Uncalibrated model score (0–1), not a probability",
        }


@dataclass
class _Loaded:
    model: Any
    metadata: ModelMetadata
    mtime: float


class ModelPredictor:
    """Lazily loads and caches one model artifact. Thread-safe."""

    def __init__(self, model_path: str | Path | None, enabled: bool = True) -> None:
        self.model_path = Path(model_path) if model_path else None
        self.enabled = enabled
        self._loaded: _Loaded | None = None
        self._failed: tuple[float, MLResult] | None = None
        self._lock = threading.Lock()

    # -- loading -----------------------------------------------------------
    def _load(self) -> _Loaded | MLResult:
        if not self.enabled:
            return MLResult(MLStatus.DISABLED, detail="disabled in configuration")
        if self.model_path is None or not self.model_path.is_file():
            return MLResult(MLStatus.UNAVAILABLE, detail="no trained model found")
        meta_path = metadata_path_for(self.model_path)
        if not meta_path.is_file():
            return MLResult(MLStatus.UNAVAILABLE, detail="model metadata file missing")

        mtime = self.model_path.stat().st_mtime
        with self._lock:
            if self._loaded and self._loaded.mtime == mtime:
                return self._loaded
            if self._failed and self._failed[0] == mtime:
                return self._failed[1]
            outcome = self._load_artifact(self.model_path, meta_path, mtime)
            if isinstance(outcome, MLResult):
                self._failed = (mtime, outcome)
            else:
                self._loaded = outcome
                self._failed = None
            return outcome

    @staticmethod
    def _load_artifact(model_path: Path, meta_path: Path, mtime: float) -> _Loaded | MLResult:
        try:
            metadata = ModelMetadata.load(meta_path)
        except (ValueError, TypeError, OSError):
            return MLResult(MLStatus.ERROR, detail="model metadata could not be read")
        if metadata.feature_set_version != feature_set_version():
            return MLResult(
                MLStatus.INCOMPATIBLE,
                model_version=metadata.model_version,
                detail="model was trained with a different feature set; retrain it",
            )
        if sha256_file(model_path) != metadata.artifact_sha256:
            logger.error("Model artifact hash mismatch; refusing to load %s", model_path.name)
            return MLResult(
                MLStatus.ERROR, model_version=metadata.model_version, detail="model file failed its integrity check"
            )
        try:
            # Trusted, integrity-checked local artifact (see module docstring).
            model = joblib.load(model_path)  # nosec B301
        except Exception:
            logger.exception("Failed to load model artifact")
            return MLResult(
                MLStatus.ERROR, model_version=metadata.model_version, detail="model file could not be loaded"
            )
        return _Loaded(model=model, metadata=metadata, mtime=mtime)

    def status(self) -> MLResult:
        loaded = self._load()
        if isinstance(loaded, MLResult):
            return loaded
        return MLResult(
            MLStatus.OK,
            threshold=loaded.metadata.threshold,
            model_version=loaded.metadata.model_version,
            detail="model loaded",
        )

    def metadata(self) -> ModelMetadata | None:
        loaded = self._load()
        return None if isinstance(loaded, MLResult) else loaded.metadata

    def loaded_model(self) -> tuple[Any, ModelMetadata] | None:
        """The verified model and its metadata, or None if unavailable (for offline evaluation)."""
        loaded = self._load()
        return None if isinstance(loaded, MLResult) else (loaded.model, loaded.metadata)

    # -- inference ----------------------------------------------------------
    def predict(self, features: URLFeatures) -> MLResult:
        loaded = self._load()
        if isinstance(loaded, MLResult):
            return loaded
        try:
            import pandas as pd

            row = pd.DataFrame(
                [[features.numeric[n] for n in NUMERIC_FEATURE_NAMES]], columns=list(NUMERIC_FEATURE_NAMES), dtype=float
            )
            score = float(loaded.model.predict_proba(row)[0][1])
        except Exception:
            logger.exception("Model prediction failed")
            return MLResult(MLStatus.ERROR, model_version=loaded.metadata.model_version, detail="prediction failed")
        threshold = float(loaded.metadata.threshold)
        return MLResult(
            MLStatus.OK,
            score=score,
            threshold=threshold,
            flagged=score >= threshold,
            model_version=loaded.metadata.model_version,
            detail="model prediction",
        )
