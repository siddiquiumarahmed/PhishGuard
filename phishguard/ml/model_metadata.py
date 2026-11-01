"""Model metadata: versioning, provenance and integrity information.

Every trained artifact ``<name>.joblib`` is accompanied by ``<name>.json``
containing the metadata below. The SHA-256 of the artifact is checked before
loading, and the feature-set version must match the running code, otherwise
the model is refused (feature drift between training and inference would
silently produce meaningless scores).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from phishguard.detector.url_features import NUMERIC_FEATURE_NAMES

METADATA_SCHEMA_VERSION = 1


def feature_set_version() -> str:
    """Stable identifier of the feature vector layout used by the code."""
    digest = hashlib.sha256("|".join(NUMERIC_FEATURE_NAMES).encode("utf-8")).hexdigest()
    return f"fs-{digest[:12]}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def metadata_path_for(model_path: Path) -> Path:
    return model_path.with_suffix(".json")


@dataclass
class ModelMetadata:
    model_version: str
    created_at: str
    algorithm: str
    feature_names: list[str]
    feature_set_version: str
    threshold: float
    threshold_strategy: str
    artifact_sha256: str
    calibrated: bool = False
    random_seed: int = 42
    dataset: dict[str, object] = field(default_factory=dict)
    split: dict[str, object] = field(default_factory=dict)
    metrics: dict[str, object] = field(default_factory=dict)
    candidates: dict[str, object] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)
    schema_version: int = METADATA_SCHEMA_VERSION

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> ModelMetadata:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Model metadata must be a JSON object.")
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})
