"""Versioned severity-model checkpoints.

Train writes a candidate under models/checkpoints/<id>/ and leaves the live
artifacts alone. Activate copies a checkpoint onto the files triage loads.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ARTIFACTS = (
    "soc_model.pkl",
    "vectorizer.pkl",
    "scaler.pkl",
    "label_encoder.pkl",
)

REPO_ROOT = Path(__file__).resolve().parent


def artifact_root() -> Path:
    raw = (os.environ.get("SOC_MODEL_ROOT") or "").strip()
    return Path(raw) if raw else REPO_ROOT


def checkpoint_root() -> Path:
    return artifact_root() / "models" / "checkpoints"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _new_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _active_path() -> Path:
    return artifact_root() / "models" / "active.json"


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _checkpoint_dir(checkpoint_id: str) -> Path:
    return checkpoint_root() / checkpoint_id


def _meta_path(checkpoint_id: str) -> Path:
    return _checkpoint_dir(checkpoint_id) / "meta.json"


def list_checkpoints() -> list:
    root = checkpoint_root()
    if not root.is_dir():
        return []
    found = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        meta = _read_json(child / "meta.json") or {"id": child.name}
        meta.setdefault("id", child.name)
        found.append(meta)
    found.sort(key=lambda row: str(row.get("created_at") or row.get("id") or ""))
    return found


def latest_checkpoint() -> Optional[Dict[str, Any]]:
    rows = list_checkpoints()
    return rows[-1] if rows else None


def active_checkpoint() -> Optional[Dict[str, Any]]:
    meta = _read_json(_active_path())
    if meta:
        return meta
    live = artifact_root() / "soc_model.pkl"
    if live.is_file():
        stamp = datetime.fromtimestamp(live.stat().st_mtime, timezone.utc).replace(microsecond=0)
        text = stamp.isoformat()
        return {"id": "shipped", "created_at": text, "activated_at": text}
    return None


def _brief(meta: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    if not meta:
        return None
    name = str(meta.get("id") or "")
    timestamp = str(meta.get("activated_at") or meta.get("created_at") or "")
    if not name and not timestamp:
        return None
    return {"name": name, "timestamp": timestamp}


def checkpoint_status() -> Dict[str, Any]:
    return {
        "active": _brief(active_checkpoint()),
        "latest": _brief(latest_checkpoint()),
    }


def _write_meta(checkpoint_id: str, metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    metrics = metrics or {}
    meta = {
        "id": checkpoint_id,
        "created_at": _now(),
        "model": metrics.get("model"),
        "n_samples": metrics.get("n_samples"),
        "cv_macro_f1": metrics.get("cv_macro_f1"),
    }
    _write_json(_meta_path(checkpoint_id), meta)
    return meta


def train_candidate(
    sample_path: str = "data/sample_logs.csv",
    labeled_path: str = "data/labeled_alerts.csv",
) -> Optional[Dict[str, Any]]:
    """Fit a candidate checkpoint. Does not replace the live triage artifacts."""
    from train_model import train_ml_model

    checkpoint_id = _new_id()
    dest = _checkpoint_dir(checkpoint_id)
    dest.mkdir(parents=True, exist_ok=True)
    metrics = train_ml_model(
        sample_path,
        model_file=str(dest / "soc_model.pkl"),
        vectorizer_file=str(dest / "vectorizer.pkl"),
        scaler_file=str(dest / "scaler.pkl"),
        label_encoder_file=str(dest / "label_encoder.pkl"),
        labeled_path=labeled_path,
        combine_labeled=True,
    )
    if not metrics:
        return None
    return _write_meta(checkpoint_id, metrics)


def register_live_as_checkpoint(metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Copy the current live artifacts into a checkpoint and mark it active.

    Used by ``python train_model.py`` so the CLI still leaves usable root files
    and the registry stays in sync.
    """
    checkpoint_id = _new_id()
    dest = _checkpoint_dir(checkpoint_id)
    dest.mkdir(parents=True, exist_ok=True)
    root = artifact_root()
    for name in ARTIFACTS:
        src = root / name
        if not src.is_file():
            raise FileNotFoundError(name)
        shutil.copy2(src, dest / name)
    meta = _write_meta(checkpoint_id, metrics)
    meta["activated_at"] = meta["created_at"]
    _write_json(_meta_path(checkpoint_id), meta)
    _write_json(_active_path(), meta)
    return meta


def activate_checkpoint(checkpoint_id: str, *, reload: bool = True) -> Dict[str, Any]:
    """Promote a trained checkpoint to the artifacts triage loads."""
    checkpoint_id = str(checkpoint_id or "").strip()
    src_dir = _checkpoint_dir(checkpoint_id)
    if not src_dir.is_dir():
        raise FileNotFoundError(checkpoint_id)
    root = artifact_root()
    root.mkdir(parents=True, exist_ok=True)
    for name in ARTIFACTS:
        src = src_dir / name
        if not src.is_file():
            raise FileNotFoundError(name)
        shutil.copy2(src, root / name)
    meta = _read_json(src_dir / "meta.json") or {"id": checkpoint_id, "created_at": _now()}
    meta["id"] = checkpoint_id
    meta["activated_at"] = _now()
    _write_json(src_dir / "meta.json", meta)
    _write_json(_active_path(), meta)
    if reload:
        try:
            from triage_engine import reload_ml_model

            reload_ml_model()
        except Exception:
            pass
    return meta
