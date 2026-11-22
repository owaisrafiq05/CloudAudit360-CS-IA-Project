"""Load controls.yaml + mapping.yaml helpers."""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.config import DATA_DIR
from app.models import CheckControlMap, Control


def load_yaml(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_mapping_dict() -> dict[str, list[dict]]:
    data = load_yaml(DATA_DIR / "frameworks" / "mapping.yaml")
    return data or {}


def controls_for_check(db: Session, check_id: str) -> list[Control]:
    rows = (
        db.query(Control)
        .join(CheckControlMap, CheckControlMap.control_id == Control.id)
        .filter(CheckControlMap.check_id == check_id)
        .all()
    )
    return rows


def unmapped_check_ids(db: Session, check_ids: set[str]) -> list[str]:
    mapped = {
        row.check_id
        for row in db.query(CheckControlMap.check_id).distinct().all()
    }
    return sorted(cid for cid in check_ids if cid not in mapped)
