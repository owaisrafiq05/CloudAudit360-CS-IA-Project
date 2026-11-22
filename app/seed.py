from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.config import DATA_DIR, get_settings
from app.models import CheckControlMap, Control, Policy, User


def load_yaml(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def seed_users(db: Session) -> None:
    settings = get_settings()
    defaults = [
        (settings.admin_username, settings.admin_password, "admin"),
        ("auditor", "auditor123", "auditor"),
        ("viewer", "viewer123", "viewer"),
    ]
    for username, password, role in defaults:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            continue
        db.add(User(username=username, password_hash=hash_password(password), role=role))


def seed_controls(db: Session) -> dict[tuple[str, str], Control]:
    data = load_yaml(DATA_DIR / "frameworks" / "controls.yaml")
    by_key: dict[tuple[str, str], Control] = {}
    for item in data.get("controls", []):
        key = (item["framework"], str(item["control_ref"]))
        existing = (
            db.query(Control)
            .filter(Control.framework == key[0], Control.control_ref == key[1])
            .first()
        )
        if existing:
            existing.title = item["title"]
            existing.description = item["description"]
            by_key[key] = existing
        else:
            ctrl = Control(
                framework=item["framework"],
                control_ref=str(item["control_ref"]),
                title=item["title"],
                description=item["description"],
            )
            db.add(ctrl)
            db.flush()
            by_key[key] = ctrl
    return by_key


def seed_mapping(db: Session, controls: dict[tuple[str, str], Control]) -> None:
    mapping = load_yaml(DATA_DIR / "frameworks" / "mapping.yaml")
    for check_id, refs in mapping.items():
        for ref in refs:
            key = (ref["framework"], str(ref["ref"]))
            ctrl = controls.get(key)
            if not ctrl:
                continue
            exists = (
                db.query(CheckControlMap)
                .filter(
                    CheckControlMap.check_id == check_id,
                    CheckControlMap.control_id == ctrl.id,
                )
                .first()
            )
            if not exists:
                db.add(CheckControlMap(check_id=check_id, control_id=ctrl.id))


def seed_policies(db: Session, controls: dict[tuple[str, str], Control]) -> None:
    data = load_yaml(DATA_DIR / "policies.yaml")
    for item in data.get("policies", []):
        linked_ids: list[int] = []
        for ref in item.get("linked_controls", []):
            ctrl = controls.get((ref["framework"], str(ref["ref"])))
            if ctrl:
                linked_ids.append(ctrl.id)
        existing = db.query(Policy).filter(Policy.name == item["name"]).first()
        if existing:
            existing.statement = item["statement"].strip()
            existing.linked_control_ids = linked_ids
        else:
            db.add(
                Policy(
                    name=item["name"],
                    statement=item["statement"].strip(),
                    linked_control_ids=linked_ids,
                )
            )


def run_seed(db: Session) -> None:
    seed_users(db)
    controls = seed_controls(db)
    db.flush()
    # refresh control map with IDs
    controls = {
        (c.framework, c.control_ref): c for c in db.query(Control).all()
    }
    seed_mapping(db, controls)
    seed_policies(db, controls)
    db.commit()
