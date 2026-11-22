"""Scan comparison helpers."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.grc.compliance import framework_scores
from app.models import Asset, Finding


def _finding_map(db: Session, scan_id: int) -> dict[str, Finding]:
    assets = {a.id: a for a in db.query(Asset).all()}
    out: dict[str, Finding] = {}
    for f in db.query(Finding).filter(Finding.scan_id == scan_id).all():
        if f.source != "custom":
            # Prefer custom; skip scanner dupes for comparison
            continue
        arn = assets[f.asset_id].arn if f.asset_id and f.asset_id in assets else ""
        key = f"{f.check_id}+{arn}"
        out[key] = f
    return out


def compare_scans(db: Session, scan_a: int, scan_b: int) -> dict:
    map_a = _finding_map(db, scan_a)
    map_b = _finding_map(db, scan_b)
    keys = set(map_a) | set(map_b)

    fixed, new, unchanged = [], [], []
    for key in sorted(keys):
        a = map_a.get(key)
        b = map_b.get(key)
        item = {
            "finding_key": key,
            "check_id": (b or a).check_id,
            "title": (b or a).title,
            "severity": (b or a).severity,
            "status_a": a.status if a else None,
            "status_b": b.status if b else None,
        }
        if a and b:
            if a.status == "FAIL" and b.status == "PASS":
                fixed.append(item)
            elif a.status == "PASS" and b.status == "FAIL":
                new.append(item)
            elif a.status == b.status:
                unchanged.append(item)
            elif b.status == "FAIL":
                new.append(item)
            else:
                unchanged.append(item)
        elif a and not b:
            if a.status == "FAIL":
                fixed.append(item)  # no longer present as fail
            else:
                unchanged.append(item)
        elif b and not a:
            if b.status == "FAIL":
                new.append(item)
            else:
                unchanged.append(item)

    scores_a = {s.framework: s.score for s in framework_scores(db, scan_a)}
    scores_b = {s.framework: s.score for s in framework_scores(db, scan_b)}
    frameworks = sorted(set(scores_a) | set(scores_b))
    score_deltas = {
        fw: {
            "a": scores_a.get(fw, 0.0),
            "b": scores_b.get(fw, 0.0),
            "delta": round(scores_b.get(fw, 0.0) - scores_a.get(fw, 0.0), 1),
        }
        for fw in frameworks
    }

    return {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "fixed": fixed,
        "new": new,
        "unchanged": unchanged,
        "score_deltas": score_deltas,
    }
