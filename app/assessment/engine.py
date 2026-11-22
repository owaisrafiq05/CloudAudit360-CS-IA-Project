"""Assessment engine: run custom checks + scanner adapters against collected snapshots."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.assessment.adapters import checkov as checkov_adapter
from app.assessment.adapters import prowler as prowler_adapter
from app.assessment.registry import get_registered_checks
from app.models import Asset, Finding, Scan, Snapshot
from app.schemas import NormalizedFinding

logger = logging.getLogger(__name__)


def _index_snapshots(snapshots: list[Snapshot]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = defaultdict(dict)
    for snap in snapshots:
        indexed[snap.service][snap.resource_id] = snap.config_json
    return indexed


def _ensure_checks_loaded() -> None:
    # Importing the package registers all decorated checks
    import app.assessment.checks  # noqa: F401


def run_custom_checks(snapshot_index: dict[str, dict[str, Any]]) -> list[NormalizedFinding]:
    _ensure_checks_loaded()
    findings: list[NormalizedFinding] = []
    for check_id, fn in get_registered_checks().items():
        try:
            findings.extend(fn(snapshot_index))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Check %s failed: %s", check_id, exc)
            findings.append(
                NormalizedFinding(
                    check_id=check_id,
                    source="custom",
                    title=f"Check error: {check_id}",
                    description=str(exc),
                    severity="medium",
                    status="ERROR",
                    evidence={"error": str(exc)},
                    remediation="Investigate check failure.",
                )
            )
    return findings


def persist_findings(
    db: Session,
    scan: Scan,
    normalized: list[NormalizedFinding],
) -> list[Finding]:
    asset_by_arn = {a.arn: a for a in db.query(Asset).all()}
    saved: list[Finding] = []
    for nf in normalized:
        asset_id = None
        if nf.asset_arn and nf.asset_arn in asset_by_arn:
            asset_id = asset_by_arn[nf.asset_arn].id
        row = Finding(
            scan_id=scan.id,
            check_id=nf.check_id,
            source=nf.source,
            asset_id=asset_id,
            title=nf.title,
            description=nf.description,
            severity=nf.severity,
            status=nf.status,
            evidence_json=nf.evidence,
            remediation=nf.remediation,
        )
        db.add(row)
        saved.append(row)
    db.flush()
    return saved


def run_assessment(
    db: Session,
    scan: Scan,
    snapshots: list[Snapshot],
    *,
    run_prowler: bool = True,
    run_checkov: bool = True,
) -> list[Finding]:
    indexed = _index_snapshots(snapshots)
    normalized = run_custom_checks(indexed)

    if run_prowler:
        normalized.extend(prowler_adapter.collect_findings())
    if run_checkov:
        normalized.extend(checkov_adapter.collect_findings())

    return persist_findings(db, scan, normalized)
