"""End-to-end pipeline: Collect -> Assess -> Map -> Score -> Register -> Reviews."""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.assessment.engine import run_assessment
from app.collector.aws_collector import collect
from app.grc.compliance import evaluate_controls
from app.grc.register import expire_exceptions, update_risk_register
from app.grc.review import generate_review_tasks
from app.models import Scan

logger = logging.getLogger(__name__)


def run_scan(
    db: Session,
    *,
    environment: str = "vulnerable",
    label: str | None = None,
    triggered_by: str = "system",
    run_prowler: bool = False,
    run_checkov: bool = False,
) -> Scan:
    expire_exceptions(db)

    scan = Scan(
        environment=environment,
        status="running",
        label=label or f"{environment} scan",
        triggered_by=triggered_by,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        snapshots = collect(db, scan, environment=environment)
        db.commit()

        run_assessment(
            db,
            scan,
            snapshots,
            run_prowler=run_prowler,
            run_checkov=run_checkov,
        )
        db.commit()

        # Risks first so compliance can honor exceptions tied to risks
        update_risk_register(db, scan.id)
        db.commit()

        evaluate_controls(db, scan.id)
        db.commit()

        generate_review_tasks(db)
        db.commit()

        scan.status = "completed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
        logger.info("Scan %s completed (%s snapshots)", scan.id, len(snapshots))
        return scan
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan failed: %s", exc)
        scan.status = "failed"
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise
