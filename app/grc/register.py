"""Risk register updates, treatment, and exceptions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.grc.risk import residual_for_treatment, score_finding
from app.models import Asset, ExceptionRecord, Finding, Risk


def finding_key(check_id: str, asset_arn: str | None) -> str:
    return f"{check_id}+{asset_arn or ''}"


def update_risk_register(db: Session, scan_id: int) -> list[Risk]:
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.status.in_(["FAIL", "PASS"]))
        .all()
    )
    assets = {a.id: a for a in db.query(Asset).all()}
    # Prefer custom over prowler for same key
    preferred: dict[str, Finding] = {}
    for f in findings:
        asset = assets.get(f.asset_id) if f.asset_id else None
        key = finding_key(f.check_id, asset.arn if asset else None)
        existing = preferred.get(key)
        if existing is None or (f.source == "custom" and existing.source != "custom"):
            preferred[key] = f

    touched: list[Risk] = []
    seen_keys: set[str] = set()

    for key, f in preferred.items():
        seen_keys.add(key)
        asset = assets.get(f.asset_id) if f.asset_id else None
        exposure = asset.exposure if asset else "private"
        criticality = asset.criticality if asset else 2

        if f.status == "PASS":
            risk = db.query(Risk).filter(Risk.finding_key == key).first()
            if risk:
                risk.last_seen_scan = scan_id
                if risk.status not in ("accepted", "closed"):
                    risk.status = "mitigated"
                    residual, residual_rating = residual_for_treatment(
                        risk.inherent_score,
                        "mitigate",
                        verified_mitigated=True,
                    )
                    risk.residual_score = residual
                    risk.residual_rating = residual_rating
                    risk.treatment = risk.treatment if risk.treatment != "none" else "mitigate"
                touched.append(risk)
            continue

        # FAIL
        scored = score_finding(
            severity=f.severity,
            exposure=exposure,
            criticality=criticality,
        )
        risk = db.query(Risk).filter(Risk.finding_key == key).first()
        if risk is None:
            risk = Risk(
                finding_key=key,
                asset_id=f.asset_id,
                title=f.title,
                likelihood=scored["likelihood"],
                impact=scored["impact"],
                inherent_score=scored["inherent_score"],
                rating=scored["rating"],
                likelihood_reason=scored["likelihood_reason"],
                impact_reason=scored["impact_reason"],
                check_id=f.check_id,
                severity=f.severity,
                status="open",
                treatment="none",
                first_seen_scan=scan_id,
                last_seen_scan=scan_id,
                residual_score=float(scored["inherent_score"]),
                residual_rating=scored["rating"],
            )
            db.add(risk)
        else:
            risk.title = f.title
            risk.asset_id = f.asset_id
            risk.likelihood = scored["likelihood"]
            risk.impact = scored["impact"]
            risk.inherent_score = scored["inherent_score"]
            risk.rating = scored["rating"]
            risk.likelihood_reason = scored["likelihood_reason"]
            risk.impact_reason = scored["impact_reason"]
            risk.check_id = f.check_id
            risk.severity = f.severity
            risk.last_seen_scan = scan_id
            if risk.status == "mitigated":
                risk.status = "open"
            residual, residual_rating = residual_for_treatment(
                risk.inherent_score,
                risk.treatment,
                verified_mitigated=False,
            )
            risk.residual_score = residual
            risk.residual_rating = residual_rating
        touched.append(risk)

    db.flush()
    return touched


def apply_treatment(
    db: Session,
    risk: Risk,
    *,
    treatment: str,
    owner: str | None,
    note: str | None,
    status: str | None = None,
) -> Risk:
    treatment = treatment.lower()
    if treatment == "accept":
        # Require an approved active exception
        now = datetime.utcnow()
        exc = (
            db.query(ExceptionRecord)
            .filter(
                ExceptionRecord.risk_id == risk.id,
                ExceptionRecord.status == "active",
                ExceptionRecord.approved_by.isnot(None),
            )
            .first()
        )
        if not exc or (exc.expires_at and exc.expires_at < now):
            raise ValueError("Accept treatment requires an approved active exception with expiry")

    risk.treatment = treatment
    if owner is not None:
        risk.owner = owner
    if note is not None:
        risk.treatment_note = note
    if status is not None:
        risk.status = status
    elif treatment == "avoid":
        risk.status = "closed"
    elif treatment == "mitigate" and risk.status == "open":
        risk.status = "in_progress"
    elif treatment == "accept":
        risk.status = "accepted"

    verified = risk.status == "mitigated"
    residual, residual_rating = residual_for_treatment(
        risk.inherent_score,
        treatment,
        verified_mitigated=verified,
    )
    risk.residual_score = residual
    risk.residual_rating = residual_rating
    db.flush()
    return risk


def create_exception(
    db: Session,
    *,
    risk_id: int,
    justification: str,
    control_id: int | None = None,
    expires_at: datetime | None = None,
) -> ExceptionRecord:
    exc = ExceptionRecord(
        risk_id=risk_id,
        control_id=control_id,
        justification=justification,
        expires_at=expires_at,
        status="active",
        approved_by=None,
    )
    db.add(exc)
    db.flush()
    return exc


def approve_exception(db: Session, exception_id: int, approved_by: str) -> ExceptionRecord:
    exc = db.query(ExceptionRecord).filter(ExceptionRecord.id == exception_id).first()
    if not exc:
        raise ValueError("Exception not found")
    exc.approved_by = approved_by
    exc.status = "active"
    db.flush()
    return exc


def expire_exceptions(db: Session) -> int:
    now = datetime.utcnow()
    rows = (
        db.query(ExceptionRecord)
        .filter(ExceptionRecord.status == "active", ExceptionRecord.expires_at.isnot(None))
        .all()
    )
    count = 0
    for exc in rows:
        if exc.expires_at and exc.expires_at < now:
            exc.status = "expired"
            count += 1
            # Revert related risk accept status
            risk = db.query(Risk).filter(Risk.id == exc.risk_id).first()
            if risk and risk.status == "accepted" and risk.treatment == "accept":
                risk.status = "open"
                risk.treatment = "none"
                risk.residual_score = float(risk.inherent_score)
                risk.residual_rating = risk.rating
    return count
