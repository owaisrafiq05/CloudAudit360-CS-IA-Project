from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.auth import require_min_role, require_user, write_audit
from app.db import get_db
from app.grc.compliance import framework_scores
from app.grc.register import apply_treatment, approve_exception, create_exception
from app.grc.review import complete_review, generate_review_tasks
from app.models import Evidence, ExceptionRecord, Finding, Report, Review, Risk, Scan, User
from app.pipeline import run_scan
from app.reporting.builder import generate_report
from app.schemas import (
    ComplianceScore,
    ExceptionCreate,
    ExceptionOut,
    FindingOut,
    ReportCreate,
    ReportOut,
    ReviewComplete,
    ReviewOut,
    RiskOut,
    RiskUpdate,
    ScanCompare,
    ScanCreate,
    ScanOut,
)
from app.web.compare import compare_scans

router = APIRouter(tags=["api"])


@router.post("/scans", response_model=ScanOut)
def api_create_scan(
    body: ScanCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("auditor")),
):
    scan = run_scan(
        db,
        environment=body.environment,
        label=body.label,
        triggered_by=user.username,
    )
    write_audit(db, user.username, "api_trigger_scan", "scan", scan.id)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[ScanOut])
def api_list_scans(db: Session = Depends(get_db), user: User = Depends(require_user)):
    return db.query(Scan).order_by(Scan.id.desc()).all()


@router.get("/scans/compare", response_model=ScanCompare)
def api_compare(
    a: int = Query(...),
    b: int = Query(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return compare_scans(db, a, b)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def api_get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/findings", response_model=list[FindingOut])
def api_findings(
    scan: int | None = None,
    severity: str | None = None,
    service: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    q = db.query(Finding)
    if scan:
        q = q.filter(Finding.scan_id == scan)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if service:
        q = q.filter(Finding.check_id.startswith(service))
    return q.order_by(Finding.id.desc()).limit(500).all()


@router.get("/controls")
def api_controls(
    framework: str | None = None,
    scan: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    from app.models import Control, ControlResult

    if not scan:
        latest = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
        scan = latest.id if latest else None
    if not scan:
        return []
    q = (
        db.query(ControlResult, Control)
        .join(Control, Control.id == ControlResult.control_id)
        .filter(ControlResult.scan_id == scan)
    )
    if framework:
        q = q.filter(Control.framework == framework)
    return [
        {
            "id": c.id,
            "framework": c.framework,
            "control_ref": c.control_ref,
            "title": c.title,
            "description": c.description,
            "status": r.status,
            "failing_finding_count": r.failing_finding_count,
        }
        for r, c in q.all()
    ]


@router.get("/compliance/{scan_id}", response_model=list[ComplianceScore])
def api_compliance(scan_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    return framework_scores(db, scan_id)


@router.get("/risks", response_model=list[RiskOut])
def api_risks(
    rating: str | None = None,
    status: str | None = None,
    owner: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    q = db.query(Risk)
    if rating:
        q = q.filter(Risk.rating == rating)
    if status:
        q = q.filter(Risk.status == status)
    if owner:
        q = q.filter(Risk.owner == owner)
    return q.order_by(Risk.inherent_score.desc()).all()


@router.patch("/risks/{risk_id}", response_model=RiskOut)
def api_patch_risk(
    risk_id: int,
    body: RiskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("auditor")),
):
    risk = db.query(Risk).filter(Risk.id == risk_id).first()
    if not risk:
        raise HTTPException(404, "Risk not found")
    try:
        apply_treatment(
            db,
            risk,
            treatment=body.treatment or risk.treatment,
            owner=body.owner if body.owner is not None else risk.owner,
            note=body.treatment_note if body.treatment_note is not None else risk.treatment_note,
            status=body.status,
        )
        if body.due_date is not None:
            risk.due_date = body.due_date
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    write_audit(db, user.username, "api_update_risk", "risk", risk.id)
    db.commit()
    db.refresh(risk)
    return risk


@router.post("/exceptions", response_model=ExceptionOut)
def api_create_exception(
    body: ExceptionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("auditor")),
):
    exc = create_exception(
        db,
        risk_id=body.risk_id,
        control_id=body.control_id,
        justification=body.justification,
        expires_at=body.expires_at,
    )
    write_audit(db, user.username, "api_create_exception", "exception", exc.id)
    db.commit()
    db.refresh(exc)
    return exc


@router.post("/exceptions/{exception_id}/approve", response_model=ExceptionOut)
def api_approve_exception(
    exception_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("admin")),
):
    try:
        exc = approve_exception(db, exception_id, approved_by=user.username)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    write_audit(db, user.username, "api_approve_exception", "exception", exception_id)
    db.commit()
    db.refresh(exc)
    return exc


@router.get("/reviews", response_model=list[ReviewOut])
def api_reviews(db: Session = Depends(get_db), user: User = Depends(require_user)):
    generate_review_tasks(db)
    db.commit()
    return db.query(Review).order_by(Review.id.desc()).all()


@router.post("/reviews/{review_id}/complete", response_model=ReviewOut)
def api_complete_review(
    review_id: int,
    body: ReviewComplete,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("auditor")),
):
    try:
        review = complete_review(
            db,
            review_id,
            outcome=body.outcome,
            notes=body.notes,
            reviewer=user.username,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    db.commit()
    db.refresh(review)
    return review


@router.get("/evidence")
def api_evidence(
    scan: int | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    import hashlib
    from pathlib import Path

    q = db.query(Evidence)
    if scan:
        q = q.filter(Evidence.scan_id == scan)
    rows = q.order_by(Evidence.id.desc()).all()
    out = []
    for e in rows:
        verified = None
        path = Path(e.path_or_json)
        if path.exists() and path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            verified = digest == e.sha256
        out.append(
            {
                "id": e.id,
                "scan_id": e.scan_id,
                "kind": e.kind,
                "path_or_json": e.path_or_json,
                "sha256": e.sha256,
                "hash_verified": verified,
                "created_at": e.created_at,
            }
        )
    return out


@router.post("/reports", response_model=ReportOut)
def api_create_report(
    body: ReportCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_min_role("auditor")),
):
    report = generate_report(
        db,
        scan_id=body.scan_id,
        report_type=body.type,
        fmt=body.format,
        created_by=user.username,
    )
    write_audit(db, user.username, "api_generate_report", "report", report.id)
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{report_id}/download")
def api_download_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    from pathlib import Path

    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not Path(report.path).exists():
        raise HTTPException(404, "Report not found")
    media = "application/pdf" if report.format == "pdf" else "text/html"
    return FileResponse(report.path, media_type=media, filename=Path(report.path).name)
