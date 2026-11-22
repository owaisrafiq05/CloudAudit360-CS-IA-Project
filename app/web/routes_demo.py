"""Guided course-demo walkthrough — plain-language presentation flow."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user, write_audit
from app.db import get_db
from app.grc.compliance import framework_scores
from app.models import Finding, Report, Risk, Scan
from app.pipeline import run_scan
from app.reporting.builder import generate_report
from app.web.compare import compare_scans

router = APIRouter(tags=["demo"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _latest_by_env(db: Session, environment: str) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.environment == environment, Scan.status == "completed")
        .order_by(Scan.id.desc())
        .first()
    )


@router.get("/demo")
def demo_home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    vuln = _latest_by_env(db, "vulnerable")
    hard = _latest_by_env(db, "hardened")

    vuln_fails = 0
    vuln_scores = []
    if vuln:
        vuln_fails = (
            db.query(Finding)
            .filter(Finding.scan_id == vuln.id, Finding.status == "FAIL", Finding.source == "custom")
            .count()
        )
        vuln_scores = framework_scores(db, vuln.id)

    hard_fails = 0
    hard_scores = []
    if hard:
        hard_fails = (
            db.query(Finding)
            .filter(Finding.scan_id == hard.id, Finding.status == "FAIL", Finding.source == "custom")
            .count()
        )
        hard_scores = framework_scores(db, hard.id)

    open_risks = db.query(Risk).filter(Risk.status.in_(["open", "in_progress", "accepted"])).count()
    mitigated = db.query(Risk).filter(Risk.status == "mitigated").count()
    comparison = compare_scans(db, vuln.id, hard.id) if vuln and hard else None
    latest_report = db.query(Report).order_by(Report.id.desc()).first()

    # Demo progress 1..5
    step = 1
    if vuln:
        step = 2
    if vuln and vuln_fails:
        step = 3
    if hard:
        step = 5 if comparison else 4
    if hard and latest_report and latest_report.scan_id == hard.id:
        step = 5

    avg_vuln = (
        round(sum(s.score for s in vuln_scores) / len(vuln_scores), 0) if vuln_scores else None
    )
    avg_hard = (
        round(sum(s.score for s in hard_scores) / len(hard_scores), 0) if hard_scores else None
    )

    return templates.TemplateResponse(
        "demo.html",
        {
            "request": request,
            "user": user,
            "vuln": vuln,
            "hard": hard,
            "vuln_fails": vuln_fails,
            "hard_fails": hard_fails,
            "vuln_scores": vuln_scores,
            "hard_scores": hard_scores,
            "avg_vuln": avg_vuln,
            "avg_hard": avg_hard,
            "open_risks": open_risks,
            "mitigated": mitigated,
            "comparison": comparison,
            "latest_report": latest_report,
            "step": step,
            "can_scan": user.role != "viewer",
        },
    )


@router.post("/demo/scan")
def demo_scan(
    request: Request,
    db: Session = Depends(get_db),
    environment: str = Form(...),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse("/demo?error=Viewers+cannot+run+scans", status_code=303)
    if environment not in ("vulnerable", "hardened"):
        return RedirectResponse("/demo?error=Invalid+environment", status_code=303)

    label = (
        "Step 1 — Weak cloud lab"
        if environment == "vulnerable"
        else "Step 4 — Hardened cloud lab"
    )
    scan = run_scan(db, environment=environment, label=label, triggered_by=user.username)
    write_audit(db, user.username, "demo_scan", "scan", scan.id)
    db.commit()

    msg = (
        "Weak+lab+scanned.+Open+Step+2+to+see+problems."
        if environment == "vulnerable"
        else "Hardened+lab+scanned.+Open+Step+5+to+see+improvement."
    )
    return RedirectResponse(f"/demo?msg={msg}", status_code=303)


@router.post("/demo/report")
def demo_report(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse("/demo?error=Viewers+cannot+generate+reports", status_code=303)

    hard = _latest_by_env(db, "hardened")
    scan = hard or db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
    if not scan:
        return RedirectResponse("/demo?error=Run+a+scan+first", status_code=303)

    report = generate_report(
        db,
        scan_id=scan.id,
        report_type="audit",
        fmt="html",
        created_by=user.username,
    )
    write_audit(db, user.username, "demo_report", "report", report.id)
    db.commit()
    return RedirectResponse(f"/reports/{report.id}/download", status_code=303)
