from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.grc.compliance import framework_scores
from app.models import Finding, Risk, Scan

router = APIRouter(tags=["overview"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _latest_env(db: Session, environment: str) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.environment == environment, Scan.status == "completed")
        .order_by(Scan.id.desc())
        .first()
    )


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    latest = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
    # Prefer showing health for hardened if available, else latest
    hard = _latest_env(db, "hardened")
    vuln = _latest_env(db, "vulnerable")
    focus = hard or latest

    scores = framework_scores(db, focus.id) if focus else []
    risks = (
        db.query(Risk)
        .filter(Risk.status.in_(["open", "in_progress", "accepted"]))
        .order_by(Risk.inherent_score.desc())
        .limit(10)
        .all()
    )
    if not risks:
        # After remediation, show mitigated risks so the page is not empty for demos
        risks = (
            db.query(Risk)
            .filter(Risk.status == "mitigated")
            .order_by(Risk.inherent_score.desc())
            .limit(10)
            .all()
        )

    rating_dist = Counter(
        r.rating
        for r in db.query(Risk).filter(Risk.status.in_(["open", "in_progress", "accepted"])).all()
    )
    findings_by_service: Counter = Counter()
    chart_scan = vuln or focus
    if chart_scan:
        for f in db.query(Finding).filter(
            Finding.scan_id == chart_scan.id, Finding.status == "FAIL", Finding.source == "custom"
        ).all():
            area = {
                "iam": "Identity",
                "s3": "Storage",
                "sg": "Network",
                "vpc": "Network",
                "cloudtrail": "Logging",
                "guardduty": "Logging",
                "ebs": "Encryption",
                "rds": "Encryption",
                "kms": "Encryption",
            }
            prefix = f.check_id.split("_")[0]
            findings_by_service[area.get(prefix, prefix)] += 1

    before_after = None
    if vuln and hard:
        vuln_scores = framework_scores(db, vuln.id)
        hard_scores = framework_scores(db, hard.id)
        before_after = {
            "vuln_id": vuln.id,
            "hard_id": hard.id,
            "vuln_fails": db.query(Finding)
            .filter(Finding.scan_id == vuln.id, Finding.status == "FAIL", Finding.source == "custom")
            .count(),
            "hard_fails": db.query(Finding)
            .filter(Finding.scan_id == hard.id, Finding.status == "FAIL", Finding.source == "custom")
            .count(),
            "avg_vuln": int(round(sum(s.score for s in vuln_scores) / max(len(vuln_scores), 1))),
            "avg_hard": int(round(sum(s.score for s in hard_scores) / max(len(hard_scores), 1))),
        }

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "latest": focus,
            "scores": scores,
            "top_risks": risks,
            "rating_dist": dict(rating_dist),
            "findings_by_service": dict(findings_by_service),
            "before_after": before_after,
        },
    )


@router.get("/trends")
def trends(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    scans = (
        db.query(Scan)
        .filter(Scan.status == "completed")
        .order_by(Scan.id.asc())
        .all()
    )
    labels = []
    compliance_series: dict[str, list[float]] = {"CIS": [], "ISO27001": [], "NIST": []}
    open_risks = []
    for scan in scans:
        labels.append(f"{scan.environment.title()} #{scan.id}")
        score_map = {s.framework: s.score for s in framework_scores(db, scan.id)}
        for fw in compliance_series:
            compliance_series[fw].append(score_map.get(fw, 0))
        still_open = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id, Finding.status == "FAIL", Finding.source == "custom")
            .count()
        )
        open_risks.append(still_open)

    return templates.TemplateResponse(
        "trends.html",
        {
            "request": request,
            "user": user,
            "labels": labels,
            "compliance_series": compliance_series,
            "open_risks": open_risks,
        },
    )
