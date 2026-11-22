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


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    latest = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
    scores = framework_scores(db, latest.id) if latest else []
    risks = (
        db.query(Risk)
        .filter(Risk.status.in_(["open", "in_progress", "accepted"]))
        .order_by(Risk.inherent_score.desc())
        .limit(10)
        .all()
    )
    rating_dist = Counter(
        r.rating
        for r in db.query(Risk).filter(Risk.status.in_(["open", "in_progress", "accepted"])).all()
    )
    findings_by_service: Counter = Counter()
    if latest:
        for f in db.query(Finding).filter(Finding.scan_id == latest.id, Finding.status == "FAIL").all():
            service = f.check_id.split("_")[0]
            findings_by_service[service] += 1

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "latest": latest,
            "scores": scores,
            "top_risks": risks,
            "rating_dist": dict(rating_dist),
            "findings_by_service": dict(findings_by_service),
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
        labels.append(f"#{scan.id} {scan.environment}")
        scores = {s.framework: s.score for s in framework_scores(db, scan.id)}
        for fw in compliance_series:
            compliance_series[fw].append(scores.get(fw, 0))
        open_count = (
            db.query(Risk)
            .filter(
                Risk.status.in_(["open", "in_progress"]),
                Risk.last_seen_scan == scan.id,
            )
            .count()
        )
        # Better: count risks that were open as of this scan (first_seen <= scan and not mitigated before)
        open_count = db.query(Risk).filter(
            Risk.first_seen_scan <= scan.id,
            Risk.status.in_(["open", "in_progress", "accepted", "mitigated", "closed"]),
        ).count()
        # For trend, show open+in_progress at time of scan using last_seen
        still_open = 0
        for r in db.query(Risk).all():
            if r.first_seen_scan and r.first_seen_scan > scan.id:
                continue
            if r.status == "mitigated" and r.last_seen_scan and r.last_seen_scan <= scan.id:
                # mitigated on or before this scan — check if last fail was before
                if r.last_seen_scan == scan.id:
                    # if last seen is this scan and mitigated, it was fixed this scan
                    continue
                if r.last_seen_scan < scan.id and r.status == "mitigated":
                    continue
            if r.status in ("open", "in_progress", "accepted"):
                still_open += 1
            elif r.status == "mitigated" and (not r.last_seen_scan or r.last_seen_scan > scan.id):
                still_open += 1
        # Simpler approach for demo: FAIL findings count as open-risk proxy
        from app.models import Finding as F

        still_open = db.query(F).filter(F.scan_id == scan.id, F.status == "FAIL", F.source == "custom").count()
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
