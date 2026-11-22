from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import Finding, Scan

router = APIRouter(tags=["findings"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/findings")
def findings_list(
    request: Request,
    db: Session = Depends(get_db),
    scan: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    service: str | None = None,
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    scan_id = scan or (scans[0].id if scans else None)
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if service:
        q = q.filter(Finding.check_id.startswith(service))
    rows = q.order_by(Finding.severity.desc(), Finding.id.asc()).all()

    return templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "user": user,
            "findings": rows,
            "scans": scans,
            "scan_id": scan_id,
            "severity": severity or "",
            "status": status or "",
            "service": service or "",
        },
    )


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return RedirectResponse("/findings?error=Finding+not+found", status_code=303)
    return templates.TemplateResponse(
        "finding_detail.html",
        {"request": request, "user": user, "finding": finding},
    )
