from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user, write_audit
from app.db import get_db
from app.models import Report, Scan
from app.reporting.builder import generate_report

router = APIRouter(tags=["reports"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/reports")
def reports_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    scans = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).all()
    reports = db.query(Report).order_by(Report.id.desc()).all()
    return templates.TemplateResponse(
        "reports.html",
        {"request": request, "user": user, "scans": scans, "reports": reports},
    )


@router.post("/reports")
def reports_create(
    request: Request,
    db: Session = Depends(get_db),
    scan_id: int = Form(...),
    report_type: str = Form("audit"),
    fmt: str = Form("html"),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse("/reports?error=Viewers+cannot+generate+reports", status_code=303)
    report = generate_report(
        db,
        scan_id=scan_id,
        report_type=report_type,
        fmt=fmt,
        created_by=user.username,
    )
    write_audit(db, user.username, "generate_report", "report", report.id)
    db.commit()
    return RedirectResponse(f"/reports?msg=Report+{report.id}+ready", status_code=303)


@router.get("/reports/{report_id}/download")
def reports_download(report_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report or not Path(report.path).exists():
        return RedirectResponse("/reports?error=Report+file+missing", status_code=303)
    media = "application/pdf" if report.format == "pdf" else "text/html"
    return FileResponse(report.path, media_type=media, filename=Path(report.path).name)
