from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user, write_audit
from app.db import get_db
from app.models import Evidence, Finding, Scan
from app.pipeline import run_scan
from app.web.compare import compare_scans

router = APIRouter(tags=["scans"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/scans")
def scans_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    return templates.TemplateResponse(
        "scans.html",
        {"request": request, "user": user, "scans": scans, "compare": None},
    )


@router.post("/scans")
def scans_trigger(
    request: Request,
    db: Session = Depends(get_db),
    environment: str = Form("vulnerable"),
    label: str = Form(""),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse("/scans?error=Viewers+cannot+trigger+scans", status_code=303)
    scan = run_scan(
        db,
        environment=environment,
        label=label or None,
        triggered_by=user.username,
    )
    write_audit(db, user.username, "trigger_scan", "scan", scan.id)
    db.commit()
    return RedirectResponse(f"/scans?msg=Scan+{scan.id}+completed", status_code=303)


@router.get("/scans/compare")
def scans_compare(
    request: Request,
    db: Session = Depends(get_db),
    a: int | None = None,
    b: int | None = None,
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    compare = compare_scans(db, a, b) if a and b else None
    return templates.TemplateResponse(
        "scans.html",
        {"request": request, "user": user, "scans": scans, "compare": compare, "a": a, "b": b},
    )


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return RedirectResponse("/scans?error=Not+found", status_code=303)
    fail = db.query(Finding).filter(Finding.scan_id == scan_id, Finding.status == "FAIL").count()
    pas = db.query(Finding).filter(Finding.scan_id == scan_id, Finding.status == "PASS").count()
    evidence = db.query(Evidence).filter(Evidence.scan_id == scan_id).all()
    return templates.TemplateResponse(
        "scan_detail.html",
        {
            "request": request,
            "user": user,
            "scan": scan,
            "fail": fail,
            "pas": pas,
            "evidence": evidence,
        },
    )
