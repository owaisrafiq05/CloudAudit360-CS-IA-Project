from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user, write_audit
from app.db import get_db
from app.grc.register import apply_treatment, approve_exception, create_exception
from app.models import ExceptionRecord, Risk

router = APIRouter(tags=["risks"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/risks")
def risks_list(
    request: Request,
    db: Session = Depends(get_db),
    rating: str | None = None,
    status: str | None = None,
    owner: str | None = None,
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    q = db.query(Risk)
    if rating:
        q = q.filter(Risk.rating == rating)
    if status:
        q = q.filter(Risk.status == status)
    if owner:
        q = q.filter(Risk.owner == owner)
    rows = q.order_by(Risk.inherent_score.desc()).all()
    return templates.TemplateResponse(
        "risks.html",
        {
            "request": request,
            "user": user,
            "risks": rows,
            "rating": rating or "",
            "status": status or "",
            "owner": owner or "",
        },
    )


@router.get("/risks/{risk_id}")
def risk_detail(risk_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    risk = db.query(Risk).filter(Risk.id == risk_id).first()
    if not risk:
        return RedirectResponse("/risks?error=Risk+not+found", status_code=303)
    exceptions = db.query(ExceptionRecord).filter(ExceptionRecord.risk_id == risk_id).all()
    return templates.TemplateResponse(
        "risk_detail.html",
        {"request": request, "user": user, "risk": risk, "exceptions": exceptions},
    )


@router.post("/risks/{risk_id}/update")
def risk_update(
    risk_id: int,
    request: Request,
    db: Session = Depends(get_db),
    owner: str = Form(""),
    treatment: str = Form("none"),
    treatment_note: str = Form(""),
    status: str = Form(""),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse(f"/risks/{risk_id}?error=Viewers+cannot+edit", status_code=303)
    risk = db.query(Risk).filter(Risk.id == risk_id).first()
    if not risk:
        return RedirectResponse("/risks?error=Not+found", status_code=303)
    try:
        apply_treatment(
            db,
            risk,
            treatment=treatment,
            owner=owner or None,
            note=treatment_note or None,
            status=status or None,
        )
        write_audit(db, user.username, "update_risk", "risk", risk.id)
        db.commit()
    except ValueError as exc:
        db.rollback()
        return RedirectResponse(f"/risks/{risk_id}?error={str(exc)}", status_code=303)
    return RedirectResponse(f"/risks/{risk_id}?msg=Updated", status_code=303)


@router.post("/risks/{risk_id}/exceptions")
def risk_exception_create(
    risk_id: int,
    request: Request,
    db: Session = Depends(get_db),
    justification: str = Form(...),
    expires_at: str = Form(""),
):
    from datetime import datetime

    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse(f"/risks/{risk_id}?error=Forbidden", status_code=303)
    exp = None
    if expires_at:
        exp = datetime.fromisoformat(expires_at)
    create_exception(db, risk_id=risk_id, justification=justification, expires_at=exp)
    write_audit(db, user.username, "create_exception", "risk", risk_id)
    db.commit()
    return RedirectResponse(f"/risks/{risk_id}?msg=Exception+requested", status_code=303)


@router.post("/exceptions/{exception_id}/approve")
def exception_approve(
    exception_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role != "admin":
        return RedirectResponse("/risks?error=Admin+only", status_code=303)
    exc = approve_exception(db, exception_id, approved_by=user.username)
    write_audit(db, user.username, "approve_exception", "exception", exception_id)
    db.commit()
    return RedirectResponse(f"/risks/{exc.risk_id}?msg=Exception+approved", status_code=303)
