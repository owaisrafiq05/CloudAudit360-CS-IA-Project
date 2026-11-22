from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.models import AuditLog, User

router = APIRouter(tags=["admin"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/admin")
def admin_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role != "admin":
        return RedirectResponse("/dashboard?error=Admin+only", status_code=303)
    users = db.query(User).order_by(User.id).all()
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "user": user, "users": users, "logs": logs},
    )
