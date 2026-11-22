from __future__ import annotations

from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user, write_audit
from app.db import get_db
from app.grc.review import access_review_payload, complete_review, generate_review_tasks
from app.models import ExceptionRecord, Review, Scan

router = APIRouter(tags=["reviews"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/reviews")
def reviews_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    generate_review_tasks(db)
    db.commit()
    reviews = db.query(Review).order_by(Review.id.desc()).all()
    exceptions = db.query(ExceptionRecord).order_by(ExceptionRecord.id.desc()).all()
    latest = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
    access = access_review_payload(db, latest.id if latest else None)
    today = date.today()
    return templates.TemplateResponse(
        "reviews.html",
        {
            "request": request,
            "user": user,
            "reviews": reviews,
            "exceptions": exceptions,
            "access": access,
            "today": today,
        },
    )


@router.post("/reviews/{review_id}/complete")
def reviews_complete(
    review_id: int,
    request: Request,
    db: Session = Depends(get_db),
    outcome: str = Form(...),
    notes: str = Form(""),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role == "viewer":
        return RedirectResponse("/reviews?error=Forbidden", status_code=303)
    complete_review(db, review_id, outcome=outcome, notes=notes or None, reviewer=user.username)
    write_audit(db, user.username, "complete_review", "review", review_id)
    db.commit()
    return RedirectResponse("/reviews?msg=Review+completed", status_code=303)
