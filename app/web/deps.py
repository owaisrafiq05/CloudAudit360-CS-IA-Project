from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_min_role
from app.db import get_db
from app.models import User


def login_required(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=303, detail="login", headers={"Location": "/login"})
    return user


def optional_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User | None:
    return get_current_user(request, db)


def redirect_if_anonymous(request: Request, db: Session) -> User | RedirectResponse:
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return user


AdminUser = Annotated[User, Depends(require_min_role("admin"))]
AuditorUser = Annotated[User, Depends(require_min_role("auditor"))]
ViewerUser = Annotated[User, Depends(require_min_role("viewer"))]
