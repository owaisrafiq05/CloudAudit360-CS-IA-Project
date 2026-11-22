from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import AuditLog, User

settings = get_settings()
serializer = URLSafeTimedSerializer(settings.secret_key)
SESSION_COOKIE = "ca360_session"
basic_security = HTTPBasic(auto_error=False)

ROLE_RANK = {"viewer": 1, "auditor": 2, "admin": 3}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_session_token(username: str, role: str) -> str:
    return serializer.dumps({"username": username, "role": role})


def load_session_token(token: str) -> dict | None:
    try:
        return serializer.loads(token, max_age=settings.session_max_age)
    except BadSignature:
        return None


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return None
    return user


def get_current_user(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    credentials: Annotated[HTTPBasicCredentials | None, Depends(basic_security)] = None,
) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        data = load_session_token(token)
        if data:
            user = db.query(User).filter(User.username == data["username"]).first()
            if user:
                return user
    if credentials:
        user = authenticate_user(db, credentials.username, credentials.password)
        if user:
            return user
    return None


def require_user(user: Annotated[User | None, Depends(get_current_user)]) -> User:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def require_role(*roles: str):
    def _dep(user: Annotated[User, Depends(require_user)]) -> User:
        if user.role not in roles and user.role != "admin":
            # admin always allowed; otherwise must match one of the roles
            if "admin" not in roles and user.role not in roles:
                min_ok = max(ROLE_RANK.get(r, 0) for r in roles)
                if ROLE_RANK.get(user.role, 0) < min_ok:
                    raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _dep


def require_min_role(min_role: str):
    def _dep(user: Annotated[User, Depends(require_user)]) -> User:
        if ROLE_RANK.get(user.role, 0) < ROLE_RANK.get(min_role, 99):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _dep


def write_audit(
    db: Session,
    user: str,
    action: str,
    entity: str,
    entity_id: str | int | None = None,
) -> None:
    db.add(
        AuditLog(
            user=user,
            action=action,
            entity=entity,
            entity_id=str(entity_id) if entity_id is not None else None,
        )
    )
