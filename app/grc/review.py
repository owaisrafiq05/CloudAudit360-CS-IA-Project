"""Periodic reviews and policy compliance helpers."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import ControlResult, Policy, Review, Snapshot


def generate_review_tasks(db: Session, *, days_ahead: int = 30) -> list[Review]:
    """Create control and access review tasks if none are open."""
    created: list[Review] = []
    due = date.today() + timedelta(days=days_ahead)

    open_control = (
        db.query(Review)
        .filter(Review.type == "control_review", Review.completed_at.is_(None))
        .first()
    )
    if not open_control:
        r = Review(
            type="control_review",
            target="All framework controls",
            reviewer=None,
            due_date=due,
        )
        db.add(r)
        created.append(r)

    open_access = (
        db.query(Review)
        .filter(Review.type == "access_review", Review.completed_at.is_(None))
        .first()
    )
    if not open_access:
        r = Review(
            type="access_review",
            target="IAM users, keys, privileged policies",
            reviewer=None,
            due_date=due,
        )
        db.add(r)
        created.append(r)

    open_policy = (
        db.query(Review)
        .filter(Review.type == "policy_review", Review.completed_at.is_(None))
        .first()
    )
    if not open_policy:
        r = Review(
            type="policy_review",
            target="Organizational security policies",
            reviewer=None,
            due_date=due,
        )
        db.add(r)
        created.append(r)

    db.flush()
    return created


def complete_review(
    db: Session,
    review_id: int,
    *,
    outcome: str,
    notes: str | None,
    reviewer: str,
) -> Review:
    review = db.query(Review).filter(Review.id == review_id).first()
    if not review:
        raise ValueError("Review not found")
    review.outcome = outcome
    review.notes = notes
    review.reviewer = reviewer
    review.completed_at = datetime.utcnow()
    db.flush()
    return review


def access_review_payload(db: Session, scan_id: int | None = None) -> dict:
    """IAM users/keys/privileged policies from latest (or given) IAM snapshot."""
    q = db.query(Snapshot).filter(Snapshot.service == "iam", Snapshot.resource_id == "account")
    if scan_id:
        q = q.filter(Snapshot.scan_id == scan_id)
    snap = q.order_by(Snapshot.id.desc()).first()
    if not snap:
        return {"users": [], "privileged_policies": []}
    cfg = snap.config_json or {}
    users = []
    for u in cfg.get("Users", []):
        users.append(
            {
                "username": u.get("UserName"),
                "arn": u.get("Arn"),
                "mfa": bool(u.get("MFADevices")),
                "access_keys": [
                    {
                        "id": k.get("AccessKeyId"),
                        "status": k.get("Status"),
                        "created": str(k.get("CreateDate")),
                    }
                    for k in u.get("AccessKeys", [])
                ],
                "attached_policies": [p.get("PolicyName") for p in u.get("AttachedPolicies", [])],
            }
        )
    return {
        "users": users,
        "privileged_policies": cfg.get("WildcardAdminPolicies", []),
        "root": cfg.get("Root", {}),
    }


def policy_compliance(db: Session, scan_id: int) -> list[dict]:
    """Derive policy compliance from linked control results for a scan."""
    results = {
        r.control_id: r
        for r in db.query(ControlResult).filter(ControlResult.scan_id == scan_id).all()
    }
    out = []
    for policy in db.query(Policy).all():
        linked = policy.linked_control_ids or []
        statuses = [results[cid].status for cid in linked if cid in results]
        if not statuses:
            overall = "NOT_ASSESSED"
        elif any(s == "FAIL" for s in statuses):
            overall = "FAIL"
        elif any(s == "EXCEPTION" for s in statuses):
            overall = "EXCEPTION"
        elif all(s == "PASS" for s in statuses):
            overall = "PASS"
        else:
            overall = "NOT_ASSESSED"
        out.append(
            {
                "id": policy.id,
                "name": policy.name,
                "statement": policy.statement,
                "linked_control_ids": linked,
                "status": overall,
                "control_statuses": statuses,
            }
        )
    return out
