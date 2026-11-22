from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.db import get_db
from app.grc.compliance import framework_scores
from app.grc.mapping import unmapped_check_ids
from app.grc.review import policy_compliance
from app.models import CheckControlMap, Control, ControlResult, Finding, Scan

router = APIRouter(tags=["controls"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/controls")
def controls_page(
    request: Request,
    db: Session = Depends(get_db),
    framework: str | None = None,
    scan: int | None = None,
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    scans = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).all()
    scan_id = scan or (scans[0].id if scans else None)
    frameworks = [r[0] for r in db.query(Control.framework).distinct().all()]
    fw = framework or (frameworks[0] if frameworks else "CIS")

    rows = []
    gaps_fail = []
    gaps_na = []
    if scan_id:
        q = (
            db.query(ControlResult, Control)
            .join(Control, Control.id == ControlResult.control_id)
            .filter(ControlResult.scan_id == scan_id, Control.framework == fw)
            .order_by(Control.control_ref)
        )
        for result, ctrl in q.all():
            rows.append({"control": ctrl, "result": result})
            if result.status == "FAIL":
                gaps_fail.append(ctrl)
            elif result.status == "NOT_ASSESSED":
                gaps_na.append(ctrl)

    scores = framework_scores(db, scan_id) if scan_id else []
    policies = policy_compliance(db, scan_id) if scan_id else []

    check_ids = set()
    if scan_id:
        check_ids = {f.check_id for f in db.query(Finding).filter(Finding.scan_id == scan_id).all()}
    unmapped = unmapped_check_ids(db, check_ids) if check_ids else []

    return templates.TemplateResponse(
        "controls.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "frameworks": frameworks,
            "framework": fw,
            "scans": scans,
            "scan_id": scan_id,
            "scores": scores,
            "gaps_fail": gaps_fail,
            "gaps_na": gaps_na,
            "policies": policies,
            "unmapped": unmapped,
        },
    )
