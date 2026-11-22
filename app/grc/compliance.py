"""Control status evaluation and framework compliance scores."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import CheckControlMap, Control, ControlResult, ExceptionRecord, Finding, Risk
from app.schemas import ComplianceScore


def _active_exception_risk_ids(db: Session, scan_id: int) -> set[int]:
    """Risks covered by an active, non-expired approved exception."""
    now = datetime.utcnow()
    rows = (
        db.query(ExceptionRecord)
        .filter(ExceptionRecord.status == "active")
        .all()
    )
    covered: set[int] = set()
    for exc in rows:
        if exc.expires_at and exc.expires_at < now:
            continue
        if exc.approved_by:  # approved
            covered.add(exc.risk_id)
    return covered


def evaluate_controls(db: Session, scan_id: int) -> list[ControlResult]:
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    # Prefer custom when both custom and prowler exist for same check+asset (dedup for scoring)
    by_key: dict[tuple[str, int | None], Finding] = {}
    for f in findings:
        key = (f.check_id, f.asset_id)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
        elif f.source == "custom" and existing.source != "custom":
            by_key[key] = f

    scored_findings = list(by_key.values())

    maps = db.query(CheckControlMap).all()
    control_checks: dict[int, set[str]] = defaultdict(set)
    for m in maps:
        control_checks[m.control_id].add(m.check_id)

    # finding_key -> risk for exception mapping
    risks = {r.finding_key: r for r in db.query(Risk).all()}
    excepted_risk_ids = _active_exception_risk_ids(db, scan_id)

    # Clear previous results for this scan
    db.query(ControlResult).filter(ControlResult.scan_id == scan_id).delete()

    results: list[ControlResult] = []
    all_controls = db.query(Control).all()
    for ctrl in all_controls:
        check_ids = control_checks.get(ctrl.id, set())
        if not check_ids:
            status = "NOT_ASSESSED"
            fail_count = 0
        else:
            relevant = [f for f in scored_findings if f.check_id in check_ids]
            if not relevant:
                status = "NOT_ASSESSED"
                fail_count = 0
            else:
                failing = [f for f in relevant if f.status == "FAIL"]
                fail_count = len(failing)
                if fail_count == 0:
                    status = "PASS"
                else:
                    # EXCEPTION if all failing findings have an active exception
                    all_excepted = True
                    for f in failing:
                        asset = f.asset
                        arn = asset.arn if asset else ""
                        finding_key = f"{f.check_id}+{arn}"
                        risk = risks.get(finding_key)
                        if not risk or risk.id not in excepted_risk_ids:
                            all_excepted = False
                            break
                    status = "EXCEPTION" if all_excepted else "FAIL"

        row = ControlResult(
            scan_id=scan_id,
            control_id=ctrl.id,
            status=status,
            failing_finding_count=fail_count,
        )
        db.add(row)
        results.append(row)

    db.flush()
    return results


def framework_scores(db: Session, scan_id: int) -> list[ComplianceScore]:
    rows = (
        db.query(ControlResult, Control)
        .join(Control, Control.id == ControlResult.control_id)
        .filter(ControlResult.scan_id == scan_id)
        .all()
    )
    by_fw: dict[str, list[ControlResult]] = defaultdict(list)
    for result, ctrl in rows:
        by_fw[ctrl.framework].append(result)

    scores: list[ComplianceScore] = []
    for framework, results in sorted(by_fw.items()):
        pass_c = sum(1 for r in results if r.status == "PASS")
        fail_c = sum(1 for r in results if r.status == "FAIL")
        exc_c = sum(1 for r in results if r.status == "EXCEPTION")
        na_c = sum(1 for r in results if r.status == "NOT_ASSESSED")
        denom = pass_c + fail_c + exc_c
        score = (pass_c / denom * 100.0) if denom else 0.0
        total = len(results)
        coverage = ((total - na_c) / total * 100.0) if total else 0.0
        scores.append(
            ComplianceScore(
                framework=framework,
                pass_count=pass_c,
                fail_count=fail_c,
                exception_count=exc_c,
                not_assessed=na_c,
                score=round(score, 1),
                coverage=round(coverage, 1),
            )
        )
    return scores
