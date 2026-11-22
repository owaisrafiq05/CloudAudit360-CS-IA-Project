"""Build audit and technical reports (HTML + optional PDF)."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app.config import REPORT_DIR
from app.grc.compliance import framework_scores
from app.models import (
    Asset,
    Control,
    ControlResult,
    Evidence,
    ExceptionRecord,
    Finding,
    Report,
    Risk,
    Scan,
)
from app.web.compare import compare_scans

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _build_context(db: Session, scan_id: int, report_type: str) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.severity.desc()).all()
    scores = framework_scores(db, scan_id)
    control_rows = (
        db.query(ControlResult, Control)
        .join(Control, Control.id == ControlResult.control_id)
        .filter(ControlResult.scan_id == scan_id)
        .order_by(Control.framework, Control.control_ref)
        .all()
    )
    risks = db.query(Risk).order_by(Risk.inherent_score.desc()).all()
    exceptions = db.query(ExceptionRecord).all()
    evidence = db.query(Evidence).filter(Evidence.scan_id == scan_id).all()
    assets = db.query(Asset).all()
    regions = sorted({a.region for a in assets})

    prev = (
        db.query(Scan)
        .filter(Scan.id < scan_id, Scan.status == "completed")
        .order_by(Scan.id.desc())
        .first()
    )
    comparison = compare_scans(db, prev.id, scan_id) if prev else None

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "report_type": report_type,
        "scan": scan,
        "findings": findings,
        "scores": scores,
        "control_rows": control_rows,
        "risks": risks,
        "exceptions": exceptions,
        "evidence": evidence,
        "assets": assets,
        "regions": regions,
        "frameworks": sorted({s.framework for s in scores}),
        "comparison": comparison,
        "fail_count": sum(1 for f in findings if f.status == "FAIL"),
        "pass_count": sum(1 for f in findings if f.status == "PASS"),
    }


def generate_report(
    db: Session,
    *,
    scan_id: int,
    report_type: str = "audit",
    fmt: str = "html",
    created_by: str | None = None,
) -> Report:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ctx = _build_context(db, scan_id, report_type)
    template_name = "report_audit.html" if report_type == "audit" else "report_technical.html"
    html = env.get_template(template_name).render(**ctx)

    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    base = REPORT_DIR / f"{report_type}_scan{scan_id}_{stamp}"
    html_path = base.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    out_path = html_path

    if fmt == "pdf":
        pdf_path = base.with_suffix(".pdf")
        try:
            from weasyprint import HTML

            HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(pdf_path))
            out_path = pdf_path
        except Exception as exc:  # noqa: BLE001
            logger.warning("PDF generation failed (%s); keeping HTML", exc)
            fmt = "html"

    report = Report(
        scan_id=scan_id,
        report_type=report_type,
        format=fmt,
        path=str(out_path),
        created_by=created_by,
    )
    db.add(report)
    db.flush()
    return report
