from app.db import Base, SessionLocal, engine
from app.grc.compliance import evaluate_controls, framework_scores
from app.models import CheckControlMap, Control, Finding, Scan
from app.seed import run_seed


def setup_module():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        run_seed(db)
    finally:
        db.close()


def test_framework_scores_fail_then_pass():
    db = SessionLocal()
    try:
        scan = Scan(environment="vulnerable", status="completed", label="t", triggered_by="test")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Create a FAIL for a mapped check
        db.add(
            Finding(
                scan_id=scan.id,
                check_id="iam_root_mfa_enabled",
                source="custom",
                title="Root MFA",
                description="x",
                severity="critical",
                status="FAIL",
                evidence_json={},
                remediation="enable mfa",
            )
        )
        db.commit()
        evaluate_controls(db, scan.id)
        db.commit()
        scores = {s.framework: s for s in framework_scores(db, scan.id)}
        assert scores["CIS"].fail_count >= 1
        assert scores["CIS"].score < 100

        # Second scan all pass for that check
        scan2 = Scan(environment="hardened", status="completed", label="t2", triggered_by="test")
        db.add(scan2)
        db.commit()
        db.refresh(scan2)
        # Add PASS for all mapped check ids to drive high score
        mapped = {m.check_id for m in db.query(CheckControlMap).all()}
        for check_id in mapped:
            db.add(
                Finding(
                    scan_id=scan2.id,
                    check_id=check_id,
                    source="custom",
                    title=check_id,
                    description="ok",
                    severity="medium",
                    status="PASS",
                    evidence_json={},
                    remediation="n/a",
                )
            )
        db.commit()
        evaluate_controls(db, scan2.id)
        db.commit()
        scores2 = {s.framework: s for s in framework_scores(db, scan2.id)}
        assert scores2["CIS"].score == 100.0
        assert scores2["ISO27001"].score == 100.0
        assert scores2["NIST"].score == 100.0
    finally:
        db.close()
