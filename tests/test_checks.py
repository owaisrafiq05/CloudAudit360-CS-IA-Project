import json
from pathlib import Path

from app.assessment.engine import run_custom_checks
from app.config import DATA_DIR


def _load_fixture(name: str) -> dict:
    raw = json.loads((DATA_DIR / "fixtures" / name).read_text(encoding="utf-8"))
    indexed: dict[str, dict] = {}
    for item in raw["snapshots"]:
        indexed.setdefault(item["service"], {})[item["resource_id"]] = item["config"]
    return indexed


def test_vulnerable_fixture_all_fail():
    findings = run_custom_checks(_load_fixture("vulnerable.json"))
    assert findings
    fails = [f for f in findings if f.status == "FAIL"]
    passes = [f for f in findings if f.status == "PASS"]
    assert len(fails) == 20
    assert len(passes) == 0


def test_hardened_fixture_all_pass():
    findings = run_custom_checks(_load_fixture("hardened.json"))
    assert findings
    fails = [f for f in findings if f.status == "FAIL"]
    passes = [f for f in findings if f.status == "PASS"]
    assert len(fails) == 0
    assert len(passes) == 20


def test_check_ids_cover_spec_minimum():
    findings = run_custom_checks(_load_fixture("vulnerable.json"))
    ids = {f.check_id for f in findings}
    required = {
        "iam_root_mfa_enabled",
        "iam_root_no_access_keys",
        "iam_user_mfa_enabled",
        "iam_password_policy_strong",
        "iam_access_key_rotated_90d",
        "iam_no_wildcard_admin_policy",
        "s3_public_access_blocked",
        "s3_encryption_enabled",
        "s3_versioning_enabled",
        "s3_tls_only_policy",
        "sg_no_ssh_open_world",
        "sg_no_rdp_open_world",
        "sg_no_all_traffic_open_world",
        "vpc_flow_logs_enabled",
        "cloudtrail_enabled_multiregion",
        "cloudtrail_log_validation",
        "guardduty_enabled",
        "ebs_default_encryption",
        "rds_encrypted",
        "kms_key_rotation_enabled",
    }
    assert required.issubset(ids)
