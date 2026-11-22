from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import yaml

from app.assessment.registry import register_check
from app.config import DATA_DIR
from app.schemas import NormalizedFinding


def _risk_cfg() -> dict:
    with (DATA_DIR / "risk_config.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _iam_snapshots(snapshots: dict[str, Any]) -> dict[str, Any]:
    return snapshots.get("iam", {}).get("account", {})


@register_check("iam_root_mfa_enabled")
def iam_root_mfa_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    root = cfg.get("Root", {})
    enabled = bool(root.get("MFAEnabled"))
    return [
        NormalizedFinding(
            check_id="iam_root_mfa_enabled",
            source="custom",
            asset_arn="arn:aws:iam::123456789012:root",
            title="Root account MFA enabled",
            description="The AWS root account must have MFA enabled.",
            severity="critical",
            status="PASS" if enabled else "FAIL",
            evidence={"Root": root},
            remediation="Enable a virtual or hardware MFA device on the root account.",
        )
    ]


@register_check("iam_root_no_access_keys")
def iam_root_no_access_keys(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    root = cfg.get("Root", {})
    present = bool(root.get("AccessKeysPresent"))
    return [
        NormalizedFinding(
            check_id="iam_root_no_access_keys",
            source="custom",
            asset_arn="arn:aws:iam::123456789012:root",
            title="Root account has no access keys",
            description="Root access keys must not exist.",
            severity="critical",
            status="FAIL" if present else "PASS",
            evidence={"Root": root},
            remediation="Delete any root access keys and use IAM users/roles instead.",
        )
    ]


@register_check("iam_user_mfa_enabled")
def iam_user_mfa_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    findings: list[NormalizedFinding] = []
    for user in cfg.get("Users", []):
        has_mfa = bool(user.get("MFADevices"))
        findings.append(
            NormalizedFinding(
                check_id="iam_user_mfa_enabled",
                source="custom",
                asset_arn=user.get("Arn"),
                title=f"MFA enabled for IAM user {user.get('UserName')}",
                description="IAM users with console access should have MFA enabled.",
                severity="high",
                status="PASS" if has_mfa else "FAIL",
                evidence={"UserName": user.get("UserName"), "MFADevices": user.get("MFADevices", [])},
                remediation="Enable MFA for the IAM user in the AWS console.",
            )
        )
    if not findings:
        findings.append(
            NormalizedFinding(
                check_id="iam_user_mfa_enabled",
                source="custom",
                asset_arn=None,
                title="MFA enabled for IAM users",
                description="No IAM users found to assess.",
                severity="high",
                status="PASS",
                evidence={"Users": []},
                remediation="N/A",
            )
        )
    return findings


@register_check("iam_password_policy_strong")
def iam_password_policy_strong(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    policy = cfg.get("PasswordPolicy") or {}
    req = _risk_cfg().get("password_policy", {})
    checks = {
        "min_length": policy.get("MinimumPasswordLength", 0) >= req.get("min_length", 14),
        "symbols": policy.get("RequireSymbols") is True if req.get("require_symbols") else True,
        "numbers": policy.get("RequireNumbers") is True if req.get("require_numbers") else True,
        "upper": policy.get("RequireUppercaseCharacters") is True
        if req.get("require_uppercase")
        else True,
        "lower": policy.get("RequireLowercaseCharacters") is True
        if req.get("require_lowercase")
        else True,
    }
    ok = all(checks.values())
    return [
        NormalizedFinding(
            check_id="iam_password_policy_strong",
            source="custom",
            asset_arn="arn:aws:iam::123456789012:root",
            title="Strong IAM password policy",
            description="Password policy must enforce length >= 14 and complexity.",
            severity="medium",
            status="PASS" if ok else "FAIL",
            evidence={"PasswordPolicy": policy, "Checks": checks},
            remediation="Update the account password policy to require 14+ chars and complexity.",
        )
    ]


@register_check("iam_access_key_rotated_90d")
def iam_access_key_rotated_90d(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    max_age = _risk_cfg().get("access_key_max_age_days", 90)
    now = datetime.now(timezone.utc)
    findings: list[NormalizedFinding] = []
    for user in cfg.get("Users", []):
        for key in user.get("AccessKeys", []):
            created = key.get("CreateDate")
            age_days = None
            if created:
                if isinstance(created, str):
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                else:
                    created_dt = created
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_days = (now - created_dt).days
            stale = age_days is not None and age_days > max_age
            findings.append(
                NormalizedFinding(
                    check_id="iam_access_key_rotated_90d",
                    source="custom",
                    asset_arn=user.get("Arn"),
                    title=f"Access key rotation for {user.get('UserName')}",
                    description=f"Access keys must be rotated within {max_age} days.",
                    severity="medium",
                    status="FAIL" if stale else "PASS",
                    evidence={
                        "AccessKeyId": key.get("AccessKeyId"),
                        "CreateDate": str(created),
                        "AgeDays": age_days,
                    },
                    remediation="Rotate the access key and deactivate the old key.",
                )
            )
    if not findings:
        findings.append(
            NormalizedFinding(
                check_id="iam_access_key_rotated_90d",
                source="custom",
                asset_arn=None,
                title="Access key rotation",
                description="No access keys found.",
                severity="medium",
                status="PASS",
                evidence={},
                remediation="N/A",
            )
        )
    return findings


@register_check("iam_no_wildcard_admin_policy")
def iam_no_wildcard_admin_policy(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = _iam_snapshots(snapshots)
    wildcards = cfg.get("WildcardAdminPolicies", [])
    # Also flag users with AdministratorAccess attached
    admin_users = [
        u
        for u in cfg.get("Users", [])
        if any(p.get("PolicyName") == "AdministratorAccess" for p in u.get("AttachedPolicies", []))
    ]
    fail = bool(wildcards) or bool(admin_users)
    # Stable account-level ARN so PASS/FAIL map to the same risk register key
    return [
        NormalizedFinding(
            check_id="iam_no_wildcard_admin_policy",
            source="custom",
            asset_arn="arn:aws:iam::123456789012:root",
            title="No wildcard / full-admin IAM policies",
            description="IAM policies must not grant Action:* Resource:* or AdministratorAccess broadly.",
            severity="high",
            status="FAIL" if fail else "PASS",
            evidence={
                "WildcardAdminPolicies": wildcards,
                "AdminUsers": [u.get("UserName") for u in admin_users],
            },
            remediation="Replace AdministratorAccess with least-privilege policies.",
        )
    ]
