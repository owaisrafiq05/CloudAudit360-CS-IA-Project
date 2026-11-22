from __future__ import annotations

import json
from typing import Any

from app.assessment.registry import register_check
from app.schemas import NormalizedFinding


def _s3_buckets(snapshots: dict[str, Any]) -> list[tuple[str, dict]]:
    s3 = snapshots.get("s3", {})
    return [(rid, cfg) for rid, cfg in s3.items()]


@register_check("s3_public_access_blocked")
def s3_public_access_blocked(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for name, cfg in _s3_buckets(snapshots):
        pab = cfg.get("PublicAccessBlock") or {}
        blocked = all(
            [
                pab.get("BlockPublicAcls") is True,
                pab.get("IgnorePublicAcls") is True,
                pab.get("BlockPublicPolicy") is True,
                pab.get("RestrictPublicBuckets") is True,
            ]
        )
        findings.append(
            NormalizedFinding(
                check_id="s3_public_access_blocked",
                source="custom",
                asset_arn=f"arn:aws:s3:::{name}",
                title=f"S3 public access blocked: {name}",
                description="S3 Block Public Access settings must all be enabled.",
                severity="high",
                status="PASS" if blocked else "FAIL",
                evidence={"PublicAccessBlock": pab},
                remediation="Enable all four Block Public Access settings on the bucket/account.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="s3_public_access_blocked",
            source="custom",
            title="S3 public access blocked",
            description="No S3 buckets found.",
            severity="high",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("s3_encryption_enabled")
def s3_encryption_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for name, cfg in _s3_buckets(snapshots):
        enc = cfg.get("Encryption") or {}
        rules = enc.get("Rules") if isinstance(enc, dict) else None
        enabled = bool(rules)
        findings.append(
            NormalizedFinding(
                check_id="s3_encryption_enabled",
                source="custom",
                asset_arn=f"arn:aws:s3:::{name}",
                title=f"S3 encryption enabled: {name}",
                description="S3 default encryption must be configured.",
                severity="medium",
                status="PASS" if enabled else "FAIL",
                evidence={"Encryption": enc},
                remediation="Enable SSE-S3 or SSE-KMS default encryption on the bucket.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="s3_encryption_enabled",
            source="custom",
            title="S3 encryption enabled",
            description="No S3 buckets found.",
            severity="medium",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("s3_versioning_enabled")
def s3_versioning_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for name, cfg in _s3_buckets(snapshots):
        versioning = cfg.get("Versioning") or {}
        enabled = versioning.get("Status") == "Enabled"
        findings.append(
            NormalizedFinding(
                check_id="s3_versioning_enabled",
                source="custom",
                asset_arn=f"arn:aws:s3:::{name}",
                title=f"S3 versioning enabled: {name}",
                description="S3 versioning should be enabled for recovery.",
                severity="low",
                status="PASS" if enabled else "FAIL",
                evidence={"Versioning": versioning},
                remediation="Enable versioning on the S3 bucket.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="s3_versioning_enabled",
            source="custom",
            title="S3 versioning enabled",
            description="No S3 buckets found.",
            severity="low",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("s3_tls_only_policy")
def s3_tls_only_policy(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for name, cfg in _s3_buckets(snapshots):
        policy_raw = cfg.get("Policy")
        has_tls = False
        if policy_raw:
            try:
                policy = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
                for stmt in policy.get("Statement", []):
                    cond = stmt.get("Condition", {})
                    bool_cond = cond.get("Bool", {})
                    if (
                        stmt.get("Effect") == "Deny"
                        and str(bool_cond.get("aws:SecureTransport", "")).lower() == "false"
                    ):
                        has_tls = True
            except (json.JSONDecodeError, TypeError, AttributeError):
                has_tls = False
        findings.append(
            NormalizedFinding(
                check_id="s3_tls_only_policy",
                source="custom",
                asset_arn=f"arn:aws:s3:::{name}",
                title=f"S3 TLS-only policy: {name}",
                description="Bucket policy must deny insecure (non-TLS) transport.",
                severity="medium",
                status="PASS" if has_tls else "FAIL",
                evidence={"PolicyPresent": bool(policy_raw), "HasTLSDeny": has_tls},
                remediation="Add a Deny statement conditioned on aws:SecureTransport=false.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="s3_tls_only_policy",
            source="custom",
            title="S3 TLS-only policy",
            description="No S3 buckets found.",
            severity="medium",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]
