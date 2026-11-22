from __future__ import annotations

from typing import Any

from app.assessment.registry import register_check
from app.schemas import NormalizedFinding


@register_check("ebs_default_encryption")
def ebs_default_encryption(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = snapshots.get("ec2", {}).get("ebs-default-encryption", {})
    enabled = bool(cfg.get("EbsEncryptionByDefault"))
    return [
        NormalizedFinding(
            check_id="ebs_default_encryption",
            source="custom",
            asset_arn="arn:aws:ec2:us-east-1:123456789012:volume/default-encryption",
            title="EBS default encryption enabled",
            description="EBS encryption by default should be enabled in the region.",
            severity="medium",
            status="PASS" if enabled else "FAIL",
            evidence=cfg,
            remediation="Enable EBS encryption by default in EC2 settings.",
        )
    ]


@register_check("rds_encrypted")
def rds_encrypted(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    rds = snapshots.get("rds", {})
    for rid, cfg in rds.items():
        inst = cfg.get("DBInstance", cfg)
        encrypted = bool(inst.get("StorageEncrypted"))
        arn = inst.get("DBInstanceArn") or f"arn:aws:rds:us-east-1:123456789012:db:{rid}"
        findings.append(
            NormalizedFinding(
                check_id="rds_encrypted",
                source="custom",
                asset_arn=arn,
                title=f"RDS encryption: {rid}",
                description="RDS instances must have storage encryption enabled.",
                severity="high",
                status="PASS" if encrypted else "FAIL",
                evidence={
                    "StorageEncrypted": encrypted,
                    "PubliclyAccessible": inst.get("PubliclyAccessible"),
                },
                remediation="Recreate the RDS instance with storage encryption enabled.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="rds_encrypted",
            source="custom",
            title="RDS encryption",
            description="No RDS instances found.",
            severity="high",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("kms_key_rotation_enabled")
def kms_key_rotation_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    keys = snapshots.get("kms", {}).get("keys", {}).get("Keys", [])
    findings: list[NormalizedFinding] = []
    customer_keys = [k for k in keys if k.get("KeyManager") == "CUSTOMER"]
    for key in customer_keys:
        ok = bool(key.get("KeyRotationEnabled"))
        findings.append(
            NormalizedFinding(
                check_id="kms_key_rotation_enabled",
                source="custom",
                asset_arn=key.get("Arn"),
                title=f"KMS key rotation: {key.get('KeyId')}",
                description="Customer-managed KMS keys should have rotation enabled.",
                severity="low",
                status="PASS" if ok else "FAIL",
                evidence={"KeyId": key.get("KeyId"), "KeyRotationEnabled": key.get("KeyRotationEnabled")},
                remediation="Enable automatic annual key rotation on the CMK.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="kms_key_rotation_enabled",
            source="custom",
            title="KMS key rotation",
            description="No customer-managed KMS keys found.",
            severity="low",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]
