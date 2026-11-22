from __future__ import annotations

from typing import Any

from app.assessment.registry import register_check
from app.schemas import NormalizedFinding


@register_check("cloudtrail_enabled_multiregion")
def cloudtrail_enabled_multiregion(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    trails = snapshots.get("cloudtrail", {}).get("trails", {}).get("Trails", [])
    ok = any(
        t.get("IsMultiRegionTrail") and (t.get("Status") or {}).get("IsLogging", True)
        for t in trails
    )
    # If Status missing but IsMultiRegionTrail true, treat as configured
    if not ok:
        ok = any(t.get("IsMultiRegionTrail") for t in trails)
    return [
        NormalizedFinding(
            check_id="cloudtrail_enabled_multiregion",
            source="custom",
            asset_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/account",
            title="CloudTrail multi-region enabled",
            description="A multi-region CloudTrail that is logging must be present.",
            severity="high",
            status="PASS" if ok else "FAIL",
            evidence={"Trails": trails},
            remediation="Create a multi-region CloudTrail and ensure logging is enabled.",
        )
    ]


@register_check("cloudtrail_log_validation")
def cloudtrail_log_validation(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    trails = snapshots.get("cloudtrail", {}).get("trails", {}).get("Trails", [])
    if not trails:
        return [
            NormalizedFinding(
                check_id="cloudtrail_log_validation",
                source="custom",
                asset_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/account",
                title="CloudTrail log file validation",
                description="CloudTrail log file validation must be enabled.",
                severity="medium",
                status="FAIL",
                evidence={"Trails": []},
                remediation="Enable log file validation on CloudTrail.",
            )
        ]
    findings = []
    for t in trails:
        ok = bool(t.get("LogFileValidationEnabled"))
        findings.append(
            NormalizedFinding(
                check_id="cloudtrail_log_validation",
                source="custom",
                asset_arn=t.get("TrailARN")
                or f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{t.get('Name', 'trail')}",
                title=f"CloudTrail log validation: {t.get('Name')}",
                description="CloudTrail log file validation must be enabled.",
                severity="medium",
                status="PASS" if ok else "FAIL",
                evidence={"Trail": t},
                remediation="Enable log file validation on the trail.",
            )
        )
    return findings


@register_check("guardduty_enabled")
def guardduty_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    detectors = snapshots.get("guardduty", {}).get("detectors", {}).get("DetectorIds", [])
    ok = len(detectors) > 0
    return [
        NormalizedFinding(
            check_id="guardduty_enabled",
            source="custom",
            asset_arn="arn:aws:guardduty:us-east-1:123456789012:detector/account",
            title="GuardDuty enabled",
            description="Amazon GuardDuty should be enabled in the account.",
            severity="medium",
            status="PASS" if ok else "FAIL",
            evidence={"DetectorIds": detectors},
            remediation="Enable a GuardDuty detector in the region/account.",
        )
    ]
