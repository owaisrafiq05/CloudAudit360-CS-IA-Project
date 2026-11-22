from __future__ import annotations

from typing import Any

from app.assessment.registry import register_check
from app.schemas import NormalizedFinding


def _security_groups(snapshots: dict[str, Any]) -> list[tuple[str, dict]]:
    ec2 = snapshots.get("ec2", {})
    results = []
    for rid, cfg in ec2.items():
        if "SecurityGroup" in cfg:
            results.append((rid, cfg["SecurityGroup"]))
    return results


def _open_to_world(sg: dict, port: int | None = None, all_traffic: bool = False) -> bool:
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        if not world:
            continue
        if all_traffic and proto == "-1":
            return True
        if port is not None:
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            if from_p is not None and to_p is not None and from_p <= port <= to_p:
                return True
    return False


@register_check("sg_no_ssh_open_world")
def sg_no_ssh_open_world(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for sg_id, sg in _security_groups(snapshots):
        open_ssh = _open_to_world(sg, port=22)
        owner = sg.get("OwnerId", "123456789012")
        region = "us-east-1"
        arn = f"arn:aws:ec2:{region}:{owner}:security-group/{sg_id}"
        findings.append(
            NormalizedFinding(
                check_id="sg_no_ssh_open_world",
                source="custom",
                asset_arn=arn,
                title=f"SSH not open to world: {sg.get('GroupName', sg_id)}",
                description="Security groups must not allow SSH (22) from 0.0.0.0/0.",
                severity="high",
                status="FAIL" if open_ssh else "PASS",
                evidence={"GroupId": sg_id, "IpPermissions": sg.get("IpPermissions", [])},
                remediation="Restrict SSH ingress to known management CIDRs or remove the rule.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="sg_no_ssh_open_world",
            source="custom",
            title="SSH not open to world",
            description="No security groups found.",
            severity="high",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("sg_no_rdp_open_world")
def sg_no_rdp_open_world(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for sg_id, sg in _security_groups(snapshots):
        open_rdp = _open_to_world(sg, port=3389)
        owner = sg.get("OwnerId", "123456789012")
        arn = f"arn:aws:ec2:us-east-1:{owner}:security-group/{sg_id}"
        findings.append(
            NormalizedFinding(
                check_id="sg_no_rdp_open_world",
                source="custom",
                asset_arn=arn,
                title=f"RDP not open to world: {sg.get('GroupName', sg_id)}",
                description="Security groups must not allow RDP (3389) from 0.0.0.0/0.",
                severity="high",
                status="FAIL" if open_rdp else "PASS",
                evidence={"GroupId": sg_id, "IpPermissions": sg.get("IpPermissions", [])},
                remediation="Restrict RDP ingress to known management CIDRs or remove the rule.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="sg_no_rdp_open_world",
            source="custom",
            title="RDP not open to world",
            description="No security groups found.",
            severity="high",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("sg_no_all_traffic_open_world")
def sg_no_all_traffic_open_world(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for sg_id, sg in _security_groups(snapshots):
        open_all = _open_to_world(sg, all_traffic=True)
        owner = sg.get("OwnerId", "123456789012")
        arn = f"arn:aws:ec2:us-east-1:{owner}:security-group/{sg_id}"
        findings.append(
            NormalizedFinding(
                check_id="sg_no_all_traffic_open_world",
                source="custom",
                asset_arn=arn,
                title=f"All-traffic not open to world: {sg.get('GroupName', sg_id)}",
                description="Security groups must not allow all protocols from 0.0.0.0/0.",
                severity="critical",
                status="FAIL" if open_all else "PASS",
                evidence={"GroupId": sg_id, "IpPermissions": sg.get("IpPermissions", [])},
                remediation="Remove the all-traffic (protocol -1) rule open to 0.0.0.0/0.",
            )
        )
    return findings or [
        NormalizedFinding(
            check_id="sg_no_all_traffic_open_world",
            source="custom",
            title="All-traffic not open to world",
            description="No security groups found.",
            severity="critical",
            status="PASS",
            evidence={},
            remediation="N/A",
        )
    ]


@register_check("vpc_flow_logs_enabled")
def vpc_flow_logs_enabled(snapshots: dict[str, Any]) -> list[NormalizedFinding]:
    cfg = snapshots.get("ec2", {}).get("vpc-flow-logs", {})
    logs = cfg.get("FlowLogs", [])
    enabled = len(logs) > 0
    return [
        NormalizedFinding(
            check_id="vpc_flow_logs_enabled",
            source="custom",
            asset_arn="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-lab",
            title="VPC Flow Logs enabled",
            description="VPC Flow Logs should be enabled for network visibility.",
            severity="medium",
            status="PASS" if enabled else "FAIL",
            evidence={"FlowLogs": logs},
            remediation="Enable VPC Flow Logs to CloudWatch Logs or S3 for all VPCs.",
        )
    ]
