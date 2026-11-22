"""Prowler adapter — runs prowler if available, or parses supplied JSON."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.schemas import NormalizedFinding

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


def _status_from_ocsf(finding: dict) -> str:
    status = str(finding.get("status_code") or finding.get("Status") or "").upper()
    if status in ("PASS", "FAIL", "ERROR"):
        return status
    # OCSF often uses status_id / status
    raw = str(finding.get("status") or "").lower()
    if "fail" in raw or "not pass" in raw:
        return "FAIL"
    if "pass" in raw:
        return "PASS"
    return "FAIL" if finding.get("status_code") == "FAIL" else "PASS"


def parse_prowler_json(path: Path) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return findings

    # Prowler may emit NDJSON or a JSON array
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else data.get("findings", [data])
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for rec in records:
        check_id = (
            rec.get("finding_info", {}).get("uid")
            or rec.get("CheckID")
            or rec.get("check_id")
            or "prowler_unknown"
        )
        title = (
            rec.get("finding_info", {}).get("title")
            or rec.get("CheckTitle")
            or rec.get("title")
            or str(check_id)
        )
        severity_raw = str(
            rec.get("severity") or rec.get("Severity") or "medium"
        ).lower()
        severity = SEVERITY_MAP.get(severity_raw, "medium")
        asset = (
            rec.get("resources", [{}])[0].get("uid")
            if rec.get("resources")
            else rec.get("ResourceArn") or rec.get("resource_arn")
        )
        findings.append(
            NormalizedFinding(
                check_id=str(check_id),
                source="prowler",
                asset_arn=asset,
                title=str(title),
                description=str(rec.get("finding_info", {}).get("desc") or rec.get("StatusExtended") or title),
                severity=severity,  # type: ignore[arg-type]
                status=_status_from_ocsf(rec),  # type: ignore[arg-type]
                evidence=rec if isinstance(rec, dict) else {"raw": rec},
                remediation=str(rec.get("remediation", {}).get("desc") or rec.get("Remediation") or ""),
            )
        )
    return findings


def collect_findings(json_path: str | Path | None = None) -> list[NormalizedFinding]:
    if json_path:
        return parse_prowler_json(Path(json_path))

    binary = shutil.which("prowler")
    if not binary:
        logger.warning("Prowler binary not found; skipping Prowler adapter")
        return []

    with tempfile.TemporaryDirectory(prefix="prowler_") as tmp:
        out_dir = Path(tmp)
        try:
            subprocess.run(
                [binary, "aws", "-M", "json-ocsf", "-o", str(out_dir)],
                check=False,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Prowler execution failed: %s", exc)
            return []

        json_files = list(out_dir.rglob("*.json"))
        results: list[NormalizedFinding] = []
        for f in json_files:
            results.extend(parse_prowler_json(f))
        return results
