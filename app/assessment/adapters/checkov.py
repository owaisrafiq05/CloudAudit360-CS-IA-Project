"""Checkov adapter — scans infra/ Terraform if checkov is installed."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.config import BASE_DIR
from app.schemas import NormalizedFinding

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def parse_checkov_json(path: Path) -> list[NormalizedFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[NormalizedFinding] = []

    # checkov JSON may be a list of framework results or a single object
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        results = block.get("results", {})
        for failed in results.get("failed_checks", []):
            findings.append(_to_finding(failed, "FAIL"))
        for passed in results.get("passed_checks", []):
            findings.append(_to_finding(passed, "PASS"))
    return findings


def _to_finding(check: dict, status: str) -> NormalizedFinding:
    severity = SEVERITY_MAP.get(str(check.get("severity", "MEDIUM")).upper(), "medium")
    return NormalizedFinding(
        check_id=str(check.get("check_id") or check.get("id") or "checkov_unknown"),
        source="checkov",
        asset_arn=check.get("resource") or check.get("file_path"),
        title=str(check.get("check_name") or check.get("name") or "Checkov finding"),
        description=str(check.get("description") or check.get("check_name") or ""),
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        evidence=check,
        remediation=str(check.get("guideline") or "Review Checkov remediation guidance."),
    )


def collect_findings(
    directory: str | Path | None = None,
    json_path: str | Path | None = None,
) -> list[NormalizedFinding]:
    if json_path:
        return parse_checkov_json(Path(json_path))

    binary = shutil.which("checkov")
    if not binary:
        logger.warning("Checkov binary not found; skipping Checkov adapter")
        return []

    target = Path(directory) if directory else BASE_DIR / "infra"
    if not target.exists():
        logger.warning("Checkov target directory missing: %s", target)
        return []

    with tempfile.TemporaryDirectory(prefix="checkov_") as tmp:
        out_file = Path(tmp) / "results.json"
        try:
            subprocess.run(
                [binary, "-d", str(target), "-o", "json", "--output-file-path", str(tmp)],
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Checkov execution failed: %s", exc)
            return []

        # checkov may write results_json.json or similar
        candidates = list(Path(tmp).rglob("*.json"))
        if out_file.exists():
            candidates.insert(0, out_file)
        results: list[NormalizedFinding] = []
        for f in candidates:
            try:
                results.extend(parse_checkov_json(f))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return results
