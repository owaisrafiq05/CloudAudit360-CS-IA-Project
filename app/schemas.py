from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class UserOut(BaseModel):
    id: int
    username: str
    role: str

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str
    password: str


class ScanCreate(BaseModel):
    environment: Literal["vulnerable", "hardened", "other"] = "other"
    label: str | None = None


class ScanOut(BaseModel):
    id: int
    started_at: datetime | None
    finished_at: datetime | None
    environment: str
    status: str
    label: str | None
    triggered_by: str | None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    scan_id: int
    check_id: str
    source: str
    asset_id: int | None
    title: str
    description: str
    severity: str
    status: str
    evidence_json: dict[str, Any] | None
    remediation: str | None
    created_at: datetime | None

    model_config = {"from_attributes": True}


class NormalizedFinding(BaseModel):
    check_id: str
    source: Literal["custom", "prowler", "checkov"]
    asset_arn: str | None = None
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["PASS", "FAIL", "ERROR"]
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""


class ControlOut(BaseModel):
    id: int
    framework: str
    control_ref: str
    title: str
    description: str
    status: str | None = None
    failing_finding_count: int | None = None

    model_config = {"from_attributes": True}


class ComplianceScore(BaseModel):
    framework: str
    pass_count: int
    fail_count: int
    exception_count: int
    not_assessed: int
    score: float
    coverage: float


class RiskOut(BaseModel):
    id: int
    finding_key: str
    asset_id: int | None
    title: str
    likelihood: int
    impact: int
    inherent_score: int
    rating: str
    owner: str | None
    treatment: str
    treatment_note: str | None
    residual_score: float | None
    residual_rating: str | None
    status: str
    first_seen_scan: int | None
    last_seen_scan: int | None
    due_date: date | None
    likelihood_reason: str | None = None
    impact_reason: str | None = None
    check_id: str | None = None
    severity: str | None = None

    model_config = {"from_attributes": True}


class RiskUpdate(BaseModel):
    owner: str | None = None
    treatment: str | None = None
    treatment_note: str | None = None
    status: str | None = None
    due_date: date | None = None


class ExceptionCreate(BaseModel):
    risk_id: int
    control_id: int | None = None
    justification: str
    expires_at: datetime | None = None


class ExceptionOut(BaseModel):
    id: int
    risk_id: int
    control_id: int | None
    justification: str
    approved_by: str | None
    expires_at: datetime | None
    status: str

    model_config = {"from_attributes": True}


class ReviewComplete(BaseModel):
    outcome: str
    notes: str | None = None


class ReviewOut(BaseModel):
    id: int
    type: str
    target: str
    reviewer: str | None
    due_date: date | None
    completed_at: datetime | None
    outcome: str | None
    notes: str | None

    model_config = {"from_attributes": True}


class ReportCreate(BaseModel):
    scan_id: int
    type: Literal["audit", "technical"] = "audit"
    format: Literal["pdf", "html"] = "html"


class ReportOut(BaseModel):
    id: int
    scan_id: int
    report_type: str
    format: str
    path: str
    created_at: datetime | None

    model_config = {"from_attributes": True}


class ScanCompare(BaseModel):
    scan_a: int
    scan_b: int
    fixed: list[dict[str, Any]]
    new: list[dict[str, Any]]
    unchanged: list[dict[str, Any]]
    score_deltas: dict[str, dict[str, float]]
