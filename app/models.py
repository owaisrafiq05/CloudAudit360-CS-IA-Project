from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    arn: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    criticality: Mapped[int] = mapped_column(Integer, default=2)
    exposure: Mapped[str] = mapped_column(String(32), default="private")
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    findings: Mapped[list[Finding]] = relationship(back_populates="asset")
    risks: Mapped[list[Risk]] = relationship(back_populates="asset")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="other")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triggered_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    snapshots: Mapped[list[Snapshot]] = relationship(back_populates="scan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan")
    control_results: Mapped[list[ControlResult]] = relationship(back_populates="scan")
    evidence_items: Mapped[list[Evidence]] = relationship(back_populates="scan")


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="snapshots")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    check_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="findings")
    asset: Mapped[Asset | None] = relationship(back_populates="findings")


class Control(Base):
    __tablename__ = "controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    control_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (UniqueConstraint("framework", "control_ref", name="uq_framework_ref"),)

    results: Mapped[list[ControlResult]] = relationship(back_populates="control")
    check_maps: Mapped[list[CheckControlMap]] = relationship(back_populates="control")


class CheckControlMap(Base):
    __tablename__ = "check_control_map"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("controls.id"), nullable=False)

    __table_args__ = (UniqueConstraint("check_id", "control_id", name="uq_check_control"),)

    control: Mapped[Control] = relationship(back_populates="check_maps")


class ControlResult(Base):
    __tablename__ = "control_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    control_id: Mapped[int] = mapped_column(ForeignKey("controls.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failing_finding_count: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (UniqueConstraint("scan_id", "control_id", name="uq_scan_control"),)

    scan: Mapped[Scan] = relationship(back_populates="control_results")
    control: Mapped[Control] = relationship(back_populates="results")


class Risk(Base):
    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(768), unique=True, nullable=False)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    inherent_score: Mapped[int] = mapped_column(Integer, nullable=False)
    rating: Mapped[str] = mapped_column(String(32), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    treatment: Mapped[str] = mapped_column(String(32), default="none")
    treatment_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    residual_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    residual_rating: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    first_seen_scan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_scan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    likelihood_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    check_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)

    asset: Mapped[Asset | None] = relationship(back_populates="risks")
    exceptions: Mapped[list[ExceptionRecord]] = relationship(back_populates="risk")


class ExceptionRecord(Base):
    __tablename__ = "exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=False)
    control_id: Mapped[int | None] = mapped_column(ForeignKey("controls.id"), nullable=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    risk: Mapped[Risk] = relationship(back_populates="exceptions")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    path_or_json: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    scan: Mapped[Scan] = relationship(back_populates="evidence_items")


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    linked_control_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
