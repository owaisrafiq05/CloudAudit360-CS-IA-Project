from __future__ import annotations

import click

from app.db import SessionLocal, init_db
from app.seed import run_seed


@click.group()
def cli() -> None:
    """CloudAudit360 CLI."""


@cli.command("seed")
def seed_cmd() -> None:
    """Create tables and seed users, controls, mappings, policies."""
    init_db()
    db = SessionLocal()
    try:
        run_seed(db)
        click.echo("Seed complete: users, controls, mappings, policies.")
    finally:
        db.close()


@cli.command("scan")
@click.option(
    "--env",
    "environment",
    type=click.Choice(["vulnerable", "hardened", "other"]),
    default="vulnerable",
)
@click.option("--label", default=None)
@click.option("--user", "triggered_by", default="cli")
def scan_cmd(environment: str, label: str | None, triggered_by: str) -> None:
    """Run full Collect -> Assess -> Map -> Score -> Register pipeline."""
    from app.pipeline import run_scan

    init_db()
    db = SessionLocal()
    try:
        scan = run_scan(
            db,
            environment=environment,
            label=label or f"{environment} scan",
            triggered_by=triggered_by,
        )
        click.echo(f"Scan {scan.id} finished with status={scan.status}")
    finally:
        db.close()


@cli.command("report")
@click.option("--scan", "scan_id", type=int, required=True)
@click.option("--type", "report_type", type=click.Choice(["audit", "technical"]), default="audit")
@click.option("--format", "fmt", type=click.Choice(["html", "pdf"]), default="html")
def report_cmd(scan_id: int, report_type: str, fmt: str) -> None:
    """Generate an audit or technical report for a scan."""
    from app.reporting.builder import generate_report

    init_db()
    db = SessionLocal()
    try:
        report = generate_report(db, scan_id=scan_id, report_type=report_type, fmt=fmt)
        click.echo(f"Report {report.id} written to {report.path}")
    finally:
        db.close()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
