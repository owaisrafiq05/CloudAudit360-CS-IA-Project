from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import EVIDENCE_DIR, REPORT_DIR, get_settings
from app.db import SessionLocal, init_db
from app.seed import run_seed

settings = get_settings()
TEMPLATES_DIR = Path(__file__).parent / "web" / "templates"
STATIC_DIR = Path(__file__).parent / "web" / "static"

scheduler = BackgroundScheduler()


def _expire_exceptions_job() -> None:
    from app.grc.register import expire_exceptions

    db = SessionLocal()
    try:
        expire_exceptions(db)
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    db = SessionLocal()
    try:
        run_seed(db)
    finally:
        db.close()
    scheduler.add_job(_expire_exceptions_job, "interval", hours=6, id="expire_exceptions")
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="CloudAudit360", version="1.0.0", lifespan=lifespan)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _register_routers() -> None:
    from app.web import (
        routes_admin,
        routes_api,
        routes_auth,
        routes_controls,
        routes_findings,
        routes_overview,
        routes_reports,
        routes_reviews,
        routes_risks,
        routes_scans,
    )

    app.include_router(routes_auth.router)
    app.include_router(routes_overview.router)
    app.include_router(routes_findings.router)
    app.include_router(routes_controls.router)
    app.include_router(routes_risks.router)
    app.include_router(routes_scans.router)
    app.include_router(routes_reviews.router)
    app.include_router(routes_reports.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_api.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "demo_mode": settings.demo_mode}


@app.get("/")
def root():
    return RedirectResponse("/dashboard")


# Routers registered after module load so package imports resolve
try:
    _register_routers()
except ImportError:
    # During early milestone installs, web routers may not exist yet
    pass
