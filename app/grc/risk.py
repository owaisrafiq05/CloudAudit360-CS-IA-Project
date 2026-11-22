"""5x5 risk methodology — likelihood, impact, inherent score, rating bands."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import yaml

from app.config import DATA_DIR


def load_risk_config(path: Path | None = None) -> dict[str, Any]:
    p = path or (DATA_DIR / "risk_config.yaml")
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def rating_for_score(score: float | int, cfg: dict | None = None) -> str:
    cfg = cfg or load_risk_config()
    s = int(score)
    for band in cfg.get("rating_bands", []):
        if band["min"] <= s <= band["max"]:
            return band["rating"]
    if s <= 0:
        return "Low"
    return "Critical"


def compute_likelihood(
    exposure: str,
    severity: str,
    cfg: dict | None = None,
) -> tuple[int, str]:
    cfg = cfg or load_risk_config()
    base = cfg.get("exposure_likelihood", {}).get(exposure, 2)
    bump = 0
    high_levels = cfg.get("high_severity_levels", ["high", "critical"])
    if cfg.get("high_severity_likelihood_bump", True) and severity in high_levels:
        bump = 1
    likelihood = min(5, base + bump)
    reason = f"exposure={exposure} -> {base}"
    if bump:
        reason += f"; +1 for severity={severity}"
    reason += f" => likelihood={likelihood}"
    return likelihood, reason


def compute_impact(
    severity: str,
    criticality: int,
    cfg: dict | None = None,
) -> tuple[int, str]:
    cfg = cfg or load_risk_config()
    sev_val = cfg.get("severity_values", {}).get(severity, 2)
    crit_map = cfg.get("criticality_values", {})
    crit_val = crit_map.get(criticality, crit_map.get(str(criticality), 3))
    # Half-up rounding so 4.5 -> 5 (avoids banker's round edge cases in demos)
    impact = int(math.floor((sev_val + crit_val) / 2 + 0.5))
    impact = max(1, min(5, impact))
    reason = (
        f"severity={severity}({sev_val}) + criticality={criticality}({crit_val}) "
        f"/ 2 => impact={impact}"
    )
    return impact, reason


def score_finding(
    *,
    severity: str,
    exposure: str = "private",
    criticality: int = 2,
    cfg: dict | None = None,
) -> dict[str, Any]:
    cfg = cfg or load_risk_config()
    likelihood, l_reason = compute_likelihood(exposure, severity, cfg)
    impact, i_reason = compute_impact(severity, criticality, cfg)
    inherent = likelihood * impact
    rating = rating_for_score(inherent, cfg)
    return {
        "likelihood": likelihood,
        "impact": impact,
        "inherent_score": inherent,
        "rating": rating,
        "likelihood_reason": l_reason,
        "impact_reason": i_reason,
    }


def residual_for_treatment(
    inherent_score: int,
    treatment: str,
    *,
    verified_mitigated: bool = False,
    cfg: dict | None = None,
) -> tuple[float, str]:
    cfg = cfg or load_risk_config()
    treatment = (treatment or "none").lower()
    if treatment == "avoid":
        return 0.0, "Low"
    if treatment == "mitigate" and verified_mitigated:
        return 1.0, rating_for_score(1, cfg)
    if treatment == "transfer":
        # impact halved — approximate by halving score (rounded up)
        residual = math.ceil(inherent_score / 2)
        return float(residual), rating_for_score(residual, cfg)
    # mitigate in progress, accept, none -> residual = inherent
    return float(inherent_score), rating_for_score(inherent_score, cfg)
