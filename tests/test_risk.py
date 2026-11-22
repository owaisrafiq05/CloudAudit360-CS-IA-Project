from app.grc.risk import compute_impact, compute_likelihood, rating_for_score, residual_for_treatment, score_finding


def test_likelihood_public_critical():
    likelihood, reason = compute_likelihood("public", "critical")
    assert likelihood == 5
    assert "exposure=public" in reason


def test_impact_high_criticality():
    impact, reason = compute_impact("high", 3)
    # severity high=4, criticality 3->5, round((4+5)/2)=5
    assert impact == 5
    assert "impact=5" in reason


def test_score_bands():
    scored = score_finding(severity="low", exposure="private", criticality=1)
    assert scored["rating"] == "Low"
    scored = score_finding(severity="critical", exposure="public", criticality=3)
    assert scored["inherent_score"] == 25
    assert scored["rating"] == "Critical"


def test_residual_rules():
    assert residual_for_treatment(20, "avoid") == (0.0, "Low")
    assert residual_for_treatment(20, "mitigate", verified_mitigated=True)[0] == 1.0
    residual, rating = residual_for_treatment(20, "transfer")
    assert residual == 10
    assert rating == "High"
    assert residual_for_treatment(12, "accept")[0] == 12.0


def test_rating_for_score():
    assert rating_for_score(4) == "Low"
    assert rating_for_score(9) == "Medium"
    assert rating_for_score(16) == "High"
    assert rating_for_score(17) == "Critical"
