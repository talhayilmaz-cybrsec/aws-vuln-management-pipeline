from datetime import datetime, timezone

import pytest

from scoring import RiskInput, assess, likelihood_points, priority_for, sla_due


def risk(**overrides):
    base = dict(cvss=9.8, epss=0.02, in_kev=False, exploit_available=False,
                exposure="internal", criticality="medium")
    base.update(overrides)
    return RiskInput(**base)


def test_kev_is_always_p1_even_with_low_cvss():
    result = assess(risk(cvss=5.0, in_kev=True, exposure="isolated", criticality="low"))
    assert result.priority == "P1"
    assert any("KEV" in r for r in result.reasons)


def test_same_cve_scores_higher_on_internet_facing_critical_asset():
    internal = assess(risk(exposure="internal", criticality="low"))
    public = assess(risk(exposure="internet", criticality="high"))
    assert public.score - internal.score == 20


def test_critical_cvss_without_exploitation_evidence_is_not_p1():
    # The core argument for risk-based prioritization: CVSS 9.8 alone,
    # with a low exploitation probability on an internal asset, is not an emergency.
    result = assess(risk(cvss=9.8, epss=0.001, exposure="internal", criticality="medium"))
    assert result.priority in ("P2", "P3")


def test_high_epss_moves_a_medium_cvss_up():
    low = assess(risk(cvss=6.5, epss=0.001))
    high = assess(risk(cvss=6.5, epss=0.7))
    assert high.score > low.score


@pytest.mark.parametrize("epss,expected", [(0.9, 25), (0.2, 18), (0.05, 8), (0.001, 2), (None, 5)])
def test_epss_buckets(epss, expected):
    assert likelihood_points(epss, in_kev=False, exploit_available=False) == expected


def test_public_exploit_adds_points_but_caps_at_35():
    assert likelihood_points(0.9, False, True) == 30
    assert likelihood_points(None, True, True) == 35


def test_score_never_exceeds_100():
    result = assess(risk(cvss=10.0, in_kev=True, exposure="internet", criticality="high"))
    assert result.score == 100


@pytest.mark.parametrize("score,priority", [(80, "P1"), (79, "P2"), (60, "P2"), (59, "P3"), (40, "P3"), (39, "P4")])
def test_priority_thresholds(score, priority):
    assert priority_for(score, in_kev=False) == priority


def test_sla_clock_starts_at_first_observed():
    first = datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert sla_due("P1", first) == datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert sla_due("P2", first, {"P1": 3, "P2": 14, "P3": 60, "P4": 120}).day == 15


def test_unknown_tag_values_fall_back_to_defaults():
    weird = assess(risk(exposure="mars", criticality="???"))
    default = assess(risk(exposure="internal", criticality="medium"))
    assert weird.score == default.score
