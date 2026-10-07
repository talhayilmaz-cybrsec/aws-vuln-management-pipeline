"""Risk scoring: pure functions, no AWS calls, fully unit-tested.

Why not CVSS alone?
    CVSS measures how bad a vulnerability *could* be. It says nothing about
    whether anyone is exploiting it, or whether the affected asset matters.
    Most CVEs rated "critical" are never exploited in the wild. This engine
    combines three questions into one 0-100 score:

    1. Severity    - how bad if exploited?        CVSS base score     (0-40)
    2. Likelihood  - is it being exploited?       CISA KEV, EPSS      (0-35)
    3. Impact      - does this asset matter?      exposure, criticality (0-25)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Default remediation SLAs in days per priority. Overridable via the
# SLA_DAYS environment variable (JSON) so each organization can apply its own.
DEFAULT_SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}

EXPOSURE_POINTS = {"internet": 15, "internal": 5, "isolated": 0}
CRITICALITY_POINTS = {"high": 10, "medium": 5, "low": 0}


@dataclass(frozen=True)
class RiskInput:
    cvss: float | None          # CVSS base score 0-10 (None if unscored)
    epss: float | None          # EPSS probability 0-1 (None if unknown)
    in_kev: bool                # listed in CISA Known Exploited Vulnerabilities
    exploit_available: bool     # Inspector: public exploit code exists
    exposure: str = "internal"  # asset tag vulnpipe:exposure
    criticality: str = "medium" # asset tag vulnpipe:criticality


@dataclass(frozen=True)
class RiskResult:
    score: int
    priority: str
    reasons: tuple[str, ...]


def severity_points(cvss: float | None) -> float:
    """CVSS 0-10 mapped linearly to 0-40. Unscored findings get a neutral 20."""
    if cvss is None:
        return 20.0
    return max(0.0, min(cvss, 10.0)) * 4.0


def likelihood_points(epss: float | None, in_kev: bool, exploit_available: bool) -> float:
    """Exploitation evidence, 0-35.

    KEV is confirmed exploitation in the wild, so it takes the maximum.
    Otherwise EPSS (probability of exploitation in the next 30 days) is
    bucketed; small EPSS values are common, so the buckets are deliberately
    steep at the low end.
    """
    if in_kev:
        return 35.0
    if epss is None:
        points = 5.0
    elif epss >= 0.5:
        points = 25.0
    elif epss >= 0.1:
        points = 18.0
    elif epss >= 0.01:
        points = 8.0
    else:
        points = 2.0
    if exploit_available:
        points += 5.0
    return min(points, 35.0)


def impact_points(exposure: str, criticality: str) -> float:
    """Asset context from tags, 0-25. Unknown values fall back to the middle."""
    return float(
        EXPOSURE_POINTS.get(exposure.lower(), EXPOSURE_POINTS["internal"])
        + CRITICALITY_POINTS.get(criticality.lower(), CRITICALITY_POINTS["medium"])
    )


def priority_for(score: int, in_kev: bool) -> str:
    """KEV always means P1: active exploitation outranks any arithmetic."""
    if in_kev or score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def assess(risk: RiskInput) -> RiskResult:
    sev = severity_points(risk.cvss)
    lik = likelihood_points(risk.epss, risk.in_kev, risk.exploit_available)
    imp = impact_points(risk.exposure, risk.criticality)
    score = int(round(min(sev + lik + imp, 100.0)))

    reasons = [f"CVSS {risk.cvss if risk.cvss is not None else 'n/a'} (+{sev:.0f})"]
    if risk.in_kev:
        reasons.append("in CISA KEV: exploited in the wild (+35)")
    else:
        epss_txt = f"{risk.epss:.3f}" if risk.epss is not None else "n/a"
        reasons.append(f"EPSS {epss_txt}{', public exploit' if risk.exploit_available else ''} (+{lik:.0f})")
    reasons.append(f"asset exposure={risk.exposure}, criticality={risk.criticality} (+{imp:.0f})")

    return RiskResult(score=score, priority=priority_for(score, risk.in_kev), reasons=tuple(reasons))


def sla_due(priority: str, first_observed: datetime, sla_days: dict[str, int] | None = None) -> datetime:
    """The remediation clock starts when the vulnerability was first observed,
    not when this engine happened to process it."""
    days = (sla_days or DEFAULT_SLA_DAYS)[priority]
    if first_observed.tzinfo is None:
        first_observed = first_observed.replace(tzinfo=timezone.utc)
    return first_observed + timedelta(days=days)
