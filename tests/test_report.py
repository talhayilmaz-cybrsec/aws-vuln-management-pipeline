from datetime import datetime, timedelta, timezone
from decimal import Decimal

from report import compute_metrics, render

NOW = datetime(2026, 10, 12, 13, 0, tzinfo=timezone.utc)


def item(cve, priority="P2", status="ACTIVE", score=65, due_in_days=10,
         first_days_ago=5, closed_days_ago=None, kev=False):
    first = NOW - timedelta(days=first_days_ago)
    i = {
        "cve": cve, "priority": priority, "status": status,
        "risk_score": Decimal(score),  # DynamoDB returns numbers as Decimal
        "in_kev": kev, "resource_id": "i-0abc",
        "first_observed": first.isoformat(),
        "sla_due": (NOW + timedelta(days=due_in_days)).isoformat(),
    }
    if closed_days_ago is not None:
        i["closed_at"] = (NOW - timedelta(days=closed_days_ago)).isoformat()
    return i


def test_open_counts_and_kev():
    m = compute_metrics([
        item("CVE-1", "P1", kev=True), item("CVE-2", "P2"), item("CVE-3", "P2"),
        item("CVE-4", "P3", status="CLOSED", closed_days_ago=1),
    ], NOW)
    assert m.open_by_priority == {"P1": 1, "P2": 2, "P3": 0, "P4": 0}
    assert m.open_total == 3
    assert m.open_in_kev == 1
    assert m.total == 4


def test_sla_breach_and_due_soon():
    m = compute_metrics([
        item("LATE", due_in_days=-2, score=90),
        item("SOON", due_in_days=3),
        item("LATER", due_in_days=20),
    ], NOW)
    assert [i["cve"] for i in m.sla_breached] == ["LATE"]
    assert m.due_next_7_days == 1
    assert round(m.sla_compliance_pct, 1) == 66.7


def test_mttr_from_first_observed_to_closed():
    m = compute_metrics([
        item("A", "P1", status="CLOSED", first_days_ago=10, closed_days_ago=6),  # 4 days
        item("B", "P1", status="CLOSED", first_days_ago=10, closed_days_ago=4),  # 6 days
        item("C", "P3", status="CLOSED", first_days_ago=30, closed_days_ago=10), # 20 days
    ], NOW)
    assert m.mttr_by_priority["P1"] == 5.0
    assert m.mttr_by_priority["P3"] == 20.0
    assert m.mttr_by_priority["P2"] is None
    assert round(m.mttr_days, 2) == 10.0
    assert m.closed_last_7_days == 2  # B (4 days ago) and A (6 days ago)


def test_top_open_sorted_by_risk_and_excludes_closed():
    m = compute_metrics([
        item("LOW", score=40), item("HIGH", score=95), item("MID", score=70),
        item("GONE", score=99, status="CLOSED", closed_days_ago=1),
    ], NOW, top_n=2)
    assert [i["cve"] for i in m.top_open] == ["HIGH", "MID"]


def test_empty_table_renders_without_errors():
    m = compute_metrics([], NOW)
    assert m.sla_compliance_pct is None and m.mttr_days is None
    text = render(m)
    assert "Open findings:        0" in text
    assert "nothing closed yet" in text


def test_render_contains_key_metrics():
    text = render(compute_metrics([item("CVE-2020-14343", "P1", score=98, due_in_days=-1, kev=True)], NOW))
    assert "CVE-2020-14343" in text and "KEV" in text
    assert "1 past due" in text
