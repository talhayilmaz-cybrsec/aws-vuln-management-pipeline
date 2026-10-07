"""Weekly vulnerability management report.

Runs on a schedule, reads every finding the risk engine recorded, and emails
the program-level metrics that managers and auditors track:

  - open findings by priority, and how many are in CISA KEV
  - SLA breaches: open findings past their remediation due date
  - findings coming due in the next 7 days
  - MTTR (mean time to remediate), overall and per priority
  - the highest-risk open findings

The metric logic is a pure function (compute_metrics) so it is unit-tested
without AWS.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any, Iterable

log = logging.getLogger()
log.setLevel(logging.INFO)

PRIORITIES = ("P1", "P2", "P3", "P4")


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Metrics:
    generated_at: datetime
    total: int = 0
    open_by_priority: dict[str, int] = field(default_factory=lambda: {p: 0 for p in PRIORITIES})
    open_in_kev: int = 0
    sla_breached: list[dict] = field(default_factory=list)
    due_next_7_days: int = 0
    closed_last_7_days: int = 0
    mttr_days: float | None = None
    mttr_by_priority: dict[str, float | None] = field(default_factory=dict)
    top_open: list[dict] = field(default_factory=list)

    @property
    def open_total(self) -> int:
        return sum(self.open_by_priority.values())

    @property
    def sla_compliance_pct(self) -> float | None:
        """Share of open findings still within their SLA."""
        if not self.open_total:
            return None
        return 100.0 * (self.open_total - len(self.sla_breached)) / self.open_total


def compute_metrics(items: Iterable[dict], now: datetime, top_n: int = 10) -> Metrics:
    m = Metrics(generated_at=now)
    open_items: list[dict] = []
    remediation_days: dict[str, list[float]] = {p: [] for p in PRIORITIES}

    for item in items:
        m.total += 1
        priority = item.get("priority", "P4")
        status = item.get("status")

        if status == "ACTIVE":
            open_items.append(item)
            m.open_by_priority[priority] = m.open_by_priority.get(priority, 0) + 1
            if item.get("in_kev"):
                m.open_in_kev += 1
            due = _dt(item.get("sla_due"))
            if due and due < now:
                m.sla_breached.append(item)
            elif due and due < now + timedelta(days=7):
                m.due_next_7_days += 1

        elif status == "CLOSED":
            closed, first = _dt(item.get("closed_at")), _dt(item.get("first_observed"))
            if closed and first and closed >= first:
                remediation_days.setdefault(priority, []).append((closed - first).total_seconds() / 86400)
            if closed and closed >= now - timedelta(days=7):
                m.closed_last_7_days += 1

    all_days = [d for days in remediation_days.values() for d in days]
    m.mttr_days = mean(all_days) if all_days else None
    m.mttr_by_priority = {p: (mean(d) if d else None) for p, d in remediation_days.items()}

    by_risk = lambda i: float(i.get("risk_score", 0))  # noqa: E731
    m.sla_breached.sort(key=by_risk, reverse=True)
    m.top_open = sorted(open_items, key=by_risk, reverse=True)[:top_n]
    return m


def render(m: Metrics) -> str:
    def days(v: float | None, empty: str = "n/a") -> str:
        return f"{v:.1f} days" if v is not None else empty

    compliance = f"{m.sla_compliance_pct:.1f}%" if m.sla_compliance_pct is not None else "n/a"
    lines = [
        f"Vulnerability management report - {m.generated_at:%Y-%m-%d}",
        "=" * 56,
        "",
        f"Open findings:        {m.open_total}  "
        + "  ".join(f"{p}={m.open_by_priority.get(p, 0)}" for p in PRIORITIES),
        f"Open in CISA KEV:     {m.open_in_kev}",
        f"SLA compliance:       {compliance}  ({len(m.sla_breached)} past due)",
        f"Due in next 7 days:   {m.due_next_7_days}",
        f"Closed last 7 days:   {m.closed_last_7_days}",
        f"MTTR (all):           {days(m.mttr_days, 'n/a (nothing closed yet)')}",
        "MTTR by priority:     "
        + "  ".join(f"{p}={days(m.mttr_by_priority.get(p))}" for p in PRIORITIES),
        "",
        "Past SLA (highest risk first):",
    ]
    if m.sla_breached:
        lines += [_row(i) for i in m.sla_breached[:10]]
    else:
        lines.append("  none")
    lines += ["", f"Top {len(m.top_open)} open findings by risk:"]
    lines += [_row(i) for i in m.top_open] or ["  none"]
    return "\n".join(lines)


def _row(i: dict) -> str:
    kev = " KEV" if i.get("in_kev") else ""
    return (f"  {i.get('priority')} {int(float(i.get('risk_score', 0))):>3}  {i.get('cve', '?'):<16}"
            f" due {str(i.get('sla_due', ''))[:10]}{kev}  {i.get('resource_id', '')}")


# --- Lambda entry point ------------------------------------------------------

def _scan_all(table) -> Iterable[dict]:
    kwargs: dict = {}
    while True:
        page = table.scan(**kwargs)
        yield from page.get("Items", [])
        if "LastEvaluatedKey" not in page:
            return
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def lambda_handler(event: dict, context: Any) -> dict:
    import boto3

    table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    metrics = compute_metrics(_scan_all(table), datetime.now(timezone.utc))
    body = render(metrics)
    log.info(body)

    boto3.client("sns").publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=f"Vulnerability report {metrics.generated_at:%Y-%m-%d}: "
                f"{metrics.open_by_priority['P1']} P1, {len(metrics.sla_breached)} past SLA",
        Message=body,
    )
    summary = {
        "open": metrics.open_total,
        "open_by_priority": metrics.open_by_priority,
        "past_sla": len(metrics.sla_breached),
        "mttr_days": metrics.mttr_days,
    }
    return json.loads(json.dumps(summary, default=float))
