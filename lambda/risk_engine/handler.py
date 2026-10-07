"""Risk engine Lambda.

Triggered by EventBridge for every Amazon Inspector finding (created,
updated, or closed). For each package vulnerability it:

  1. extracts the CVE, CVSS, exploit/fix flags, and the affected asset
  2. enriches with CISA KEV and EPSS (scoring.py / enrichment.py)
  3. computes a 0-100 risk score, a priority (P1-P4), and an SLA due date
  4. upserts the result into DynamoDB (the system of record for reporting)
  5. alerts once via SNS when a finding reaches an alerting priority
  6. on closure, records closed_at so time-to-remediate can be measured

It can also be invoked with {"backfill": true} to score every finding that
already existed before the engine was deployed.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable

from enrichment import ThreatIntel
from scoring import DEFAULT_SLA_DAYS, RiskInput, assess, sla_due

log = logging.getLogger()
log.setLevel(logging.INFO)

TAG_PREFIX = "vulnpipe:"

# Container images carry no asset tags in Inspector findings; until an image
# is tied to a running workload, treat it as an internal, medium asset.
DEFAULT_CONTEXT = {"exposure": "internal", "criticality": "medium"}


# --- Parsing helpers ---------------------------------------------------------

def parse_time(value: Any) -> datetime | None:
    """Inspector timestamps arrive as datetimes (API), ISO strings, epoch
    numbers, or EventBridge's 'Oct 7, 2026, 22:15:03 PM' style."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y, %H:%M:%S %p", "%b %d, %Y, %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    log.warning("Unparseable timestamp %r", value)
    return None


def pick_cvss(details: dict, inspector_score: Any) -> float | None:
    """Prefer NVD's CVSS v3.x, then the highest version from any source,
    then Inspector's own score."""
    entries = [c for c in details.get("cvss") or [] if c.get("baseScore") is not None]
    nvd_v3 = [c for c in entries if c.get("source") == "NVD" and str(c.get("version", "")).startswith("3")]
    chosen = nvd_v3 or sorted(entries, key=lambda c: str(c.get("version", "")), reverse=True)
    if chosen:
        return float(chosen[0]["baseScore"])
    return float(inspector_score) if inspector_score is not None else None


def asset_context(resource: dict) -> dict:
    tags = resource.get("tags") or {}
    ctx = dict(DEFAULT_CONTEXT)
    for key in ("exposure", "criticality", "environment"):
        if f"{TAG_PREFIX}{key}" in tags:
            ctx[key] = str(tags[f"{TAG_PREFIX}{key}"]).lower()
    return ctx


def to_dynamo(value: Any) -> Any:
    """DynamoDB rejects Python floats; convert recursively to Decimal."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: to_dynamo(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_dynamo(v) for v in value]
    return value


# --- Engine ------------------------------------------------------------------

class RiskEngine:
    def __init__(self, table, sns, topic_arn: str, intel: ThreatIntel,
                 sla_days: dict[str, int] | None = None,
                 alert_priorities: tuple[str, ...] = ("P1",),
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.table = table
        self.sns = sns
        self.topic_arn = topic_arn
        self.intel = intel
        self.sla_days = sla_days or DEFAULT_SLA_DAYS
        self.alert_priorities = alert_priorities
        self.now = now

    def process(self, finding: dict) -> dict | None:
        if finding.get("type") != "PACKAGE_VULNERABILITY":
            log.info("Skipping non-package finding %s (%s)", finding.get("findingArn"), finding.get("type"))
            return None

        details = finding.get("packageVulnerabilityDetails") or {}
        resource = (finding.get("resources") or [{}])[0]
        cve = details.get("vulnerabilityId")
        status = finding.get("status", "ACTIVE")
        now = self.now()
        first_observed = parse_time(finding.get("firstObservedAt")) or now

        # EPSS: Inspector often includes it; fall back to the FIRST API.
        epss = (finding.get("epss") or {}).get("score")
        epss = float(epss) if epss is not None else self.intel.epss(cve)

        ctx = asset_context(resource)
        risk = RiskInput(
            cvss=pick_cvss(details, finding.get("inspectorScore")),
            epss=epss,
            in_kev=self.intel.in_kev(cve),
            exploit_available=finding.get("exploitAvailable") == "YES",
            exposure=ctx["exposure"],
            criticality=ctx["criticality"],
        )
        result = assess(risk)
        due = sla_due(result.priority, first_observed, self.sla_days)

        packages = [
            {"name": p.get("name"), "version": p.get("version"), "fixed_in": p.get("fixedInVersion")}
            for p in details.get("vulnerablePackages") or []
        ]

        record = {
            "cve": cve,
            "title": finding.get("title"),
            "status": status,
            "inspector_severity": finding.get("severity"),
            "resource_id": resource.get("id"),
            "resource_type": resource.get("type"),
            "exposure": ctx["exposure"],
            "criticality": ctx["criticality"],
            "cvss": risk.cvss,
            "epss": risk.epss,
            "in_kev": risk.in_kev,
            "exploit_available": risk.exploit_available,
            "fix_available": finding.get("fixAvailable"),
            "packages": packages,
            "risk_score": result.score,
            "priority": result.priority,
            "risk_reasons": list(result.reasons),
            "sla_due": due.isoformat(),
            "first_observed": first_observed.isoformat(),
            "last_processed": now.isoformat(),
        }
        if status == "CLOSED":
            closed = parse_time(finding.get("updatedAt")) or now
            record["closed_at"] = closed.isoformat()

        self._upsert(finding["findingArn"], record)

        if status == "ACTIVE" and result.priority in self.alert_priorities:
            self._alert_once(finding["findingArn"], record)

        log.info("%s %s on %s -> score %d %s", cve, status, resource.get("id"), result.score, result.priority)
        return record

    def _upsert(self, finding_arn: str, record: dict) -> None:
        names, values, sets = {}, {}, []
        for i, (key, value) in enumerate(record.items()):
            names[f"#k{i}"] = key
            values[f":v{i}"] = to_dynamo(value)
            sets.append(f"#k{i} = :v{i}")
        # first_seen is written once and never overwritten.
        names["#fs"] = "first_seen"
        values[":fs"] = record["last_processed"]
        self.table.update_item(
            Key={"finding_arn": finding_arn},
            UpdateExpression="SET " + ", ".join(sets) + ", #fs = if_not_exists(#fs, :fs)",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    def _alert_once(self, finding_arn: str, record: dict) -> None:
        """Mark the finding as alerted with a conditional write; only the
        writer that wins the condition sends the alert, so Inspector's
        repeated update events never produce duplicate emails."""
        try:
            self.table.update_item(
                Key={"finding_arn": finding_arn},
                UpdateExpression="SET alerted_at = :t",
                ConditionExpression="attribute_not_exists(alerted_at)",
                ExpressionAttributeValues={":t": record["last_processed"]},
            )
        except self.table.meta.client.exceptions.ConditionalCheckFailedException:
            return

        subject = f"[{record['priority']}] {record['cve']} risk {record['risk_score']} on {record['resource_id']}"
        lines = [
            f"Priority:      {record['priority']} (risk score {record['risk_score']}/100)",
            f"CVE:           {record['cve']}",
            f"Title:         {record['title']}",
            f"Resource:      {record['resource_type']} {record['resource_id']}",
            f"Fix available: {record['fix_available']}",
            f"Remediate by:  {record['sla_due'][:10]}",
            "",
            "Why this priority:",
            *[f"  - {r}" for r in record["risk_reasons"]],
            "",
            "Affected packages:",
            *[f"  - {p['name']} {p['version']} -> fixed in {p['fixed_in'] or 'n/a'}" for p in record["packages"]],
        ]
        self.sns.publish(TopicArn=self.topic_arn, Subject=subject[:100], Message="\n".join(lines))

    def backfill(self, inspector) -> dict:
        """Score every active package finding that already exists."""
        counts = {"processed": 0, "skipped": 0}
        paginator = inspector.get_paginator("list_findings")
        pages = paginator.paginate(filterCriteria={
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
        })
        for page in pages:
            for finding in page.get("findings", []):
                counts["processed" if self.process(finding) else "skipped"] += 1
        return counts


# --- Lambda entry point ------------------------------------------------------

_engine: RiskEngine | None = None


def _build_engine() -> RiskEngine:
    import boto3  # available in the Lambda runtime; imported lazily for tests

    return RiskEngine(
        table=boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]),
        sns=boto3.client("sns"),
        topic_arn=os.environ["TOPIC_ARN"],
        intel=ThreatIntel(),
        sla_days=json.loads(os.environ["SLA_DAYS"]) if os.environ.get("SLA_DAYS") else None,
        alert_priorities=tuple(os.environ.get("ALERT_PRIORITIES", "P1").split(",")),
    )


def lambda_handler(event: dict, context: Any) -> dict:
    global _engine
    if _engine is None:
        _engine = _build_engine()  # reused across warm invocations (keeps intel cache)

    if event.get("backfill"):
        import boto3

        return _engine.backfill(boto3.client("inspector2"))

    if event.get("detail-type") == "Inspector2 Finding":
        record = _engine.process(event["detail"])
        return {"processed": 1 if record else 0}

    log.warning("Ignoring unexpected event: %s", json.dumps(event)[:500])
    return {"processed": 0}
