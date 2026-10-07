import re
from datetime import datetime, timezone

import pytest

from enrichment import KEV_URL, ThreatIntel
from handler import RiskEngine, parse_time, pick_cvss

NOW = datetime(2026, 10, 7, 23, 0, tzinfo=timezone.utc)


# --- Fakes: no AWS, no network ----------------------------------------------

class ConditionalCheckFailed(Exception):
    pass


class FakeTable:
    """Implements just enough of DynamoDB's update_item semantics."""

    class meta:
        class client:
            class exceptions:
                ConditionalCheckFailedException = ConditionalCheckFailed

    def __init__(self):
        self.items = {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues,
                    ExpressionAttributeNames=None, ConditionExpression=None):
        item = self.items.setdefault(Key["finding_arn"], {})
        if ConditionExpression == "attribute_not_exists(alerted_at)":
            if "alerted_at" in item:
                raise ConditionalCheckFailed()
            item["alerted_at"] = ExpressionAttributeValues[":t"]
            return
        names = ExpressionAttributeNames or {}
        # Clauses all start with an attribute-name placeholder (#...); split there
        # so the comma inside if_not_exists(#fs, :fs) is not treated as a separator.
        for clause in re.split(r", (?=#)", UpdateExpression[len("SET "):]):
            left, right = clause.split(" = ")
            key = names.get(left, left)
            if right.startswith("if_not_exists"):
                item.setdefault(key, ExpressionAttributeValues[":fs"])
            else:
                item[key] = ExpressionAttributeValues[right]


class FakeSNS:
    def __init__(self):
        self.messages = []

    def publish(self, TopicArn, Subject, Message):
        self.messages.append({"subject": Subject, "message": Message})


def fake_fetch(kev_ids=(), epss=None):
    def fetch(url):
        if url == KEV_URL:
            return {"vulnerabilities": [{"cveID": c} for c in kev_ids]}
        return {"data": [{"epss": str(epss)}] if epss is not None else []}
    return fetch


def engine(kev_ids=(), epss=None):
    table, sns = FakeTable(), FakeSNS()
    eng = RiskEngine(table, sns, "arn:aws:sns:us-east-1:111122223333:vulnpipe-alerts",
                     ThreatIntel(fetch=fake_fetch(kev_ids, epss)), now=lambda: NOW)
    return eng, table, sns


def finding(cve="CVE-2020-14343", status="ACTIVE", cvss=9.8, tags=None, **extra):
    f = {
        "findingArn": f"arn:aws:inspector2:us-east-1:111122223333:finding/{cve}",
        "type": "PACKAGE_VULNERABILITY",
        "title": f"{cve} - pyyaml",
        "severity": "CRITICAL",
        "status": status,
        "firstObservedAt": "Oct 7, 2026, 22:15:03 PM",
        "updatedAt": "2026-10-09T10:00:00Z",
        "exploitAvailable": "NO",
        "fixAvailable": "YES",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": cve,
            "cvss": [{"baseScore": cvss, "source": "NVD", "version": "3.1"}],
            "vulnerablePackages": [{"name": "PyYAML", "version": "5.3.1", "fixedInVersion": "5.4"}],
        },
        "resources": [{
            "id": "i-0abc123",
            "type": "AWS_EC2_INSTANCE",
            "tags": tags if tags is not None else {"vulnpipe:exposure": "internet", "vulnpipe:criticality": "high"},
        }],
    }
    f.update(extra)
    return f


# --- Tests -------------------------------------------------------------------

def test_kev_finding_is_stored_as_p1_and_alerts_once():
    eng, table, sns = engine(kev_ids=["CVE-2020-14343"])
    eng.process(finding())
    eng.process(finding())  # Inspector re-sends updates; must not re-alert

    item = table.items["arn:aws:inspector2:us-east-1:111122223333:finding/CVE-2020-14343"]
    assert item["priority"] == "P1"
    assert item["in_kev"] is True
    assert item["sla_due"].startswith("2026-10-14")  # 7 days from first observed
    assert len(sns.messages) == 1
    assert sns.messages[0]["subject"].startswith("[P1] CVE-2020-14343")


def test_non_kev_low_epss_finding_is_recorded_without_alert():
    eng, table, sns = engine(epss=0.004)
    record = eng.process(finding(tags={}))  # untagged asset -> defaults
    assert record["priority"] in ("P2", "P3")
    assert record["exposure"] == "internal"
    assert sns.messages == []


def test_inspector_supplied_epss_is_used_without_api_call():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"vulnerabilities": []}

    table, sns = FakeTable(), FakeSNS()
    eng = RiskEngine(table, sns, "topic", ThreatIntel(fetch=fetch), now=lambda: NOW)
    record = eng.process(finding(epss={"score": 0.61}))
    assert float(record["epss"]) == 0.61
    assert calls == [KEV_URL]  # only the KEV download, no EPSS lookup


def test_closed_finding_records_closed_at_for_mttr():
    eng, table, sns = engine(kev_ids=["CVE-2020-14343"])
    eng.process(finding())
    eng.process(finding(status="CLOSED"))
    item = next(iter(table.items.values()))
    assert item["status"] == "CLOSED"
    assert item["closed_at"].startswith("2026-10-09")
    assert item["first_seen"] == NOW.isoformat()  # preserved from first processing
    assert len(sns.messages) == 1


def test_closed_finding_never_alerts():
    eng, _, sns = engine(kev_ids=["CVE-2020-14343"])
    eng.process(finding(status="CLOSED"))
    assert sns.messages == []


def test_non_package_findings_are_skipped():
    eng, table, _ = engine()
    assert eng.process({"findingArn": "x", "type": "NETWORK_REACHABILITY"}) is None
    assert table.items == {}


def test_kev_outage_degrades_gracefully():
    def broken(url):
        raise TimeoutError("feed down")

    table, sns = FakeTable(), FakeSNS()
    eng = RiskEngine(table, sns, "topic", ThreatIntel(fetch=broken), now=lambda: NOW)
    record = eng.process(finding())
    assert record is not None and record["in_kev"] is False


def test_floats_are_stored_as_decimal():
    from decimal import Decimal

    eng, table, _ = engine(epss=0.25)
    eng.process(finding(tags={}))
    item = next(iter(table.items.values()))
    assert isinstance(item["cvss"], Decimal)
    assert isinstance(item["epss"], Decimal)


@pytest.mark.parametrize("value", [
    "Oct 7, 2026, 22:15:03 PM",
    "2026-10-07T22:15:03Z",
    datetime(2026, 10, 7, 22, 15, 3),
    1791411303,
])
def test_parse_time_accepts_inspector_formats(value):
    parsed = parse_time(value)
    assert parsed is not None and parsed.tzinfo is not None


def test_pick_cvss_prefers_nvd_v3():
    details = {"cvss": [
        {"baseScore": 5.0, "source": "VENDOR", "version": "3.1"},
        {"baseScore": 9.8, "source": "NVD", "version": "3.1"},
        {"baseScore": 7.5, "source": "NVD", "version": "2.0"},
    ]}
    assert pick_cvss(details, None) == 9.8
    assert pick_cvss({}, 6.1) == 6.1
    assert pick_cvss({}, None) is None
