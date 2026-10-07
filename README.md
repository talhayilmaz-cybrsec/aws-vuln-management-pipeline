# AWS Vulnerability Management Pipeline

An automated vulnerability management pipeline on AWS. Container images and
infrastructure code are scanned before deployment, running workloads are
scanned continuously with Amazon Inspector, and a Python risk engine
prioritizes CVEs using CVSS, EPSS, and the CISA Known Exploited
Vulnerabilities (KEV) catalog instead of CVSS alone.

> **Status:** Phases 1-2 deployed. Phase 3 (risk engine) code complete.
> Reporting planned.

## Architecture

```
 Developer push
      │
      ▼
 GitHub Actions ──► Trivy image scan ──► Trivy config scan
      │                    │                    │
      │             SARIF → GitHub Security tab │
      │                    └──── gate: block on CRITICAL / misconfig
      ▼
 AWS (Terraform)                                        [planned]
 Amazon Inspector ─► Security Hub ─► EventBridge ─► Lambda risk engine
   (EC2, ECR, Lambda)                                    │
                                    CVSS + EPSS + CISA KEV + asset context
                                                         │
                                 ┌───────────────────────┼──────────────┐
                                 ▼                       ▼              ▼
                           SNS alert            GitHub Issue (SLA)   DynamoDB
```

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Pre-deployment scanning: Trivy in GitHub Actions, SARIF upload, build gates | Done |
| 2 | AWS infrastructure in Terraform, GitHub OIDC (no stored keys) | Deployed |
| 3 | Risk engine Lambda: CVSS + EPSS + KEV + asset context, SLA routing | Code complete |
| 4 | Weekly metrics report: severity counts, SLA breaches, MTTR | Planned |
| 5 | Documentation, screenshots, teardown | Planned |

## Phase 1: Pre-deployment scanning

Workflow: [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)

| Job | What it checks | Blocks the build when |
|---|---|---|
| Container image scan | OS packages and Python dependencies in the built image | A **CRITICAL** vulnerability with an available fix exists |
| Config scan | Dockerfile and IaC misconfigurations | A **HIGH** or **CRITICAL** misconfiguration exists |

Every finding, at all severities, is uploaded to the repository's
**Security → Code scanning** tab as SARIF, so the gate only decides what
blocks; nothing is hidden.

### Intentionally vulnerable demo target

`app/` contains a minimal Flask service packaged in a deliberately outdated
image so the pipeline has real findings to act on:

- `python:3.8-slim-buster`: end-of-life Python on end-of-life Debian 10
- `PyYAML 5.3.1`: CVE-2020-14343, arbitrary code execution (CVSS 9.8)
- Outdated `Werkzeug` and `requests` with known CVEs
- Container runs as root (Trivy `DS-0002`)

The first pipeline run is expected to **fail**. Remediating the image
(supported base image, patched dependencies, non-root user) makes it pass,
demonstrating the gate end to end.

## Phase 2: AWS infrastructure

Two Terraform stacks:

| Stack | Deployed by | Creates |
|---|---|---|
| [`bootstrap/`](bootstrap/) | Once, manually, from AWS CloudShell | S3 state bucket (versioned, encrypted, TLS-only), GitHub OIDC provider, deploy role |
| [`infra/`](infra/) | GitHub Actions ([`deploy-infra.yml`](.github/workflows/deploy-infra.yml)) | Inspector (EC2/ECR/Lambda), Security Hub, ECR, KMS key, SNS alerts, DynamoDB findings table, scan target EC2 |

### Security decisions

- **No long-lived AWS keys.** Bootstrap runs in CloudShell with the console
  session's temporary credentials. GitHub Actions gets short-lived credentials
  through OIDC, and the role trusts only this repository's `main` branch.
- **Least privilege for the pipeline.** The deploy role has `PowerUserAccess`
  (which excludes IAM) plus IAM permissions scoped to `vulnpipe-*` roles only,
  so the pipeline cannot create or modify any other identity.
- **Encryption at rest with a customer managed KMS key** (rotation enabled)
  for alerts and findings data.
- **Locked-down scan target.** The intentionally vulnerable EC2 instance has no
  inbound rules, no SSH key, IMDSv2 only, and an encrypted disk. It is
  vulnerable on paper (package CVEs) but not reachable.
- **OIDC trust pinned to immutable IDs.** GitHub's token subject includes the
  numeric account and repository IDs, and the role trusts those, so a deleted
  and re-created account or repository with the same name cannot assume it.
- **The infrastructure code passes the same gate as the app.** Trivy scans the
  Terraform on every push. Accepted risks are suppressed inline with a written
  justification (`#trivy:ignore`), never silently.

## Phase 3: Risk engine

Code: [`lambda/risk_engine/`](lambda/risk_engine/) · Tests: [`tests/`](tests/)

Every Inspector finding event (created, updated, closed) triggers a Python
Lambda through EventBridge. CVSS alone measures how bad a vulnerability
*could* be; most "critical" CVEs are never exploited. The engine answers
three questions and combines them into a 0-100 score:

| Question | Signal | Points |
|---|---|---|
| How bad if exploited? | CVSS base score (NVD v3 preferred) | 0-40 |
| Is it being exploited? | **CISA KEV** (confirmed in the wild) = max; otherwise **EPSS** probability, plus public exploit availability | 0-35 |
| Does this asset matter? | Asset tags `vulnpipe:exposure` and `vulnpipe:criticality` | 0-25 |

| Priority | Rule | Remediation SLA |
|---|---|---|
| P1 | In CISA KEV, or score >= 80 | 7 days |
| P2 | Score 60-79 | 30 days |
| P3 | Score 40-59 | 90 days |
| P4 | Below 40 | 180 days |

The SLA clock starts at Inspector's *first observed* time. SLAs and alerting
priorities are Terraform variables.

**What happens to each finding**

- Upserted into DynamoDB with score, priority, the reasons behind the score,
  SLA due date, and affected packages. This is the system of record for
  reporting.
- P1 findings trigger one SNS email. A conditional write guarantees exactly
  one alert per finding, even though Inspector re-sends update events.
- When Inspector closes a finding (patched or resource removed), `closed_at`
  is recorded so time-to-remediate can be measured.
- Feed outages degrade gracefully: if KEV or EPSS is unreachable, the finding
  is still recorded with the signals that are available.
- Findings that existed before the engine was deployed are scored with a
  one-time backfill: `aws lambda invoke --function-name vulnpipe-risk-engine
  --payload '{"backfill": true}' --cli-binary-format raw-in-base64-out out.json`

The scoring and handler logic are covered by unit tests that run on every
push, with no AWS account or network access needed.

## Tooling

Trivy 0.74.0 (pinned) · GitHub Actions · Docker · Python 3.13 · pytest ·
Terraform · Amazon Inspector · AWS Security Hub · EventBridge · Lambda ·
DynamoDB · SNS · KMS · FIRST EPSS · CISA KEV

## Author

Talha Yilmaz
