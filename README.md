# AWS Vulnerability Management Pipeline

An automated vulnerability management pipeline on AWS. Container images and
infrastructure code are scanned before deployment, running workloads are
scanned continuously with Amazon Inspector, and a Python risk engine
prioritizes CVEs using CVSS, EPSS, and the CISA Known Exploited
Vulnerabilities (KEV) catalog instead of CVSS alone.

> **Status:** Phase 1 (pre-deployment scanning) complete. AWS runtime scanning,
> risk engine, and reporting in progress.

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
| 2 | AWS infrastructure in Terraform, GitHub OIDC (no stored keys) | Planned |
| 3 | Risk engine Lambda: CVSS + EPSS + KEV + asset context, SLA routing | Planned |
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

## Tooling

Trivy 0.74.0 (pinned) · GitHub Actions · Docker · Python ·
Terraform, Amazon Inspector, AWS Security Hub, EventBridge, Lambda,
DynamoDB, SNS (planned phases)

## Author

Talha Yilmaz
