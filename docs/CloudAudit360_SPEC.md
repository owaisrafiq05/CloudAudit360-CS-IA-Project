# CloudAudit360: Technical Spec (for Cursor)

Single project covering two courses:
- **Cloud Security:** collect AWS config, run scanners and custom checks, prioritize, remediate, re-scan.
- **Information Assurance (GRC):** map findings to framework controls, score compliance, quantify risk, keep a risk register, handle exceptions, retain evidence, generate audit reports.

One pipeline: **Collect -> Assess -> Normalize -> Map -> Score -> Register -> Report**.

Build only what is listed here. Keep it simple, working, and demo-able.

---

## 1. Stack (fixed choices)

| Area | Choice |
|---|---|
| Language | Python 3.11 |
| Backend/API | FastAPI + Uvicorn |
| ORM / DB | SQLAlchemy 2.x + Alembic; PostgreSQL (SQLite allowed for local dev) |
| AWS access | boto3, read-only role |
| Scanner integration | Prowler (JSON output) via subprocess; Checkov for Terraform scanning |
| Custom checks | Python modules using boto3 |
| Dashboard | Server-rendered Jinja2 + Chart.js + Tailwind (CDN). No SPA. |
| Reports | Jinja2 HTML -> PDF with WeasyPrint (also downloadable as HTML) |
| Scheduling | APScheduler (in-app) or cron triggering `python -m app.cli scan` |
| Infra lab | Terraform (two stacks: `vulnerable/`, `hardened/`) |
| Packaging | Docker + docker-compose (app, postgres) |
| Auth | Simple login (session cookie) with roles: `admin`, `auditor`, `viewer` |

Optional and out of the critical path: Nmap/Nessus. Only add a Nmap wrapper if time remains.

---

## 2. Repo Structure

```
cloudaudit360/
  app/
    main.py                 # FastAPI app, routers, templates
    config.py               # env settings
    db.py                   # engine/session
    models.py               # SQLAlchemy models
    schemas.py              # Pydantic models
    cli.py                  # `scan`, `seed`, `report` commands
    collector/
      aws_collector.py      # boto3 data collection -> snapshots
    assessment/
      engine.py             # runs custom checks + scanner adapters
      checks/               # one file per area
        iam.py  storage.py  network.py  logging_.py  encryption.py
      adapters/
        prowler.py          # parse Prowler JSON -> Finding
        checkov.py          # parse Checkov JSON -> Finding
    grc/
      mapping.py            # load controls.yaml + mapping.yaml
      compliance.py         # control status + framework scores
      risk.py               # likelihood/impact/score/bands
      register.py           # risk register + treatment + exceptions
      review.py             # periodic review tasks
    reporting/
      builder.py            # builds report context, renders PDF/HTML
      templates/            # report_audit.html, report_technical.html
    web/
      routes_*.py           # dashboard, findings, controls, risks, scans, reports, admin
      templates/            # base.html + pages
  data/
    frameworks/controls.yaml    # control catalogue
    frameworks/mapping.yaml     # check_id -> control ids
    policies.yaml               # policy statements, linked to controls
    risk_config.yaml            # scoring tables and bands
  infra/
    vulnerable/  hardened/      # Terraform
  docker-compose.yml  Dockerfile  requirements.txt  README.md
```

---

## 3. Data Model (tables)

- `users(id, username, password_hash, role)`
- `assets(id, arn, type, service, name, region, criticality[1-3], exposure[public|internal|private], owner, tags_json)`
- `scans(id, started_at, finished_at, environment[vulnerable|hardened|other], status, label, triggered_by)`
- `snapshots(id, scan_id, service, resource_id, config_json, collected_at)`: raw timestamped evidence
- `findings(id, scan_id, check_id, source[custom|prowler|checkov], asset_id, title, description, severity[low|medium|high|critical], status[PASS|FAIL|ERROR], evidence_json, remediation, created_at)`
- `controls(id, framework, control_ref, title, description)`: loaded from YAML
- `check_control_map(check_id, control_id)`
- `control_results(id, scan_id, control_id, status[PASS|FAIL|NOT_ASSESSED|EXCEPTION], failing_finding_count)`
- `risks(id, finding_key, asset_id, title, likelihood, impact, inherent_score, rating, owner, treatment[mitigate|accept|transfer|avoid|none], treatment_note, residual_score, residual_rating, status[open|in_progress|mitigated|accepted|closed], first_seen_scan, last_seen_scan, due_date)`
  - `finding_key` = `check_id + asset_arn`, so the same issue across scans maps to one risk
- `exceptions(id, risk_id, control_id, justification, approved_by, expires_at, status[active|expired|revoked])`
- `evidence(id, scan_id, finding_id NULL, kind[snapshot|scanner_output|screenshot|note], path_or_json, sha256, created_at)`
- `reviews(id, type[control_review|access_review|policy_review], target, reviewer, due_date, completed_at, outcome, notes)`
- `policies(id, name, statement, linked_control_ids, last_reviewed_at)`
- `audit_log(id, user, action, entity, entity_id, ts)`

---

## 4. Collector (`collector/aws_collector.py`)

- Uses boto3 with an assumed read-only role (`SecurityAudit` + `ViewOnlyAccess` managed policies). No write calls.
- Collects per service and stores in `snapshots` with timestamp and SHA-256 hash (also stored as `evidence`):
  - **IAM:** account summary, password policy, users, MFA devices, access keys (age, last used), root account status, attached admin policies
  - **S3:** buckets, public access block, bucket policy/ACL, default encryption, versioning, logging, TLS-only policy
  - **EC2/VPC:** security groups and rules, NACLs, instances (public IP), EBS volumes (encrypted), VPC flow logs, default EBS encryption
  - **CloudTrail:** trails, multi-region, log validation, logging status, KMS encryption
  - **CloudWatch/Config/GuardDuty:** enabled status, alarms for key events (root usage, unauthorized API calls)
  - **KMS:** keys, rotation status
  - **RDS:** instances, encryption, public accessibility, backups
- Populates/updates `assets` with criticality (from tag `criticality`, default 2) and exposure (derived: public IP/SG open to 0.0.0.0/0 or public bucket -> `public`).

---

## 5. Assessment Engine

**Normalized finding format** (every source maps to this):
```json
{"check_id":"s3_bucket_public_access_blocked","source":"custom","asset_arn":"arn:aws:s3:::x",
 "title":"...","description":"...","severity":"high","status":"FAIL",
 "evidence":{...},"remediation":"..."}
```

**Custom checks** (each is a function `(snapshot) -> list[Finding]`, registered with a decorator). Minimum set (~20):

| Area | check_id | Severity |
|---|---|---|
| IAM | `iam_root_mfa_enabled` | critical |
| IAM | `iam_root_no_access_keys` | critical |
| IAM | `iam_user_mfa_enabled` | high |
| IAM | `iam_password_policy_strong` (len>=14, complexity) | medium |
| IAM | `iam_access_key_rotated_90d` | medium |
| IAM | `iam_no_wildcard_admin_policy` | high |
| S3 | `s3_public_access_blocked` | high |
| S3 | `s3_encryption_enabled` | medium |
| S3 | `s3_versioning_enabled` | low |
| S3 | `s3_tls_only_policy` | medium |
| Network | `sg_no_ssh_open_world` (22) | high |
| Network | `sg_no_rdp_open_world` (3389) | high |
| Network | `sg_no_all_traffic_open_world` | critical |
| Network | `vpc_flow_logs_enabled` | medium |
| Logging | `cloudtrail_enabled_multiregion` | high |
| Logging | `cloudtrail_log_validation` | medium |
| Logging | `guardduty_enabled` | medium |
| Encryption | `ebs_default_encryption` | medium |
| Encryption | `rds_encrypted` | high |
| Encryption | `kms_key_rotation_enabled` | low |

**Scanner adapters:** `prowler.py` runs `prowler aws -M json-ocsf -o <dir>` (or reads a supplied JSON) and converts to normalized findings (`source="prowler"`). `checkov.py` runs `checkov -d infra/ -o json` for IaC findings. If a scanner binary is missing, log a warning and skip. The app must still work with custom checks only.

**Dedup:** when a Prowler and a custom finding cover the same check and asset, keep both rows but count once in scoring (use `check_id` mapping; prefer custom).

---

## 6. GRC Engine

### 6.1 Frameworks and control mapping
Frameworks (confirmed): **ISO/IEC 27001:2022 (Annex A)**, **NIST (CSF 2.0 / SP 800-53 refs)**, **CIS AWS Foundations Benchmark**. Store a subset (~25-35 controls total) in `controls.yaml`; verify references against the benchmark version you use. The table below is a starting seed:

| check_id | ISO 27001 | NIST | CIS AWS |
|---|---|---|---|
| iam_root_mfa_enabled | A.8.5 | IA-2 | 1.5 |
| iam_root_no_access_keys | A.8.2 | AC-6 | 1.4 |
| iam_user_mfa_enabled | A.8.5 | IA-2 | 1.10 |
| iam_password_policy_strong | A.5.17 | IA-5 | 1.8 |
| iam_access_key_rotated_90d | A.5.17 | IA-5 | 1.14 |
| iam_no_wildcard_admin_policy | A.8.2, A.5.15 | AC-6 | 1.16 |
| s3_public_access_blocked | A.8.3 | AC-3 | 2.1.4 |
| s3_encryption_enabled | A.8.24 | SC-28 | 2.1.1 |
| s3_tls_only_policy | A.8.24 | SC-8 | 2.1.2 |
| s3_versioning_enabled | A.8.13 | CP-9 | n/a |
| sg_no_ssh_open_world | A.8.20, A.8.22 | SC-7 | 5.2 |
| sg_no_rdp_open_world | A.8.20, A.8.22 | SC-7 | 5.2 |
| sg_no_all_traffic_open_world | A.8.20 | SC-7 | 5.2 |
| vpc_flow_logs_enabled | A.8.15, A.8.16 | AU-12 | 3.9 |
| cloudtrail_enabled_multiregion | A.8.15 | AU-2 | 3.1 |
| cloudtrail_log_validation | A.8.15 | AU-9 | 3.2 |
| guardduty_enabled | A.8.16 | SI-4 | n/a |
| ebs_default_encryption | A.8.24 | SC-28 | 2.2.1 |
| rds_encrypted | A.8.24 | SC-28 | 2.3.1 |
| kms_key_rotation_enabled | A.8.24 | SC-12 | 3.6 |

`mapping.yaml` format:
```yaml
s3_public_access_blocked:
  - {framework: ISO27001, ref: A.8.3}
  - {framework: NIST, ref: AC-3}
  - {framework: CIS, ref: "2.1.4"}
```
Unmapped scanner checks are stored but marked "unmapped" (shown in a gap list).

### 6.2 Compliance scoring (`compliance.py`)
Per scan, per control:
- `FAIL` if any mapped check has a FAIL finding (not covered by an active exception)
- `EXCEPTION` if all failing findings have an active approved exception
- `PASS` if mapped checks exist and all pass
- `NOT_ASSESSED` if no mapped check ran

Framework score = `PASS / (PASS + FAIL + EXCEPTION) * 100`. Controls with NOT_ASSESSED are excluded and reported as a coverage % (`assessed / total`).

### 6.3 Risk methodology (`risk.py`, config in `risk_config.yaml`)
Explainable 5x5 model applied to every FAIL finding:
- **Likelihood (1-5)** from exposure + severity: `public`=5, `internal`=3, `private`=2; +1 (cap 5) if severity is critical/high.
- **Impact (1-5)** = `round((severity_value + asset_criticality_value) / 2)`, where severity low/medium/high/critical -> 1/2/4/5 and criticality 1/2/3 -> 1/3/5.
- **Inherent score** = L x I (1-25).
- **Rating bands:** 1-4 Low, 5-9 Medium, 10-16 High, 17-25 Critical.
- The UI shows the breakdown (likelihood reason, impact reason) next to every score.

### 6.4 Risk register and treatment (`register.py`)
- One `risk` row per `finding_key`. A new scan creates new risks, updates `last_seen_scan` for existing ones, and sets `status=mitigated` when the finding passes on re-scan.
- Treatment options: **mitigate / accept / transfer / avoid**. Requires owner and note; accept requires an approved exception with expiry.
- **Residual score rules:**
  - mitigate + verified by re-scan -> residual = 1x1
  - mitigate in progress -> residual = inherent
  - accept -> residual = inherent
  - transfer -> impact halved (rounded up)
  - avoid -> closed, residual = 0
- **Exceptions:** create, approve (admin only), auto-expire (checked on each scan and by the scheduler). Expired exceptions revert the control to FAIL.

### 6.5 Governance and review (`review.py`)
- `policies.yaml`: ~8 policy statements (e.g. MFA required, encryption at rest, logging enabled), each linked to controls. The policy page shows compliance status per policy, derived from its linked controls.
- **Periodic reviews:** generate review tasks (control review, access review) with due dates. The access review lists IAM users, keys, and privileged policies from the latest snapshot for the reviewer to mark keep/revoke. Overdue items are highlighted.

---

## 7. API (FastAPI; HTML pages call these or render server-side)

```
POST /api/scans                  # trigger scan {environment, label}
GET  /api/scans                  # list
GET  /api/scans/{id}             # summary
GET  /api/scans/compare?a=&b=    # diff: fixed / new / unchanged findings, score deltas
GET  /api/findings?scan=&severity=&service=&status=
GET  /api/controls?framework=&scan=
GET  /api/compliance/{scan_id}   # framework scores + coverage
GET  /api/risks                  # filter by rating, status, owner
PATCH /api/risks/{id}            # owner, treatment, note, status
POST /api/exceptions             # request
POST /api/exceptions/{id}/approve
GET  /api/reviews  POST /api/reviews/{id}/complete
GET  /api/evidence?scan=         # list + hash verification
POST /api/reports                # {scan_id, type: audit|technical, format: pdf|html}
GET  /api/reports/{id}/download
```
CLI: `python -m app.cli seed|scan --env vulnerable|report --scan N`.

---

## 8. Dashboard Pages

1. **Overview:** framework compliance gauges, risk-rating distribution, top 10 risks, findings by service, latest scan info.
2. **Trends:** line charts of compliance score and open-risk count across scans (shows improvement vs the vulnerable baseline).
3. **Findings:** filterable table; detail view with evidence JSON and remediation guidance.
4. **Controls:** per framework, status per control, drill-down to findings and gap analysis (failing + not assessed).
5. **Risk register:** table with rating, owner, treatment, residual; edit form; risk score breakdown.
6. **Exceptions and reviews:** exception requests/approvals, review tasks, access review.
7. **Scans:** history, trigger scan, compare two scans.
8. **Reports:** generate and download.

---

## 9. Reports

- **Audit report** (primary): cover, scope (assets, regions, frameworks), methodology (steps from section 6.3 and 6.2), executive summary, compliance scores per framework, control status table, findings with risk ratings, risk register extract with treatment and residual risk, exceptions, evidence index (with hashes), recommendations, scan-over-scan improvement.
- **Technical report:** findings by service, severity, evidence, remediation steps, before/after comparison.

---

## 10. Test Lab (Terraform)

- `infra/vulnerable/`: intentionally misconfigured AWS resources: public S3 bucket without encryption, SG open on 22/3389, no MFA user with admin policy, old access key, no CloudTrail, unencrypted EBS/RDS (use cheap/free-tier sizes).
- `infra/hardened/`: same resources fixed: block public access, SSE-KMS, TLS-only policy, restricted SGs, CloudTrail multi-region with validation, flow logs, GuardDuty, encrypted volumes.
- Demo flow: scan vulnerable -> review risks -> apply `hardened` -> re-scan -> compare (scores up, risks mitigated).
- Safety: dedicated AWS account or sandbox, billing alarm, `terraform destroy` after demos.

---

## 11. Build Order (milestones)

1. Project skeleton, Docker, DB models, auth, seed data (controls, mapping, policies).
2. Terraform lab + collector -> snapshots.
3. Custom checks + normalized findings + engine runner (CLI scan works end to end).
4. Mapping + compliance scoring + control results.
5. Risk scoring + risk register + treatment + exceptions.
6. API + dashboard pages (overview, findings, controls, risks).
7. Prowler/Checkov adapters.
8. Scan comparison + trends + reviews/policies + evidence hashing.
9. Reports (audit + technical PDF/HTML).
10. Polish, demo run on both environments, README.

## 12. Constraints and Conventions

- All AWS calls read-only; credentials via env or role, never committed.
- Type hints, Pydantic schemas, small functions; one module per check area.
- Every check must emit PASS and FAIL findings with evidence JSON and remediation text.
- Add unit tests for checks (mock boto3 with `moto` or fixtures) and for risk/compliance scoring.
- Config values (bands, severity weights, thresholds) live in YAML, not hardcoded.
