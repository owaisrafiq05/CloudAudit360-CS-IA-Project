# CloudAudit360

Single project covering **Cloud Security** and **Information Assurance (GRC)**.

Pipeline: **Collect → Assess → Normalize → Map → Score → Register → Report**

## Features

- Read-only AWS config collection (or DEMO fixtures without AWS credentials)
- ~20 custom security checks (IAM, S3, network, logging, encryption)
- Optional Prowler / Checkov adapters (skipped gracefully if binaries missing)
- Control mapping to ISO 27001, NIST, and CIS AWS Foundations
- Compliance scoring, 5×5 risk methodology, risk register, exceptions, reviews
- Server-rendered dashboard (Jinja2 + Chart.js + Tailwind CDN)
- Audit & technical reports (HTML / PDF)
- Terraform lab stacks: `infra/vulnerable` and `infra/hardened`

## Quick start (local demo)

Requires **Python 3.11+** (3.12 recommended).

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

python -m app.cli seed
python -m app.cli scan --env vulnerable
python -m app.cli scan --env hardened
uvicorn app.main:app --reload --port 8000
```

Open http://127.0.0.1:8000

| User | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| auditor | auditor123 | auditor |
| viewer | viewer123 | viewer |

`DEMO_MODE=true` (default) loads `data/fixtures/{vulnerable,hardened}.json` so the full demo works without AWS.

## Docker

```bash
docker compose up --build
```

App: http://localhost:8000 · Postgres on 5432

## CLI

```bash
python -m app.cli seed
python -m app.cli scan --env vulnerable|hardened|other
python -m app.cli report --scan 1 --type audit --format html
```

## API (session cookie or HTTP Basic)

- `POST /api/scans` · `GET /api/scans` · `GET /api/scans/compare?a=&b=`
- `GET /api/findings` · `GET /api/controls` · `GET /api/compliance/{scan_id}`
- `GET /api/risks` · `PATCH /api/risks/{id}`
- `POST /api/exceptions` · `POST /api/exceptions/{id}/approve`
- `GET /api/reviews` · `POST /api/reviews/{id}/complete`
- `GET /api/evidence?scan=` · `POST /api/reports` · `GET /api/reports/{id}/download`

## Demo narrative (both courses)

1. Scan **vulnerable** → many FAIL findings, low compliance, Critical/High risks
2. Review risk register, assign owners/treatments, request exceptions
3. Apply `infra/hardened` (or just scan the hardened fixture)
4. Re-scan **hardened** → scores rise to 100%, risks mitigated
5. Compare scans, generate audit report with evidence hashes

## Tests

```bash
pytest -q
```

## Safety

- All AWS API usage is read-only.
- Never commit credentials. Use `.env` / IAM roles.
- Terraform labs: dedicated sandbox account, billing alarm, `terraform destroy` after demos.

## Project layout

See `docs/CloudAudit360_SPEC.md` for the full technical specification.
