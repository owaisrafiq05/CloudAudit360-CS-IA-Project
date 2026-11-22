# CloudAudit360 Lab Infrastructure

Two Terraform stacks for the course demo:

| Stack | Purpose |
|---|---|
| `vulnerable/` | Intentionally misconfigured resources |
| `hardened/` | Same resource types with security controls applied |

## Safety

- Use a **dedicated AWS sandbox account** only.
- Set a billing alarm before `apply`.
- Run `terraform destroy` after demos.

## Demo flow

```bash
# 1. Deploy vulnerable lab (optional — DEMO_MODE uses fixtures without AWS)
cd infra/vulnerable && terraform init && terraform apply

# 2. Scan via CloudAudit360
python -m app.cli scan --env vulnerable

# 3. Review risks in the dashboard, then deploy hardened
cd ../hardened && terraform init && terraform apply

# 4. Re-scan and compare
python -m app.cli scan --env hardened
```

Without AWS credentials, set `DEMO_MODE=true` (default). The collector loads
`data/fixtures/vulnerable.json` and `hardened.json` instead.
