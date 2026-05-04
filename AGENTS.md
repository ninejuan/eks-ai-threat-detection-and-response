# ATDR Project Conventions

## Directory Structure

```
.
├── app/                    # Lambda function code (Python 3.12)
│   ├── agents/             # AI agent handlers (summary, triage, solution, remediation)
│   ├── ingestor/           # SQS → Step Functions trigger
│   ├── slack_bot/          # Slack events, interactions, commands
│   ├── degraded_notifier/  # Fallback Slack alerts when AI fails
│   └── shared/             # Common utilities (Bedrock, DynamoDB, Slack, secrets, config)
├── terraform/
│   ├── modules/            # Reusable Terraform modules (vpc, eks, iam, etc.)
│   └── envs/demo/          # Demo environment composition
├── kubernetes/             # Helm values and K8s manifests
│   ├── falco/              # Falco Helm values + custom rules
│   ├── tetragon/           # Tetragon TracingPolicies
│   ├── monitoring/         # Prometheus, Grafana, Loki Helm values
│   ├── external-secrets/   # ESO ClusterSecretStore + ExternalSecrets
│   └── admission-policies/ # ValidatingAdmissionPolicy (CEL)
├── tests/                  # pytest unit tests mirroring app/ structure
└── docs/                   # Design documents (Korean)
```

## Coding Conventions

### Python
- Linter: ruff (config in pyproject.toml)
- Line length: 120
- Formatter: ruff format
- All Lambda handlers: `def lambda_handler(event: dict, context) -> dict`
- Imports: absolute (`from app.shared.bedrock import BedrockClient`)
- No `# type: ignore`, no `as any`

### Terraform
- `terraform fmt` required (enforced by pre-commit)
- `terraform validate` must pass
- Module structure: main.tf, variables.tf, outputs.tf
- Resource naming: `${var.project}-<resource>`
- No hardcoded account IDs or regions

### YAML
- yamllint with .yamllint.yml config
- Max line length: 200

## Branch Strategy

- `main`: stable, all CI checks must pass
- `feat/<name>`: feature branches, PR into main
- `fix/<name>`: bug fix branches

## Commit Messages

```
<verb> <what was changed>

<optional body explaining why>
```

Verbs: Add, Fix, Update, Remove, Refactor

## Pre-commit Hooks

Runs automatically on every commit:
- trailing-whitespace, end-of-file-fixer
- check-yaml, check-json, detect-private-key
- terraform_fmt, terraform_validate
- ruff (lint + format)
- yamllint
