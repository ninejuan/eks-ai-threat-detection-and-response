# ATDR Project Conventions

## Non-Negotiable Project Instructions

These instructions override convenience, personal preference, and generic best practices. If a future agent or contributor is about to choose a different architecture, they must stop, re-read this section, and implement the project-specific requirement instead.

- Follow `refs/eksai1.jpg` and `refs/eksai2.jpg` as the source-of-truth architecture diagrams. Do not replace their architecture with a simpler local interpretation.
- Use `../k8s-noisy-neighbor-control` as the reference implementation for operational patterns before inventing new deployment or Makefile behavior.
- Remediation must use EKS MCP. Lambda remediation code must not call the Kubernetes API directly, must not manage kubeconfig directly, and must not shell out to `kubectl` for remediation. The allowed path is: Remediation Agent → MCP client/token → EKS MCP server → Kubernetes API.
- The MCP auth token secret is required. Do not remove it as "unused"; wire it into both Lambda-side clients and the in-cluster MCP server authentication path.
- Infrastructure mutation must go through `make infra-up`, `make infra-down`, `make platform-up`, or `make platform-down`. Do not run `terraform apply`, `terraform destroy`, direct AWS mutation commands, or ad-hoc `kubectl apply` for project infrastructure outside those Make targets.
- No placeholders in implementation paths. `TODO`, fake ARNs/account IDs, sample domains, stub handlers, and mock-only code are unacceptable unless they are clearly documentation examples and cannot run in production.
- The project domain is `atdr.juany.dev`. Do not use `atdr.io` or other substitute domains.
- EKS identity must use EKS Pod Identity, not IRSA. Do not add OIDC-provider/IRSA-based service account role annotations unless explicitly documenting legacy alternatives.
- `gp3` must be the default storage class for persistent Kubernetes storage.
- EKS add-on updates must preserve user-managed config with `resolve_conflicts_on_update = "PRESERVE"`. Do not use `OVERWRITE`.
- Do not add `Co-authored-by`, Sisyphus branding, or any other agent attribution to commits unless the user explicitly requests it.
- Do not commit generated deployment artifacts such as Lambda zip bundles, build outputs, or other reproducible archives unless the user explicitly requests tracked artifacts.
- Do not create one commit per file or per trivial artifact. Group commits by logical change that can be reviewed and reverted independently.
- Do not modify `Makefile` or other operator-facing entrypoints merely to run one-off restart, rollout, debug, or recovery commands needed for the current session. Run those commands directly. Only change user-facing workflows when the change is a durable improvement for future operators.

## Instruction-Drift Defense

Before any non-trivial edit, run this mental checklist and verify with repository search when relevant:

1. Does the change bypass EKS MCP, Slack approval, Step Functions, Pod Identity, gp3, or the reference diagrams?
2. Does it remove a secret, Make target, Terraform resource, or Kubernetes manifest because it looks unused without first proving the intended data path?
3. Does it introduce placeholders, hardcoded account IDs/regions/domains, direct `kubectl`, direct Kubernetes clients from Lambda, or IRSA/OIDC drift?
4. Does it mutate infrastructure outside the sanctioned Make targets?
5. Does it add commit attribution the user did not ask for, commit generated artifacts, or turn Makefile into a one-off command wrapper for the current debugging session?
6. Does it split commits by file instead of by logical unit?

If the answer to any item is yes, do not proceed with that approach. Fix the design so it satisfies the explicit project constraints first, then implement.

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
