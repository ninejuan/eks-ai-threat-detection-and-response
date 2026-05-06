# ATDR Project Conventions

## Non-Negotiable Project Instructions

These instructions override convenience, personal preference, and generic best practices. If a future agent or contributor is about to choose a different architecture, they must stop, re-read this section, and implement the project-specific requirement instead.

- Follow `refs/eksai1.jpg` and `refs/eksai2.jpg` as the source-of-truth architecture diagrams. Do not replace their architecture with a simpler local interpretation.
- Use `../k8s-noisy-neighbor-control` as the reference implementation for operational patterns before inventing new deployment or Makefile behavior.
- Remediation must use EKS MCP. Lambda remediation code must not call the Kubernetes API directly, must not manage kubeconfig directly, and must not shell out to `kubectl` for remediation. The allowed path is: Remediation Agent → MCP client/token → EKS MCP server → Kubernetes API.
- The MCP auth token secret is required. Do not remove it as "unused"; wire it into both Lambda-side clients and the in-cluster MCP server authentication path.
- Infrastructure mutation must go through `make infra-up`, `make infra-down`, `make platform-up`, or `make platform-down`. Do not run `terraform apply`, `terraform destroy`, direct AWS mutation commands, or ad-hoc `kubectl apply` for project infrastructure outside those Make targets.
- Do not reach for `aws` CLI mutating verbs (`put-secret-value`, `update-function-configuration`, `update-function-code`, `update-service`, `put-function-concurrency`, `attach-role-policy`, `put-role-policy`, `create-*`, `delete-*`, `update-*` on live resources), `aws ssm send-command`, `kubectl apply/edit/patch/delete/scale/rollout/cordon/drain`, `helm upgrade/uninstall`, `eksctl ...`, or any other live-resource mutation as a shortcut to "just fix this one instance" when a failure happens in the deployed environment. This is not faster; it creates silent drift from Terraform / Helm / Kubernetes manifests and destroys the debugging trail. If a deployed resource is wrong, change the source artifact (`terraform/`, `kubernetes/`, `app/`, Makefile target) and re-run the sanctioned `make` target. Read-only AWS/kubectl calls (`describe-*`, `get-*`, `list-*`, `logs`, `exec -it ... -- sh`, `port-forward` for inspection) are fine and encouraged for diagnosis.
- Never run a mutating CLI command against the live account or cluster without an explicit, in-this-turn user instruction. "The user is waiting" is not permission. If the sanctioned path requires a Make target the user hasn't asked to run, stop and ask. Queue the proposed command, show the expected diff/effect, and wait.
- No placeholders in implementation paths. `TODO`, fake ARNs/account IDs, sample domains, stub handlers, and mock-only code are unacceptable unless they are clearly documentation examples and cannot run in production.
- The project domain is `atdr.juany.dev`. Do not use `atdr.io` or other substitute domains.
- EKS identity must use EKS Pod Identity, not IRSA. Do not add OIDC-provider/IRSA-based service account role annotations unless explicitly documenting legacy alternatives.
- `gp3` must be the default storage class for persistent Kubernetes storage.
- EKS add-on updates must preserve user-managed config with `resolve_conflicts_on_update = "PRESERVE"`. Do not use `OVERWRITE`.
- Do not add `Co-authored-by`, Sisyphus branding, or any other agent attribution to commits unless the user explicitly requests it.
- Do not commit generated deployment artifacts such as Lambda zip bundles, build outputs, or other reproducible archives unless the user explicitly requests tracked artifacts.
- Do not create one commit per file or per trivial artifact. Group commits by logical change that can be reviewed and reverted independently.
- Commit messages must be 25 characters or fewer. No exceptions.
- Do not modify `Makefile` or other operator-facing entrypoints merely to run one-off restart, rollout, debug, or recovery commands needed for the current session. Run those commands directly. Only change user-facing workflows when the change is a durable improvement for future operators.
- Do not modify production code to paper over a failure you have not yet diagnosed. Added retry loops, bumped timeouts, extra warmups, removed caches, and broadened `except` clauses are not debugging — they hide the signal and add latency on the happy path. Before any such change, pull the actual error from CloudWatch Logs (`/aws/lambda/atdr-*`), `kubectl logs -n atdr deploy/eks-mcp-server`, or the DynamoDB `execution_log`, and cite the exact call site that failed. Then make the targeted fix.
- When the Remediation agent executes a multi-step isolation plan, the step order is a correctness invariant, not a hint. Forensic capture must complete before any destructive or network-isolating step. If an LLM tool-use loop is what drives the order, it MUST be guarded in `handler.py` so that `delete_pod`, `patch_deployment(replicas=0)`, `apply_cilium_network_policy`, and `cordon_node`/`drain_node` cannot execute until `checkpoint_pod` (and `capture_hubble_flows` when applicable) returned `status=success` in the current `execution_log`. The SYSTEM_PROMPT alone is not sufficient; models reorder.
- MCP tool input schemas exposed to the LLM must not include parameters the system owns. Destination buckets, IAM roles, cluster names, AWS regions, account IDs, and any other "where the action actually lands" values MUST come from environment variables, the `Config` object, or server-side constants — not from tool arguments the model can hallucinate. Likewise, any user- or model-supplied string that flows into a Kubernetes label, annotation, DNS name, or resource name MUST be sanitized server-side (MCP server) against the K8s validation rules before the API call; client-side sanitization in `tools.py` is not sufficient because the server is the last line of defense.
- Incident identity (the `incident_id`) is a system-owned value. It MUST NOT appear in any MCP tool input_schema exposed to the LLM. `app/agents/remediation/tools.py::execute_tool` is responsible for injecting it into the `tool_input` of every tool in `INCIDENT_AWARE_TOOLS` before calling `McpClient.call_tool`. The server-side `_sanitize_incident_id` must run on every inbound value; unparseable incident IDs fall back to the `adhoc/` evidence prefix.
- Experimental MCP tools (currently `checkpoint_container_experimental`) MUST report `status="unsupported"` with an actionable reason and a `fallback_recommendation` pointing at a non-experimental tool whenever runtime capability detection fails. They MUST NOT throw exceptions upward that would cause the incident pipeline to fail — `_checkpoint_result()` is the single exit point. Experimental capability failures are expected and are not remediation failures.

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
