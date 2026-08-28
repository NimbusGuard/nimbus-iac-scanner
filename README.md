# nimbus-iac-scanner

Shift-left IaC scanning for NimbusGuard (roadmap E2.6). Parses
Terraform source, evaluates it against the same real control catalog a
runtime NimbusGuard scan uses, and fails your CI pipeline with the
*exact same control ID* a runtime scan would surface — closing this
ficha's own "listo cuando" criterion literally: **a PR that introduces
a public S3 bucket fails the check with `NG-AWS-S3-001`, the same
control ID your scheduled cloud scans already use.**

This CLI never talks to AWS/Azure and never deploys anything — it
reads your Terraform source, builds the same resource shape a real
scan would produce, and asks `nimbus_app`'s own
`POST /iac/gate-check` (a proxy in front of the shared Evaluation
Engine) whether it would pass.

## Quick start

```bash
pip install nimbus-iac-scanner   # or: pip install git+https://github.com/NimbusGuard/nimbus-iac-scanner.git

export NIMBUS_API_URL="https://your-nimbusguard-instance/v1"
export NIMBUS_API_KEY="nbg_..."   # a service account with view_findings

nimbus-iac-scan --path infra/
```

Exit codes: `0` passed, `1` a real misconfiguration blocked the build,
`2` the check itself couldn't run (bad credentials, unreachable API).

## GitHub Actions

```yaml
- uses: NimbusGuard/nimbus-iac-scanner@main
  with:
    api-url: https://your-nimbusguard-instance/v1
    api-key: ${{ secrets.NIMBUS_API_KEY }}
    path: infra/
    min-severity: HIGH   # optional — default: any FAIL blocks the build
```

On a `pull_request`-triggered run, this also posts (and keeps updating,
never duplicating) a summary comment on the PR.

## GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/NimbusGuard/nimbus-iac-scanner/main/gitlab/nimbus-iac-scan.gitlab-ci.yml'

nimbus-iac-scan:
  extends: .nimbus-iac-scan
  variables:
    NIMBUS_IAC_SCAN_PATH: "infra/"
```

Set `NIMBUS_API_URL`/`NIMBUS_API_KEY` as masked CI/CD variables in your
GitLab project — never commit them. No MR-comment support yet (see
"Known gaps" below); the pipeline still genuinely fails the build on a
real misconfiguration.

## What's covered today

A deliberately narrow, real first slice — not an attempt at exhaustive
coverage:

| Terraform resource | nimbus_app control(s) | Notes |
|---|---|---|
| `aws_s3_bucket` + `aws_s3_bucket_public_access_block` | `NG-AWS-S3-001` (public access) | The public-access-block resource must reference the bucket (by Terraform reference or by its literal bucket name) for this to evaluate — a bucket with no such resource in your Terraform is honestly `NOT_EVALUATED`, never a guessed PASS or FAIL. |
| `aws_security_group` (inline `ingress {}` blocks) | `NG-AWS-EC2-001`/`002` (SSH/RDP exposure) and any other security_group-targeted control | The newer, decomposed `aws_vpc_security_group_ingress_rule` resource (AWS provider v5+) is not mapped yet — see Known gaps. |

A Terraform resource type this tool doesn't recognize is silently
skipped from evaluation (never sent, never fabricated as passing) —
the CLI's own report lists which unrecognized types it saw, so nothing
disappears without a trace.

## Known gaps, deliberate

- **CloudFormation and Bicep parsing** — not built. This is Terraform-
  only today; the roadmap's own original scope named all three, and
  the other two remain real, disclosed, unstarted work.
- **Only 2 resource types mapped** (S3 public access, security group
  ingress) — the curated starting set, not the full catalog. Extending
  this means adding an entry to `nimbus_iac_scanner/resource_mapping.py`'s
  own `_MAPPERS` registry per new Terraform resource type, using the
  real `configuration.*` field shape the matching evaluation-engine
  control actually reads (confirmed by reading that control's own
  source, never guessed from a field name alone).
- **`aws_vpc_security_group_ingress_rule`** (the newer, decomposed AWS
  provider v5+ resource) is not mapped — only the classic inline
  `ingress {}` block on `aws_security_group` itself.
- **No custom controls** — only the built-in catalog, same scope
  boundary `POST /cwpp/gate-check` (nimbus_app's own CWPP CI/CD gate)
  already established for the identical reason: a customer's own
  custom Rego control has no stable id a CI tool could reference
  safely without a real per-org auth context, which a platform-wide
  service account intentionally doesn't have.
- **No admission controller for Kubernetes via this path** — that's a
  different concept from nimbus_app's own CWPP admission webhook
  (which already evaluates containers/pods against the
  NG-CONTAINER-*/NG-K8S-* catalog); an IaC-resource-level admission
  controller isn't built.
- **No GitLab MR-comment posting** — the GitHub Action posts/updates a
  PR comment; the GitLab template only fails the pipeline today.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python3 -m pytest
```

`python-hcl2` is deliberately pinned to `4.3.5`, not the latest 8.x —
see `nimbus_iac_scanner/terraform_parser.py`'s own docstring for the
confirmed, real reason (8.x changed its own output shape in a way
that breaks this tool's parsing).
