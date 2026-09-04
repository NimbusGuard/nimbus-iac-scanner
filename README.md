# nimbus-iac-scanner

Shift-left IaC scanning for NimbusGuard (roadmap E2.6). Parses
Terraform, CloudFormation, and Bicep source, evaluates it against the
same real control catalog a runtime NimbusGuard scan uses, and fails
your CI pipeline with the *exact same control ID* a runtime scan would
surface — closing this ficha's own "listo cuando" criterion literally:
**a PR that introduces a public S3 bucket fails the check with
`NG-AWS-S3-001`, the same control ID your scheduled cloud scans already
use.**

This CLI never talks to AWS/Azure and never deploys anything — it
reads your IaC source, builds the same resource shape a real scan would
produce, and asks `nimbus_app`'s own `POST /iac/gate-check` (a proxy in
front of the shared Evaluation Engine) whether it would pass.

## Quick start

```bash
pip install nimbus-iac-scanner   # or: pip install git+https://github.com/NimbusGuard/nimbus-iac-scanner.git

export NIMBUS_API_URL="https://your-nimbusguard-instance/v1"
export NIMBUS_API_KEY="nbg_..."   # a service account with view_findings

nimbus-iac-scan --path infra/
```

All three formats (Terraform `*.tf`, CloudFormation
`*.json`/`*.yaml`/`*.yml`, Bicep `*.bicep`) are evaluated in one combined
pass — every recognized resource, regardless of which format declared
it, goes into the same gate-check call and the same report. Bicep needs
the real `bicep` CLI on PATH (`az bicep install`, or see
[Microsoft's own install docs](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install))
— if `.bicep` files are found but the CLI isn't available, the scan
fails loudly (exit code `2`) rather than silently skipping them.

Exit codes: `0` passed, `1` a real misconfiguration blocked the build,
`2` the check itself couldn't run (bad credentials, unreachable API, a
real IaC syntax error, a missing `bicep` CLI).

### Blocking policy (which findings fail the build)

By default any FAIL blocks the build. Two ways to change that:

- `--min-severity HIGH` (or CRITICAL/MEDIUM/LOW/INFORMATIONAL) — only a
  FAIL at or above that severity blocks; lower-severity FAILs are
  reported but don't fail the build.
- **A central policy on the platform.** An org admin can set
  `iac_block_severity` on the organization in NimbusGuard
  (`PATCH /organizations/{id}`); the CLI reads it from the gate-check
  response and uses it as the default threshold, so the block policy
  lives in one place instead of every pipeline's YAML. Precedence: an
  explicit `--min-severity` flag always wins; otherwise the org policy;
  otherwise any FAIL blocks. (A FAIL of unknown severity always blocks —
  fail-closed.)

### `--changed-only` (scan just the PR delta)

For a repo with a large existing backlog, `--changed-only` evaluates only
the IaC files changed in the current PR/MR (or since `--diff-base`),
instead of the whole tree — so a PR's report doesn't re-list every
pre-existing finding in the repo.

```bash
nimbus-iac-scan --path infra/ --changed-only
nimbus-iac-scan --path infra/ --changed-only --diff-base origin/main
```

It resolves the base ref from the CI's own PR/MR context automatically
(GitHub `GITHUB_BASE_REF`, GitLab `CI_MERGE_REQUEST_DIFF_BASE_SHA`/target
branch), falling back to `HEAD~1` on a plain push. Needs a git checkout
with the base ref available — if the diff genuinely can't be computed
(shallow clone without the base, not a git repo), it exits `2` (the check
couldn't run as requested) rather than silently full-scanning. A PR that
changes no IaC files exits `0` cleanly.

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
never duplicating) a summary comment on the PR. Installs the real
`bicep` CLI automatically (set `install-bicep: false` to skip this if
you have no `.bicep` files or already install it yourself).

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
GitLab project — never commit them. For MR-comment posting/updating
(mirrors the GitHub Action's own behavior), also set
`NIMBUS_GITLAB_TOKEN` — a real GitLab Personal/Project Access Token
with `api` scope, masked, never GitLab's own predefined `$CI_JOB_TOKEN`
(its permission to post arbitrary MR notes isn't reliable across every
project's own settings).

## What's covered today

A deliberately curated, real slice per format — not an attempt at
exhaustive coverage.

### Terraform

| Resource | nimbus_app control(s) | Notes |
|---|---|---|
| `aws_s3_bucket` + `aws_s3_bucket_public_access_block` | `NG-AWS-S3-001` (public access) | The public-access-block resource must reference the bucket (by Terraform reference or by its literal bucket name) for this to evaluate — a bucket with no such resource in your Terraform is honestly `NOT_EVALUATED`, never a guessed PASS or FAIL. |
| `aws_security_group` (inline `ingress {}` blocks + the newer, decomposed `aws_vpc_security_group_ingress_rule`) | `NG-AWS-EC2-001`/`002` (SSH/RDP exposure) and any other security_group-targeted control | Both rule shapes merge into the same evaluated rule set. A standalone `aws_vpc_security_group_ingress_rule` referencing a security group NOT declared in the same Terraform (e.g. a data-sourced or externally-managed one) is skipped — see Known gaps. |
| `aws_db_instance` | `NG-AWS-RDS-001` (public accessibility), `NG-AWS-RDS-002` (storage encryption) | `publicly_accessible`/`storage_encrypted` both default to `false` when omitted (Terraform's own confirmed, documented default), never a guess. |
| `aws_kms_key` | `NG-AWS-KMS-001` (key rotation) | A Terraform-declared key is always treated as customer-managed (a structural fact — AWS-managed keys are never created as a resource). `customer_master_key_spec` defaults to `SYMMETRIC_DEFAULT`, `enable_key_rotation` defaults to `false`, both confirmed Terraform defaults. |
| `aws_cloudtrail` | `NG-AWS-CLOUDTRAIL-001` (logging enabled) | `enable_logging` defaults to `true` when omitted (confirmed Terraform default). |
| `aws_ebs_volume` | (encryption, via any `ebs_volume`-targeted control) | `encrypted` has no documented Terraform-level default — omitted entirely unless your Terraform sets it explicitly, never guessed either direction. |
| `aws_iam_user` / `aws_iam_role` + `*_policy_attachment` / `*_policy` (inline) | `NG-AWS-IAM-001` (users) / `NG-AWS-IAM-012` (roles), admin-privilege detection | Attached-policy correlation (by ARN) is fully reliable. Inline-policy JSON is parsed from a heredoc or an escaped string literal; a `jsonencode(...)` policy body (a common, idiomatic way to write this) can't be evaluated by a static parser and is silently omitted from that one principal's own `inline_policies` — see Known gaps. |

### CloudFormation

The SAME 8 concepts as Terraform, above — but CloudFormation expresses
several of them as plain, already-inline properties on a single
resource rather than a separate, cross-referenced one (no separate
"public access block" or "policy attachment" resource needed):

| Resource | nimbus_app control(s) | Notes |
|---|---|---|
| `AWS::S3::Bucket` | `NG-AWS-S3-001` | `PublicAccessBlockConfiguration` is inline on the bucket itself. |
| `AWS::EC2::SecurityGroup` | `NG-AWS-EC2-001`/`002` | `SecurityGroupIngress` is an inline list on the resource; only the `CidrIp` (ipv4) source is mapped. |
| `AWS::RDS::DBInstance` | `NG-AWS-RDS-001`/`002` | `StorageEncrypted` defaults `false` (confirmed CloudFormation default); `PubliclyAccessible` has **no** single documented CloudFormation default at all (confirmed live — depends on your VPC/subnet setup) and is omitted entirely if absent, a real, disclosed difference from the Terraform mapper's own behavior for the equivalent argument. |
| `AWS::KMS::Key` | `NG-AWS-KMS-001` | Same confirmed defaults as Terraform (`KeySpec` → `SYMMETRIC_DEFAULT`, `EnableKeyRotation` → `false`). |
| `AWS::CloudTrail::Trail` | `NG-AWS-CLOUDTRAIL-001` | `IsLogging` is a **required** CloudFormation property with no documented default at all — genuinely different from Terraform's own `enable_logging` (which defaults `true`); omitted if genuinely absent, never guessed. |
| `AWS::EC2::Volume` | (encryption) | `Encrypted` has no documented CloudFormation default — omitted unless explicitly set. |
| `AWS::IAM::Role` / `AWS::IAM::User` | `NG-AWS-IAM-001`/`012` | `ManagedPolicyArns` is a plain list of ARN strings (no separate attachment resource); `Policies[].PolicyDocument` arrives ALREADY as a native, parsed JSON object — no string-parsing dance at all, unlike Terraform's own `jsonencode(...)`/heredoc complications. |

### Bicep (Azure)

A deliberately narrower slice than the AWS-side formats above — the
same "narrower first, real and working over exhaustive" precedent this
tool already applies to its own AWS coverage:

| Resource | nimbus_app control(s) | Notes |
|---|---|---|
| `Microsoft.Storage/storageAccounts` | `NG-AZURE-STORAGE-001` | `allowBlobPublicAccess` — Microsoft's own current ARM reference states "the default interpretation is false for this property," confirmed live, not guessed; treated as `false` when absent. |
| `Microsoft.Network/networkSecurityGroups` | `NG-AZURE-NET-001` and any other network_security_group-targeted control | `securityRules[]` mapped from ARM's own camelCase property names to the exact snake_case shape the real evaluation-engine control reads. |

Compiled via the real `bicep` CLI (`bicep build --stdout`) — this
tool trusts the ONE canonical, Microsoft-maintained compiler for what a
`.bicep` file actually resolves to, rather than a second, independent
Bicep parser.

A resource type none of the above tables list is silently skipped from
evaluation (never sent, never fabricated as passing) — the CLI's own
report lists which unrecognized types it saw, so nothing disappears
without a trace.

## Known gaps, deliberate

- **A curated set of resource types per format, not the full catalog**
  — extending this means adding an entry to the matching `_MAPPERS`
  registry (`resource_mapping.py`/`cloudformation_mapping.py`/
  `bicep_mapping.py`), using the real `configuration.*` field shape the
  matching evaluation-engine control actually reads (confirmed by
  reading that control's own source, never guessed from a field name
  alone).
- **A standalone Terraform `aws_vpc_security_group_ingress_rule` can
  only be correlated when it references a security group declared in
  the SAME Terraform parse** — Terraform never exposes a security
  group's eventual real `sg-xxxx` id statically, so a literal
  `security_group_id` string (an externally-managed or data-sourced
  security group) can't be matched back to anything and is skipped.
  `cidr_ipv6`/`prefix_list_id`/`referenced_security_group_id` sources
  on this resource aren't mapped either — only `cidr_ipv4`, matching
  the only source type NG-AWS-EC2-001/002 themselves ever inspect
  (this same scope also applies to CloudFormation's own
  `SecurityGroupIngress`).
- **A Terraform inline IAM policy written via `jsonencode(...)` can't
  be parsed** — a static parser can never evaluate a Terraform function
  call. Only a heredoc or a JSON string literal (escaped or not)
  parses; a `jsonencode(...)` policy is silently omitted from that
  principal's own `inline_policies`, never fabricated or crashed on.
  CloudFormation has no equivalent gap — `PolicyDocument` is always
  already a native object there.
- **Bicep is 2 resource types, not the full Azure catalog** — a real,
  disclosed narrower scope than the AWS-side formats' own 8. Extending
  it is the same registry-entry pattern as the others, once a new
  Azure control's own real ARM property shape is confirmed.
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

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python3 -m pytest
```

`python-hcl2` is deliberately pinned to `4.3.5`, not the latest 8.x —
see `nimbus_iac_scanner/terraform_parser.py`'s own docstring for the
confirmed, real reason (8.x changed its own output shape in a way
that breaks this tool's parsing).

Bicep-specific tests in `tests/test_bicep_parser.py` need the real
`bicep` CLI on PATH and skip gracefully (not fail) when it isn't
present — install it with `az bicep install` (note: this doesn't add
it to PATH, see Microsoft's own docs) or the manual method in
`.github/workflows/test.yml`.
