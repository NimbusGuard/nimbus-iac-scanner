# nimbus-iac-scanner — competitor analysis & robustness roadmap

> Written 2026-09-03. Grounds the "make IaC scanning very robust — research
> what other providers do well and badly, and improve" effort. This is a
> living plan, not a spec; each item links to the safe/incremental discipline
> the repo already follows (confirm every config field against the real
> Evaluation Engine control source, never guess).

## Where the market is (2025–2026)

Researched live (sources at bottom), not recalled:

| Tool | Owner | Does well | Does badly / gap |
|---|---|---|---|
| **Checkov** | Palo Alto | 1,000+ Terraform policies incl. ~800 **graph-based cross-resource** checks no Rego scanner reproduces; multiple releases/month; inline suppressions; SARIF | Noisy defaults on medium repos → needs suppression tuning; custom-rule authoring has a learning curve |
| **Trivy** | Aqua | One binary for IaC + containers + deps + K8s; absorbed the whole tfsec ruleset (low-FP on Terraform); inline suppressions carry over; SARIF | Non-Terraform format coverage less mature than Checkov/KICS |
| **KICS** | Checkmarx | 2,400+ queries across **22+ IaC platforms** (breadth leader) | Rego-only; less cross-resource depth than Checkov |
| **tfsec** | Aqua | Well-regarded low-FP Terraform ruleset | Frozen — folded into Trivy, no new features |
| **Terrascan** | Tenable | (was) OPA/Rego, multi-IaC | **Archived Nov 2025** — dead, degrading coverage |
| **Snyk IaC** | Snyk | Best developer-first UX: inline IDE feedback + PR commentary | Commercial |

**The consensus robustness features** a mature IaC scanner is expected to have:
broad resource/rule coverage · **cross-resource ("graph") awareness** ·
**inline suppressions** with a documented reason · **SARIF** output (GitHub
Security tab) · PR/MR annotations · severity gating · a **baseline/config
file** for accepted risk · low false-positive rate.

## Where nimbus-iac-scanner stands today

**Real strengths (keep and lean into these):**
- **"Confirm against the real control source, never guess"** doctrine — every
  `configuration.*` key and every omitted-attribute default is confirmed
  against the Evaluation Engine control's own source + the provider's docs.
  This is the same low-false-positive discipline tfsec was praised for, made
  structural. It is the single most valuable thing here — do not dilute it for
  coverage volume.
- **Cross-resource correlation already exists** (Checkov's own differentiator):
  S3 → its `aws_s3_bucket_public_access_block`, security group → standalone
  `aws_vpc_security_group_ingress_rule`, IAM principal → its policy
  attachments/inline policies. Extend this, don't lose it.
- **Same control IDs at shift-left as at runtime** — a PR check fails with the
  exact `NG-AWS-*`/`NG-AZURE-*` control a runtime scan would use. Few tools tie
  the two together this cleanly.
- PR (GitHub) + MR (GitLab) annotations, severity gating (`--min-severity`),
  three formats (Terraform / CloudFormation / Bicep).

**Real gaps (what "very robust" means here):**
1. **Coverage is narrow** — 8 Terraform + 8 CloudFormation + 2 Bicep resource
   types, vs. **96 targets** the Engine actually has controls for (61 AWS + 35
   Azure — see `engine_targets.reference.json`). This is the biggest gap by far.
2. **Azure is barely covered** — only via Bicep (2 types), and **not at all via
   Terraform `azurerm_*`** (the most common real-world Azure IaC).
3. **No inline suppressions** — no way for a developer to accept a specific
   finding on a specific resource with a documented reason.
4. **No SARIF output** — can't feed GitHub/GitLab code-scanning natively.
5. **No baseline/config file** — no repo-level accepted-risk management.
6. **No dedicated UI** — findings live only in CLI output + PR/MR comments.

## Roadmap (prioritized, each item is safe/incremental/test-verifiable)

### P1 — Coverage expansion (the bulk)
Work through `engine_targets.reference.json` (the 96 `provider:resource_type`
targets with their real `required_fields`). For each unmapped type: confirm the
config shape against the control's own source in
`../nimbusguard-evaluation-engine`, confirm each default against the provider's
current docs, add the mapper to every applicable format (Terraform `aws_*`/
`azurerm_*`, CloudFormation `AWS::*`, Bicep `Microsoft.*`), add tests
(maps-correctly + omitted-is-omitted + no-longer-in-`unmapped_resource_types`),
commit per type or small batch. Prioritize by control count (highest-value
first) and real-world commonness. **This closes gaps 1 and 2.**

### P2 — Inline suppressions
`#nimbusguard:skip=CONTROL_ID:reason` (and a bare `#nimbusguard:ignore`) on or
above a resource block, parsed per format, filtered out of the gate-check
verdict but reported as "suppressed (reason)". A suppression with no reason is
still honored but flagged. Standard, expected, unambiguous. **Closes gap 3.**

### P3 — SARIF output (`--format sarif`, additive)
The industry-standard scanner output; GitHub/GitLab code-scanning consume it.
Additive `--format {text,sarif}` (default `text`, byte-identical to today).
Each finding → a SARIF `result` with `ruleId` = control ID, `level` from
severity, and `location` = the IaC file/line when the parser can provide it.
**Closes gap 4.**

### P4 — Baseline / config file (`.nimbus-iac.yaml`)
Repo-level accepted-risk + path excludes + a `--baseline` diff mode (only fail
on findings not already in the baseline). More design surface than P1–P3 — a
first cut is a simple allow-list of `control_id`+`identifier` pairs. **Closes
gap 5.**

### P5 — UI section (DESIGN ONLY here — build is nimbus_web's)
A dedicated "IaC / Shift-Left" view. This CLI is the wrong repo to build it in;
this roadmap only proposes the backend contract + UI shape for the nimbus_web
session to build against. See `docs/ui-section-design.md`. **Addresses gap 6.**

## Non-negotiables while executing this
- Never guess a config field or a default — confirm against the control source
  and provider docs. A wrong mapper is worse than a missing one (it produces a
  false PASS/FAIL, destroying the low-FP edge).
- An unrecognized resource type is silently skipped, never fabricated.
- Omit a config key when the source attribute is genuinely absent (unless the
  provider documents a real default for the absent case — then it IS data).
- Every increment ships with tests and its own commit.

## Sources
- https://www.env0.com/blog/best-iac-scan-tool-comparing-checkov-vs-tfsec-vs-terrascan
- https://spacelift.io/blog/terraform-scanning-tools
- https://www.invicti.com/blog/web-security/iac-security-scanning-tools
- https://appsecsanta.com/iac-security-tools/terraform-security-scanning
- https://safeguard.sh/resources/blog/best-infrastructure-as-code-iac-security-scanning-tools
