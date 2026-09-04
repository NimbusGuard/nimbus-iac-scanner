"""The actual CLI entrypoint -- `nimbus-iac-scan` / `python -m
nimbus_iac_scanner`. Exit codes: 0 = passed (no blocking failure), 1 =
a real misconfiguration blocked the build, 2 = the check itself
couldn't run at all (unreachable API, bad credentials, an unparseable
IaC file, a missing `bicep` CLI, etc.) -- kept distinct from 1 so a CI
pipeline can tell "your infrastructure is insecure" apart from "we
couldn't even ask."

Evaluates all 3 supported IaC formats in one pass -- Terraform
(`*.tf`), CloudFormation (`*.json`/`*.yaml`/`*.yml` that structurally
look like a template), and Bicep (`*.bicep`, compiled via the real
`bicep` CLI) -- each via its own independent parser+mapper pair (see
`terraform_parser.py`/`resource_mapping.py`,
`cloudformation_parser.py`/`cloudformation_mapping.py`,
`bicep_parser.py`/`bicep_mapping.py`), merged into one combined
gate-check call and one combined report.
"""
import argparse
import json
import os
import sys

from nimbus_iac_scanner import cloudformation_mapping, cloudformation_parser, resource_mapping, terraform_parser
from nimbus_iac_scanner.api_client import GateCheckError, run_gate_check
from nimbus_iac_scanner.ci_source import collect_ci_source
from nimbus_iac_scanner.git_diff import DiffError, changed_files as git_changed_files
from nimbus_iac_scanner.bicep_parser import BicepCliNotFoundError, BicepCompileError
from nimbus_iac_scanner import bicep_mapping, bicep_parser
from nimbus_iac_scanner.mr_comment import MrCommentError, find_merge_request_iid
from nimbus_iac_scanner.mr_comment import post_or_update_comment as post_or_update_mr_comment
from nimbus_iac_scanner.pr_comment import PrCommentError, find_pull_request_number
from nimbus_iac_scanner.pr_comment import post_or_update_comment as post_or_update_pr_comment
from nimbus_iac_scanner.reporter import format_markdown_report, format_report, should_fail_build


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimbus-iac-scan",
        description="Evaluate Terraform/CloudFormation/Bicep source against nimbus_app's real control catalog before it's ever deployed.",
    )
    parser.add_argument("--path", default=".", help="Directory to scan (default: current directory).")
    parser.add_argument(
        "--api-url", default=os.environ.get("NIMBUS_API_URL"),
        help="nimbus_app's own base API URL (or set NIMBUS_API_URL).",
    )
    parser.add_argument(
        "--api-key", default=os.environ.get("NIMBUS_API_KEY"),
        help="A nimbus_app service-account API key with view_findings (or set NIMBUS_API_KEY).",
    )
    parser.add_argument(
        "--min-severity", default=None, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        help=(
            "Only fail the build on a FAIL at or above this severity. Overrides the "
            "organization's central block policy (Organization.iac_block_severity) if that "
            "is set on the platform. When neither is set, any FAIL blocks the build."
        ),
    )
    parser.add_argument(
        "--post-pr-comment", action="store_true",
        help="Post/update a summary comment on the current GitHub pull request (GitHub Actions only).",
    )
    parser.add_argument(
        "--post-mr-comment", action="store_true",
        help="Post/update a summary note on the current GitLab merge request (GitLab CI only; needs NIMBUS_GITLAB_TOKEN).",
    )
    parser.add_argument(
        "--changed-only", action="store_true",
        help=(
            "Only evaluate IaC files changed in this PR/MR (or since --diff-base), "
            "not the whole tree -- for repos with a large existing backlog that don't "
            "want every PR's report re-listing pre-existing findings. Needs a git "
            "checkout with the base ref available (exit 2 if the diff can't be computed)."
        ),
    )
    parser.add_argument(
        "--diff-base", default=None,
        help=(
            "The base git ref to diff against for --changed-only (e.g. origin/main). "
            "Defaults to the CI's own PR/MR base, or HEAD~1 outside a PR."
        ),
    )
    return parser


def _collect_all_resources(path: str, changed_files: "set[str] | None" = None) -> tuple[list[dict], set[str]]:
    """Runs all 3 format parsers+mappers, merges their real, mapped
    resources and their real unrecognized-type sets into one combined
    pair. A Bicep-specific failure (no CLI, a real compile error) is
    NOT caught here -- it propagates up to `main`, which turns it into
    the same real, non-zero "the check itself couldn't run" exit code
    as any other unreachable-dependency failure, never silently
    dropping the Bicep half of the scan.

    `changed_files` (--changed-only): when given, each parser only reads
    files whose absolute path is in the set (see each parser's own
    `only_files` param) -- so the scan is scoped to the PR delta at parse
    time, correct for all 3 formats including Terraform (whose key drops
    the source file)."""
    mapped: list[dict] = []
    unmapped: set[str] = set()

    tf_resources = terraform_parser.parse_directory(path, only_files=changed_files)
    mapped.extend(resource_mapping.map_resources(tf_resources))
    unmapped |= resource_mapping.unmapped_resource_types(tf_resources)

    cfn_resources = cloudformation_parser.parse_directory(path, only_files=changed_files)
    mapped.extend(cloudformation_mapping.map_resources(cfn_resources))
    unmapped |= cloudformation_mapping.unmapped_resource_types(cfn_resources)

    bicep_resources = bicep_parser.parse_directory(path, only_files=changed_files)
    mapped.extend(bicep_mapping.map_resources(bicep_resources))
    unmapped |= bicep_mapping.unmapped_resource_types(bicep_resources)

    return mapped, unmapped


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.api_url or not args.api_key:
        print("error: --api-url/--api-key (or NIMBUS_API_URL/NIMBUS_API_KEY) are required", file=sys.stderr)
        return 2

    changed_files = None
    if args.changed_only:
        try:
            changed_files = git_changed_files(args.diff_base)
        except DiffError as e:
            print(f"error: --changed-only could not compute the changed files: {e}", file=sys.stderr)
            return 2
        if not changed_files:
            print("No changed files in this diff -- nothing to evaluate.")
            return 0

    try:
        mapped, unmapped = _collect_all_resources(args.path, changed_files=changed_files)
    except (BicepCliNotFoundError, BicepCompileError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not mapped:
        scope = "changed files" if args.changed_only else "--path"
        print(f"No recognized resources found to evaluate in the {scope}.")
        if unmapped:
            print(f"({len(unmapped)} unrecognized resource type(s) found)")
        return 0

    # Tell the platform HOW this scan ran, so its finding lifecycle can
    # reconcile safely: scan_path is the --path scope, is_partial is True
    # for a --changed-only run (which must never auto-resolve findings).
    source = collect_ci_source()
    source["scan_path"] = args.path
    source["is_partial"] = bool(args.changed_only)

    try:
        result = run_gate_check(args.api_url, args.api_key, mapped, source=source)
    except GateCheckError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Plain text for the terminal / CI log; markdown (a rendered table) for
    # the PR/MR comment -- a code-host comment renders markdown, a terminal
    # doesn't.
    report = format_report(result.results, unmapped)
    print(report)
    if result.scan_ids:
        # A link back to the persisted run(s) in the NimbusGuard UI --
        # one line, informational, never affects the exit code.
        print(f"\nRecorded in NimbusGuard: scan {', '.join(result.scan_ids)}", file=sys.stderr)

    if args.post_pr_comment or args.post_mr_comment:
        # identifier -> (file, line), so the comment can link each finding back
        # to its exact declaration in the repo (the response echoes the same
        # identifier we sent each resource under).
        source_by_identifier = {
            r["identifier"]: {"file": r.get("source_file"), "line": r.get("source_line")}
            for r in mapped if r.get("identifier")
        }
        markdown_report = format_markdown_report(
            result.results, unmapped, source_by_identifier, _blob_base_url(),
        )
        if args.post_pr_comment:
            _try_post_pr_comment(markdown_report)
        if args.post_mr_comment:
            _try_post_mr_comment(markdown_report)

    # Precedence: an explicit --min-severity flag (local intent) always
    # wins; otherwise the org's central block policy from the platform
    # (Organization.iac_block_severity, returned by the gate-check);
    # otherwise any FAIL blocks. So the block threshold can live centrally
    # on NimbusGuard without every pipeline hardcoding it.
    effective_min_severity = args.min_severity or result.block_severity
    if args.min_severity is None and result.block_severity:
        print(f"note: using the organization's central block policy (min severity: {result.block_severity})", file=sys.stderr)
    fail = should_fail_build(result.results, effective_min_severity)
    return 1 if fail else 0


def _try_post_pr_comment(report: str) -> None:
    """A PR-comment failure is logged, never fatal -- it must never
    change the CLI's own exit code (see this module's own docstring)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    pr_number = find_pull_request_number(os.environ.get("GITHUB_EVENT_PATH"))

    if pr_number is None:
        print("note: --post-pr-comment given, but this doesn't look like a pull_request-triggered run -- skipping.", file=sys.stderr)
        return
    if not repo or not token:
        print("note: --post-pr-comment given, but GITHUB_REPOSITORY/GITHUB_TOKEN aren't set -- skipping.", file=sys.stderr)
        return

    try:
        post_or_update_pr_comment(repo, pr_number, token, report)
    except PrCommentError as e:
        print(f"warning: could not post the PR comment: {e}", file=sys.stderr)


def _try_post_mr_comment(report: str) -> None:
    """Same "never fatal" posture as _try_post_pr_comment. `NIMBUS_GITLAB_TOKEN`
    is deliberately its own, dedicated env var (never GitLab's own
    predefined `CI_JOB_TOKEN`) -- confirmed that token's own permission
    to post arbitrary MR notes isn't universally reliable across every
    real project configuration, so this always expects a real GitLab
    Personal/Project Access Token supplied explicitly, same
    "credential supplied explicitly, never assumed" posture
    NIMBUS_API_KEY itself already has."""
    gitlab_url = os.environ.get("CI_SERVER_URL")
    project_id = os.environ.get("CI_PROJECT_ID")
    token = os.environ.get("NIMBUS_GITLAB_TOKEN")
    mr_iid = find_merge_request_iid(os.environ.get("CI_MERGE_REQUEST_IID"))

    if mr_iid is None:
        print("note: --post-mr-comment given, but this doesn't look like a merge-request-triggered pipeline -- skipping.", file=sys.stderr)
        return
    if not gitlab_url or not project_id or not token:
        print("note: --post-mr-comment given, but CI_SERVER_URL/CI_PROJECT_ID/NIMBUS_GITLAB_TOKEN aren't all set -- skipping.", file=sys.stderr)
        return

    try:
        post_or_update_mr_comment(gitlab_url, project_id, mr_iid, token, report)
    except MrCommentError as e:
        print(f"warning: could not post the MR comment: {e}", file=sys.stderr)


def _github_pr_head_sha() -> "str | None":
    """The PR's own head commit SHA from the GitHub Actions event payload --
    a precise, stable blob ref for the file links (GITHUB_SHA on a
    pull_request event is the temporary merge commit, which links less
    cleanly). `None` outside a PR run."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            event = json.load(f)
    except (OSError, ValueError):
        return None
    pr = event.get("pull_request")
    head = pr.get("head") if isinstance(pr, dict) else None
    sha = head.get("sha") if isinstance(head, dict) else None
    return sha if isinstance(sha, str) else None


def _blob_base_url() -> "str | None":
    """`https://.../blob/<ref>` for the current repo, used to link a finding
    to its source file:line in the PR/MR comment. `None` when not running in a
    recognized CI (a local run -- no repo to link into)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if repo:
        ref = (
            _github_pr_head_sha()
            or os.environ.get("GITHUB_SHA")
            or os.environ.get("GITHUB_HEAD_REF")
            or os.environ.get("GITHUB_REF_NAME")
        )
        return f"https://github.com/{repo}/blob/{ref}" if ref else None
    server = os.environ.get("CI_SERVER_URL")
    project = os.environ.get("CI_PROJECT_PATH")
    ref = os.environ.get("CI_COMMIT_SHA") or os.environ.get("CI_COMMIT_REF_NAME")
    if server and project and ref:
        return f"{server.rstrip('/')}/{project}/-/blob/{ref}"
    return None


if __name__ == "__main__":
    sys.exit(main())
