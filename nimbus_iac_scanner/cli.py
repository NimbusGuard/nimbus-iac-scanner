"""The actual CLI entrypoint -- `nimbus-iac-scan` / `python -m
nimbus_iac_scanner`. Exit codes: 0 = passed (no blocking failure), 1 =
a real misconfiguration blocked the build, 2 = the check itself
couldn't run at all (unreachable API, bad credentials, etc.) -- kept
distinct from 1 so a CI pipeline can tell "your infrastructure is
insecure" apart from "we couldn't even ask."
"""
import argparse
import os
import sys

from nimbus_iac_scanner.api_client import GateCheckError, run_gate_check
from nimbus_iac_scanner.pr_comment import PrCommentError, find_pull_request_number, post_or_update_comment
from nimbus_iac_scanner.reporter import format_report, should_fail_build
from nimbus_iac_scanner.resource_mapping import map_resources, unmapped_resource_types
from nimbus_iac_scanner.terraform_parser import parse_directory


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nimbus-iac-scan",
        description="Evaluate Terraform source against nimbus_app's real control catalog before it's ever deployed.",
    )
    parser.add_argument("--path", default=".", help="Directory to scan for *.tf files (default: current directory).")
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
        help="Only fail the build on a FAIL at or above this severity (default: any FAIL blocks the build).",
    )
    parser.add_argument(
        "--post-pr-comment", action="store_true",
        help="Post/update a summary comment on the current GitHub pull request (GitHub Actions only).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.api_url or not args.api_key:
        print("error: --api-url/--api-key (or NIMBUS_API_URL/NIMBUS_API_KEY) are required", file=sys.stderr)
        return 2

    all_resources = parse_directory(args.path)
    mapped = map_resources(all_resources)
    unmapped = unmapped_resource_types(all_resources)

    if not mapped:
        print("No recognized resources found to evaluate.")
        if unmapped:
            print(f"({len(unmapped)} unrecognized resource type(s) found -- see --path's own resources)")
        return 0

    try:
        result = run_gate_check(args.api_url, args.api_key, mapped)
    except GateCheckError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    report = format_report(result.results, unmapped)
    print(report)

    if args.post_pr_comment:
        _try_post_pr_comment(report)

    fail = should_fail_build(result.results, args.min_severity)
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
        post_or_update_comment(repo, pr_number, token, report)
    except PrCommentError as e:
        print(f"warning: could not post the PR comment: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
