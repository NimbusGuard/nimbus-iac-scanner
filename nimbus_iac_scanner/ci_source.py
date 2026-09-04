"""Collects the "where did this gate-check run" source metadata that
nimbus_app persists on each `IacScan`, so a human can browse the scan
history in the UI (repo/branch/PR, pass/fail, drill-down to the
controls that failed) -- see that repo's `app/routes/iac.py` /
`app/models/iac_scan.py`.

Everything here is best-effort, read from the CI provider's own
already-standard predefined variables (never a new secret, never a
network call): a run outside a recognized CI just labels itself
`ci_provider="cli"` with no repo/branch, which the server records as-is
(every field is nullable). The PR/MR number reuses the exact same
`find_pull_request_number`/`find_merge_request_iid` helpers the
comment-posting path already uses, so a scan and its PR comment always
agree on which PR they belong to.

The GitHub branch prefers `GITHUB_HEAD_REF` (the PR's own source branch)
over `GITHUB_REF_NAME` -- on a `pull_request`-triggered run the latter
is the synthetic `<n>/merge` ref, not a real branch name, so it would
read as noise in the history. Outside a PR (a push run), `GITHUB_HEAD_REF`
is unset and `GITHUB_REF_NAME` is the real branch, so the fallback is
correct there too.
"""
import os
from typing import Any, Optional

from nimbus_iac_scanner.mr_comment import find_merge_request_iid
from nimbus_iac_scanner.pr_comment import find_pull_request_number


def _github_source() -> dict[str, Optional[str]]:
    pr = find_pull_request_number(os.environ.get("GITHUB_EVENT_PATH"))
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY") or None,
        "branch": os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or None,
        "commit_sha": os.environ.get("GITHUB_SHA") or None,
        "pull_request": str(pr) if pr is not None else None,
        "ci_provider": "github",
    }


def _gitlab_source() -> dict[str, Optional[str]]:
    mr = find_merge_request_iid(os.environ.get("CI_MERGE_REQUEST_IID"))
    return {
        "repository": os.environ.get("CI_PROJECT_PATH") or None,
        "branch": os.environ.get("CI_COMMIT_REF_NAME") or None,
        "commit_sha": os.environ.get("CI_COMMIT_SHA") or None,
        "pull_request": str(mr) if mr is not None else None,
        "ci_provider": "gitlab",
    }


def collect_ci_source() -> dict[str, Any]:
    """Returns the `source` dict for the gate-check request. Always a
    dict (never None) -- a local/unrecognized run is still recorded, just
    labeled `ci_provider="cli"` with no repo/branch, so the UI history is
    honest about where each run came from. Detection is by the provider's
    own canonical marker var (`GITHUB_ACTIONS`/`GITLAB_CI`)."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return _github_source()
    if os.environ.get("GITLAB_CI") == "true":
        return _gitlab_source()
    return {
        "repository": None,
        "branch": None,
        "commit_sha": None,
        "pull_request": None,
        "ci_provider": "cli",
    }
