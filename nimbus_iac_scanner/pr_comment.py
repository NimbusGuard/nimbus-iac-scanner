"""Posts (or updates, never duplicates) a PR comment with the gate-
check report, via the real GitHub REST API. GitLab's own MR-comment
API is a real, disclosed follow-up -- not built this pass (the GitLab
CI template runs the check and fails the pipeline on a real
misconfiguration, which already satisfies this ficha's own "listo
cuando" criterion; only the PR-comment convenience is GitHub-only for
now)."""
from typing import Optional

import requests

_MARKER = "<!-- nimbus-iac-scanner:report -->"
_API_BASE = "https://api.github.com"


class PrCommentError(Exception):
    """Never raised for "no PR context found" (see find_pull_request_number)
    -- only for a real GitHub API failure once we've confirmed there IS
    a PR to comment on. A PR-comment failure never changes the CLI's
    own exit code (see cli.py) -- posting a comment is a convenience,
    not part of the pass/fail gate itself."""


def find_pull_request_number(event_path: Optional[str]) -> Optional[int]:
    """Reads the real GitHub Actions event payload
    (`GITHUB_EVENT_PATH`) for `pull_request.number` -- returns `None`
    (never a guess) when this isn't a pull_request-triggered run (e.g.
    a push to main, a manual dispatch, or running outside GitHub
    Actions entirely) -- the caller skips commenting silently in that
    case, not an error."""
    if not event_path:
        return None
    import json
    try:
        with open(event_path, encoding="utf-8") as f:
            event = json.load(f)
    except (OSError, ValueError):
        return None
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        return None
    number = pr.get("number")
    return number if isinstance(number, int) else None


def _find_existing_comment_id(repo: str, pr_number: int, token: str) -> Optional[int]:
    resp = requests.get(
        f"{_API_BASE}/repos/{repo}/issues/{pr_number}/comments",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise PrCommentError(f"Could not list existing PR comments (HTTP {resp.status_code}): {resp.text}")
    for comment in resp.json():
        if _MARKER in (comment.get("body") or ""):
            return comment["id"]
    return None


def post_or_update_comment(repo: str, pr_number: int, token: str, body: str) -> None:
    """`repo` is `owner/name` (GITHUB_REPOSITORY's own format). Updates
    the SAME comment on every re-run of the same PR (searched via
    `_MARKER`) rather than posting a new one each time -- a PR pushed 5
    times shouldn't accumulate 5 separate scan comments."""
    full_body = f"{_MARKER}\n\n## NimbusGuard IaC scan\n\n{body}"
    existing_id = _find_existing_comment_id(repo, pr_number, token)

    if existing_id is not None:
        resp = requests.patch(
            f"{_API_BASE}/repos/{repo}/issues/comments/{existing_id}",
            json={"body": full_body},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=30,
        )
    else:
        resp = requests.post(
            f"{_API_BASE}/repos/{repo}/issues/{pr_number}/comments",
            json={"body": full_body},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=30,
        )

    if resp.status_code not in (200, 201):
        raise PrCommentError(f"Could not post/update the PR comment (HTTP {resp.status_code}): {resp.text}")
