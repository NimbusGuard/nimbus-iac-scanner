"""Posts (or updates, never duplicates) a summary comment on a GitLab
merge request, via GitLab's real REST API -- the GitLab counterpart to
`pr_comment.py`'s own GitHub mechanism, closing the one gap that
section's own docstring named ("No GitLab MR-comment posting").

GitLab's own predefined CI variables: `CI_MERGE_REQUEST_IID` (only set
when the pipeline was genuinely triggered for a merge request -- a
branch/tag pipeline never has this), `CI_PROJECT_ID` (a numeric project
id, always available, url-safe with no encoding needed -- preferred
over `CI_PROJECT_PATH`, which would need percent-encoding), and
`CI_SERVER_URL` (the real GitLab instance base URL -- confirmed this
must be used instead of a hardcoded gitlab.com, since this repo's own
GitLab CI template (gitlab/nimbus-iac-scan.gitlab-ci.yml) is meant to
work against a self-hosted GitLab instance too, not just SaaS)."""
from typing import Optional

import requests

_MARKER = "<!-- nimbus-iac-scanner:report -->"


class MrCommentError(Exception):
    """A real GitLab API failure once a merge-request context is
    already confirmed to exist -- never raised for "no MR context
    found" (see find_merge_request_iid), and never changes the CLI's
    own exit code (posting a comment is a convenience, not part of the
    pass/fail gate), same posture as pr_comment.py's own PrCommentError."""


def find_merge_request_iid(raw_iid: Optional[str]) -> Optional[int]:
    """`raw_iid` is `CI_MERGE_REQUEST_IID`'s own raw string value (or
    `None`/empty if this isn't a merge-request-triggered pipeline at
    all -- a branch or tag pipeline never sets it). Returns `None`
    (never a guess) in that case; the caller skips commenting silently,
    not an error."""
    if not raw_iid:
        return None
    try:
        return int(raw_iid)
    except ValueError:
        return None


def _find_existing_note_id(gitlab_url: str, project_id: str, mr_iid: int, token: str) -> Optional[int]:
    resp = requests.get(
        f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes",
        headers={"PRIVATE-TOKEN": token},
        timeout=30,
    )
    if resp.status_code != 200:
        raise MrCommentError(f"Could not list existing MR notes (HTTP {resp.status_code}): {resp.text}")
    for note in resp.json():
        if _MARKER in (note.get("body") or ""):
            return note["id"]
    return None


def post_or_update_comment(gitlab_url: str, project_id: str, mr_iid: int, token: str, body: str) -> None:
    """Updates the SAME note on every re-run of the same MR (searched
    via `_MARKER`) rather than posting a new one each time -- an MR
    pushed 5 times shouldn't accumulate 5 separate scan comments, same
    convention as pr_comment.py's own GitHub mechanism.

    `token` is a GitLab Personal/Project Access Token with API scope
    (never `CI_JOB_TOKEN` by default -- confirmed its own real
    permissions to post arbitrary MR notes vary by project setting and
    aren't universally reliable, so this module always expects a real
    token to be supplied explicitly, same as this tool's own
    NIMBUS_API_KEY convention)."""
    full_body = f"{_MARKER}\n\n## NimbusGuard IaC scan\n\n{body}"
    existing_id = _find_existing_note_id(gitlab_url, project_id, mr_iid, token)

    base = f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    if existing_id is not None:
        resp = requests.put(f"{base}/{existing_id}", json={"body": full_body}, headers={"PRIVATE-TOKEN": token}, timeout=30)
    else:
        resp = requests.post(base, json={"body": full_body}, headers={"PRIVATE-TOKEN": token}, timeout=30)

    if resp.status_code not in (200, 201):
        raise MrCommentError(f"Could not post/update the MR note (HTTP {resp.status_code}): {resp.text}")
