"""`--changed-only` support: compute the set of IaC files changed in the
current PR/MR (or since a base ref), so a scan can restrict itself to
just the delta instead of the whole tree. This is for clients with a
large existing backlog who don't want every PR's report re-listing every
pre-existing finding in the whole repo -- only what THIS change touches.

Everything here is a thin wrapper over `git`, best-effort but never
silent: if `--changed-only` is requested and the diff genuinely can't be
computed (not a git repo, the base ref isn't fetched), a `DiffError` is
raised and the CLI turns it into exit code 2 ("the check couldn't run as
requested") rather than quietly falling back to a full scan -- a scan
that silently ignored the --changed-only request would be a surprising,
wrong result, not a friendly default.

Base ref resolution order:
  1. an explicit --diff-base value (always wins);
  2. GitHub Actions PR:  origin/$GITHUB_BASE_REF  (the PR's target branch);
  3. GitLab MR:  $CI_MERGE_REQUEST_DIFF_BASE_SHA  (the exact merge-base
     the MR diff is computed against), else
     origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME;
  4. fallback: HEAD~1 (compare against the previous commit -- reasonable
     for a plain push build).

The diff itself uses the three-dot form (`<base>...HEAD`), i.e. the
changes on HEAD since it diverged from the base -- exactly the PR delta,
not everything that happened on the base branch meanwhile. Deletions are
excluded (a deleted file has no resources left to scan).
"""
import os
import subprocess
from pathlib import Path
from typing import Optional


class DiffError(Exception):
    """`--changed-only` was requested but the changed-file set could not
    be computed (git unavailable, not a repo, base ref not found/fetched).
    The CLI surfaces this as exit code 2, never a silent full scan."""


def _run_git(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        raise DiffError("git is not installed or not on PATH") from e
    if result.returncode != 0:
        raise DiffError(f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def resolve_base_ref(explicit: Optional[str] = None) -> str:
    """The ref to diff HEAD against. See this module's own docstring for
    the resolution order. Never raises -- a bad ref surfaces later, when
    the actual `git diff` against it fails."""
    if explicit:
        return explicit
    github_base = os.environ.get("GITHUB_BASE_REF")
    if github_base:
        return f"origin/{github_base}"
    gitlab_base_sha = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if gitlab_base_sha:
        return gitlab_base_sha
    gitlab_target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    if gitlab_target:
        return f"origin/{gitlab_target}"
    return "HEAD~1"


def changed_files(explicit_base: Optional[str] = None) -> set[str]:
    """The absolute paths of files added/modified/renamed between the
    resolved base ref and HEAD. Raises DiffError if git can't compute it.
    Deleted files are excluded (nothing left to scan). Paths are resolved
    to absolutes so they can be matched against the parsers' own
    `Path(...).resolve()` file paths."""
    repo_root = Path(_run_git(["rev-parse", "--show-toplevel"]).strip())
    base = resolve_base_ref(explicit_base)
    # --diff-filter=d excludes deletions; the three-dot form is the PR delta.
    out = _run_git(["diff", "--name-only", "--diff-filter=d", f"{base}...HEAD"])
    files: set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        files.add(str((repo_root / line).resolve()))
    return files
