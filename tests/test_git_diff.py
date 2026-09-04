from unittest.mock import patch

import pytest

from nimbus_iac_scanner.git_diff import DiffError, changed_files, resolve_base_ref


def test_explicit_base_wins(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert resolve_base_ref("origin/develop") == "origin/develop"


def test_github_pr_base(monkeypatch):
    for v in ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert resolve_base_ref() == "origin/main"


def test_gitlab_base_sha_preferred(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.setenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", "abc123")
    monkeypatch.setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")
    assert resolve_base_ref() == "abc123"


def test_gitlab_target_branch_fallback(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", raising=False)
    monkeypatch.setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "develop")
    assert resolve_base_ref() == "origin/develop"


def test_default_head_1(monkeypatch):
    for v in ("GITHUB_BASE_REF", "CI_MERGE_REQUEST_DIFF_BASE_SHA", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
        monkeypatch.delenv(v, raising=False)
    assert resolve_base_ref() == "HEAD~1"


def test_changed_files_returns_absolute_paths(monkeypatch):
    for v in ("GITHUB_BASE_REF", "CI_MERGE_REQUEST_DIFF_BASE_SHA", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
        monkeypatch.delenv(v, raising=False)

    def fake_run_git(args):
        if args[0] == "rev-parse":
            return "/repo/root\n"
        if args[0] == "diff":
            return "infra/main.tf\ninfra/nested/sg.tf\n\n"
        raise AssertionError(args)

    with patch("nimbus_iac_scanner.git_diff._run_git", side_effect=fake_run_git):
        files = changed_files()
    assert files == {"/repo/root/infra/main.tf", "/repo/root/infra/nested/sg.tf"}


def test_changed_files_raises_diff_error_on_git_failure(monkeypatch):
    def fake_run_git(args):
        raise DiffError("boom")

    with patch("nimbus_iac_scanner.git_diff._run_git", side_effect=fake_run_git):
        with pytest.raises(DiffError):
            changed_files()
