import json

from nimbus_iac_scanner.ci_source import collect_ci_source

# Every CI predefined variable this module reads, so a test can clear the
# whole set with monkeypatch.delenv before setting only what it means to.
_ALL_CI_VARS = [
    "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_HEAD_REF", "GITHUB_REF_NAME",
    "GITHUB_SHA", "GITHUB_EVENT_PATH",
    "GITLAB_CI", "CI_PROJECT_PATH", "CI_COMMIT_REF_NAME", "CI_COMMIT_SHA",
    "CI_MERGE_REQUEST_IID",
]


def _clear_ci_env(monkeypatch):
    for var in _ALL_CI_VARS:
        monkeypatch.delenv(var, raising=False)


def test_outside_ci_labels_itself_cli(monkeypatch):
    _clear_ci_env(monkeypatch)
    source = collect_ci_source()
    assert source["ci_provider"] == "cli"
    assert source["repository"] is None
    assert source["branch"] is None
    assert source["commit_sha"] is None
    assert source["pull_request"] is None


def test_github_push_run(monkeypatch):
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "abc1234")
    source = collect_ci_source()
    assert source == {
        "repository": "acme/infra",
        "branch": "main",
        "commit_sha": "abc1234",
        "pull_request": None,
        "ci_provider": "github",
    }


def test_github_pr_run_prefers_head_ref_and_reads_pr_number(monkeypatch, tmp_path):
    _clear_ci_env(monkeypatch)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 42}}))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    # On a pull_request run GITHUB_REF_NAME is the synthetic "<n>/merge"
    # ref; GITHUB_HEAD_REF is the real source branch and must win.
    monkeypatch.setenv("GITHUB_REF_NAME", "42/merge")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/x")
    monkeypatch.setenv("GITHUB_SHA", "def5678")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    source = collect_ci_source()
    assert source["branch"] == "feature/x"
    assert source["pull_request"] == "42"
    assert source["ci_provider"] == "github"


def test_gitlab_mr_run(monkeypatch):
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_PROJECT_PATH", "group/project")
    monkeypatch.setenv("CI_COMMIT_REF_NAME", "feature/y")
    monkeypatch.setenv("CI_COMMIT_SHA", "999aaa")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    source = collect_ci_source()
    assert source == {
        "repository": "group/project",
        "branch": "feature/y",
        "commit_sha": "999aaa",
        "pull_request": "7",
        "ci_provider": "gitlab",
    }


def test_gitlab_branch_pipeline_has_no_mr(monkeypatch):
    _clear_ci_env(monkeypatch)
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI_PROJECT_PATH", "group/project")
    monkeypatch.setenv("CI_COMMIT_REF_NAME", "main")
    monkeypatch.setenv("CI_COMMIT_SHA", "111bbb")
    source = collect_ci_source()
    assert source["pull_request"] is None
    assert source["ci_provider"] == "gitlab"
