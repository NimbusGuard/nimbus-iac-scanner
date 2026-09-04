import os
from unittest.mock import patch

from nimbus_iac_scanner.api_client import GateCheckResult
from nimbus_iac_scanner.cli import main

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "mixed_project")


def test_missing_api_url_or_key_exits_2(capsys):
    exit_code = main(["--path", FIXTURE_DIR])
    assert exit_code == 2
    assert "required" in capsys.readouterr().err


def test_a_real_fail_result_exits_1_and_prints_the_control_id(capsys):
    fake_result = GateCheckResult(
        passed=False,
        results=[{
            "identifier": "aws_s3_bucket.insecure", "resource_type": "s3_bucket",
            "control_id": "NG-AWS-S3-001", "control_name": "S3 bucket should not allow public access",
            "status": "FAIL", "severity": "CRITICAL", "message": "S3 bucket allows public access.",
        }],
    )
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main(["--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "NG-AWS-S3-001" in out
    assert "aws_lambda_layer_version" in out  # the unmapped-resource-types notice


def test_a_clean_pass_exits_0(capsys):
    fake_result = GateCheckResult(passed=True, results=[{"identifier": "x", "status": "PASS"}])
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main(["--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0


def test_min_severity_downgrades_a_low_fail_to_a_passing_exit_code():
    fake_result = GateCheckResult(
        passed=False,
        results=[{"identifier": "x", "status": "FAIL", "severity": "LOW"}],
    )
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main([
            "--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k",
            "--min-severity", "HIGH",
        ])
    assert exit_code == 0


def test_gate_check_error_exits_2(capsys):
    from nimbus_iac_scanner.api_client import GateCheckError
    with patch("nimbus_iac_scanner.cli.run_gate_check", side_effect=GateCheckError("unreachable")):
        exit_code = main(["--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 2
    assert "unreachable" in capsys.readouterr().err


def test_no_mapped_resources_exits_0_without_calling_the_api(tmp_path):
    (tmp_path / "unmapped.tf").write_text('''
resource "aws_lambda_layer_version" "lyr" {
  layer_name = "only-unmapped"
}
''')
    with patch("nimbus_iac_scanner.cli.run_gate_check") as mock_gate_check:
        exit_code = main(["--path", str(tmp_path), "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0
    mock_gate_check.assert_not_called()


def test_post_pr_comment_failure_never_changes_the_exit_code(monkeypatch):
    """A PR-comment failure is a convenience failure, never a gate
    failure -- confirmed directly, not just documented."""
    fake_result = GateCheckResult(passed=True, results=[])
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/infra")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)  # no PR context -> skip, not error
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main([
            "--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k",
            "--post-pr-comment",
        ])
    assert exit_code == 0


def test_collects_and_merges_resources_across_all_3_formats(tmp_path):
    (tmp_path / "main.tf").write_text('''
resource "aws_security_group" "tf_sg" {
  name = "tf-sg"
}
''')
    (tmp_path / "template.json").write_text(
        '{"Resources": {"CfnBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}'
    )
    fake_result = GateCheckResult(passed=True, results=[])
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result) as mock_run:
        exit_code = main(["--path", str(tmp_path), "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0
    sent_resources = mock_run.call_args.args[2]
    identifiers = {r["identifier"] for r in sent_resources}
    assert identifiers == {"aws_security_group.tf_sg", "AWS::S3::Bucket.CfnBucket"}


def test_a_bicep_cli_not_found_error_exits_2_and_is_never_silently_swallowed(tmp_path, monkeypatch):
    (tmp_path / "main.bicep").write_text("resource sa 'X' = {}")
    monkeypatch.setattr("nimbus_iac_scanner.bicep_parser.is_bicep_cli_available", lambda: False)
    with patch("nimbus_iac_scanner.cli.run_gate_check") as mock_run:
        exit_code = main(["--path", str(tmp_path), "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 2
    mock_run.assert_not_called()


def test_post_mr_comment_with_no_merge_request_context_never_changes_the_exit_code(monkeypatch):
    fake_result = GateCheckResult(passed=True, results=[])
    monkeypatch.delenv("CI_MERGE_REQUEST_IID", raising=False)
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main([
            "--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k",
            "--post-mr-comment",
        ])
    assert exit_code == 0


def test_post_mr_comment_posts_when_a_real_merge_request_context_exists(monkeypatch):
    fake_result = GateCheckResult(passed=True, results=[])
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "9")
    monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.example.com")
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("NIMBUS_GITLAB_TOKEN", "tok")
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result), \
         patch("nimbus_iac_scanner.cli.post_or_update_mr_comment") as mock_post:
        exit_code = main([
            "--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k",
            "--post-mr-comment",
        ])
    assert exit_code == 0
    mock_post.assert_called_once()
    assert mock_post.call_args.args[0] == "https://gitlab.example.com"
    assert mock_post.call_args.args[2] == 9


def test_org_block_policy_is_used_when_no_min_severity_flag(capsys):
    # org policy HIGH; a LOW fail should NOT block (exit 0)
    fake_result = GateCheckResult(
        passed=False,
        results=[{"identifier": "x", "status": "FAIL", "severity": "LOW"}],
        block_severity="HIGH",
    )
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main(["--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0


def test_explicit_min_severity_flag_overrides_org_block_policy(capsys):
    # org policy HIGH, but the flag says CRITICAL -> a HIGH fail must NOT block
    fake_result = GateCheckResult(
        passed=False,
        results=[{"identifier": "x", "status": "FAIL", "severity": "HIGH"}],
        block_severity="HIGH",
    )
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main([
            "--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k",
            "--min-severity", "CRITICAL",
        ])
    assert exit_code == 0


def test_org_block_policy_blocks_a_fail_at_the_threshold(capsys):
    fake_result = GateCheckResult(
        passed=False,
        results=[{"identifier": "x", "status": "FAIL", "severity": "HIGH"}],
        block_severity="HIGH",
    )
    with patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result):
        exit_code = main(["--path", FIXTURE_DIR, "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 1


def test_changed_only_scans_only_changed_files(tmp_path):
    (tmp_path / "changed.tf").write_text('resource "aws_security_group" "kept" { name = "k" }\n')
    (tmp_path / "unchanged.tf").write_text('resource "aws_security_group" "dropped" { name = "d" }\n')
    changed = {str((tmp_path / "changed.tf").resolve())}

    fake_result = GateCheckResult(passed=True, results=[])
    with patch("nimbus_iac_scanner.cli.git_changed_files", return_value=changed), \
         patch("nimbus_iac_scanner.cli.run_gate_check", return_value=fake_result) as mock_run:
        exit_code = main(["--path", str(tmp_path), "--changed-only", "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0
    sent = mock_run.call_args.args[2]
    identifiers = {r["identifier"] for r in sent}
    assert identifiers == {"aws_security_group.kept"}  # unchanged.tf's resource is never parsed


def test_changed_only_diff_error_exits_2(tmp_path, capsys):
    from nimbus_iac_scanner.git_diff import DiffError
    with patch("nimbus_iac_scanner.cli.git_changed_files", side_effect=DiffError("no base ref")):
        exit_code = main(["--path", str(tmp_path), "--changed-only", "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 2
    assert "changed-only" in capsys.readouterr().err


def test_changed_only_empty_diff_exits_0_without_calling_the_api(tmp_path):
    with patch("nimbus_iac_scanner.cli.git_changed_files", return_value=set()), \
         patch("nimbus_iac_scanner.cli.run_gate_check") as mock_run:
        exit_code = main(["--path", str(tmp_path), "--changed-only", "--api-url", "https://api.example.com", "--api-key", "k"])
    assert exit_code == 0
    mock_run.assert_not_called()
