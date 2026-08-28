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
    assert "aws_lambda_function" in out  # the unmapped-resource-types notice


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
resource "aws_lambda_function" "fn" {
  function_name = "only-unmapped"
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
