from nimbus_iac_scanner.reporter import format_report, should_fail_build


def test_should_fail_build_default_matches_any_fail():
    results = [{"status": "PASS"}, {"status": "FAIL", "severity": "LOW"}]
    assert should_fail_build(results) is True


def test_should_fail_build_default_passes_when_nothing_fails():
    results = [{"status": "PASS"}, {"status": "NOT_EVALUATED"}]
    assert should_fail_build(results) is False


def test_should_fail_build_with_min_severity_ignores_a_fail_below_threshold():
    results = [{"status": "FAIL", "severity": "LOW"}]
    assert should_fail_build(results, min_severity="HIGH") is False


def test_should_fail_build_with_min_severity_catches_a_fail_at_threshold():
    results = [{"status": "FAIL", "severity": "HIGH"}]
    assert should_fail_build(results, min_severity="HIGH") is True


def test_should_fail_build_with_min_severity_catches_a_fail_above_threshold():
    results = [{"status": "FAIL", "severity": "CRITICAL"}]
    assert should_fail_build(results, min_severity="HIGH") is True


def test_should_fail_build_fails_closed_on_a_missing_severity():
    """No honest way to confirm an unclassified FAIL is below the
    threshold -- a security gate must err toward catching it."""
    results = [{"status": "FAIL", "severity": None}]
    assert should_fail_build(results, min_severity="CRITICAL") is True


def test_should_fail_build_never_triggers_on_a_non_fail_status():
    results = [{"status": "NOT_EVALUATED", "severity": "CRITICAL"}, {"status": "ERROR", "severity": "HIGH"}]
    assert should_fail_build(results) is False
    assert should_fail_build(results, min_severity="LOW") is False


def test_format_report_lists_failures_with_control_id_and_message():
    results = [{
        "identifier": "aws_s3_bucket.data", "control_id": "NG-AWS-S3-001",
        "control_name": "S3 bucket should not allow public access",
        "status": "FAIL", "severity": "CRITICAL", "message": "S3 bucket allows public access.",
    }]
    report = format_report(results, unmapped_resource_types=set())
    assert "NG-AWS-S3-001" in report
    assert "aws_s3_bucket.data" in report
    assert "S3 bucket allows public access." in report
    assert "CRITICAL" in report


def test_format_report_notes_unmapped_resource_types():
    report = format_report([], unmapped_resource_types={"aws_lambda_function"})
    assert "aws_lambda_function" in report


def test_format_report_with_no_unmapped_types_has_no_note_section():
    report = format_report([{"status": "PASS"}], unmapped_resource_types=set())
    assert "mapped to a nimbus_app control" not in report
