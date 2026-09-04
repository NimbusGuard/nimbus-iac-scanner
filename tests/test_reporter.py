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


# --- format_markdown_report (the PR/MR comment body) ---
from nimbus_iac_scanner.reporter import format_markdown_report


def _fail(identifier, control_id, severity, message, control_name="rule"):
    return {"status": "FAIL", "identifier": identifier, "control_id": control_id,
            "severity": severity, "message": message, "control_name": control_name}


def test_markdown_passing_has_a_check_and_no_table():
    md = format_markdown_report([{"status": "PASS"}], set())
    assert "✅" in md and "Passed" in md
    assert "| Severity |" not in md  # no findings table when nothing fails


def test_markdown_failing_has_summary_counts_and_a_worst_first_table():
    results = [
        _fail("aws_s3_bucket.a", "NG-AWS-S3-001", "CRITICAL", "S3 bucket allows public access"),
        _fail("aws_kms_key.k", "NG-AWS-KMS-001", "LOW", "rotation disabled"),
        _fail("aws_security_group.sg", "NG-AWS-EC2-001", "HIGH", "SSH open"),
        {"status": "PASS"},
    ]
    md = format_markdown_report(results, set())
    # blocking summary with the real failing count (3), passes excluded
    assert "Blocking — 3 findings" in md
    # a severity-count table with badges
    assert "🔴 Critical" in md and "🟠 High" in md and "🔵 Low" in md
    # a real findings table, collapsible, with code-formatted resource + control
    assert "| Severity | Resource | Control | Issue |" in md
    assert "`aws_s3_bucket.a`" in md and "`NG-AWS-S3-001`" in md
    assert "<details" in md and "</details>" in md
    # worst-first: CRITICAL row appears before the HIGH row, which precedes LOW
    assert md.index("NG-AWS-S3-001") < md.index("NG-AWS-EC2-001") < md.index("NG-AWS-KMS-001")


def test_markdown_escapes_pipes_in_cells():
    md = format_markdown_report([_fail("res|x", "NG-A|B", "MEDIUM", "a | b message")], set())
    # a literal pipe inside a cell is escaped so it can't start a new column
    assert "res\\|x" in md and "a \\| b message" in md


def test_markdown_notes_unmapped_types():
    md = format_markdown_report([_fail("r", "C", "LOW", "m")], {"aws_foo", "azurerm_bar"})
    assert "2 resource type(s) aren't mapped" in md


def test_markdown_findings_are_collapsed_by_default():
    md = format_markdown_report([_fail("r", "C", "LOW", "m")], set())
    assert "<details>" in md and "<details open>" not in md


def test_markdown_links_resource_to_source_when_known():
    src = {"aws_s3_bucket.a": {"file": "terraform/aws.tf", "line": 13}}
    md = format_markdown_report(
        [_fail("aws_s3_bucket.a", "NG-AWS-S3-001", "CRITICAL", "public")],
        set(), src, "https://github.com/o/r/blob/sha",
    )
    assert "[`aws_s3_bucket.a`](https://github.com/o/r/blob/sha/terraform/aws.tf#L13)" in md


def test_markdown_no_link_without_blob_base_or_absolute_path():
    src = {"r": {"file": "/abs/path.tf", "line": 3}}
    # absolute path -> no link (only repo-root-relative paths link correctly)
    md = format_markdown_report([_fail("r", "C", "LOW", "m")], set(), src, "https://github.com/o/r/blob/sha")
    assert "https://github.com/o/r/blob/sha" not in md
    # no blob base (local run) -> plain code, no link
    md2 = format_markdown_report([_fail("r", "C", "LOW", "m")], set(), {"r": {"file": "a.tf", "line": 1}}, None)
    assert "](http" not in md2
