"""Inline (# nimbus:ignore) + .nimbusignore directive parsing/resolution."""
from nimbus_iac_scanner.ignore_directives import (
    parse_inline_ignores,
    parse_nimbusignore_lines,
    resolve_directives,
)


# --------------------------- inline comments -------------------------


def test_inline_above_the_resource_maps_to_it():
    text = (
        "# nimbus:ignore NG-AWS-S3-001 reason=false_positive note=\"legacy bucket\"\n"
        'resource "aws_s3_bucket" "data" {\n'
        "}\n"
    )
    decls = [(2, "aws_s3_bucket.data")]
    ds = parse_inline_ignores(text, decls)
    assert len(ds) == 1
    d = ds[0]
    assert d.control_id == "NG-AWS-S3-001" and d.identifier == "aws_s3_bucket.data"
    assert d.source == "inline" and d.reason_type == "false_positive" and d.note == "legacy bucket"


def test_inline_on_the_declaration_line_maps_to_it():
    text = 'resource "aws_s3_bucket" "data" {  # nimbus:ignore NG-AWS-S3-001\n}\n'
    ds = parse_inline_ignores(text, [(1, "aws_s3_bucket.data")])
    assert len(ds) == 1 and ds[0].identifier == "aws_s3_bucket.data"


def test_inline_wildcard_control():
    text = "# nimbus:ignore *\nresource \"aws_s3_bucket\" \"data\" {\n}\n"
    ds = parse_inline_ignores(text, [(2, "aws_s3_bucket.data")])
    assert ds[0].control_id == "*"


def test_inline_with_blank_gap_still_maps():
    text = (
        "# nimbus:ignore NG-AWS-S3-001\n"
        "\n"
        "# just a note\n"
        'resource "aws_s3_bucket" "data" {\n}\n'
    )
    ds = parse_inline_ignores(text, [(4, "aws_s3_bucket.data")])
    assert len(ds) == 1 and ds[0].identifier == "aws_s3_bucket.data"


def test_inline_too_far_above_does_not_map():
    text = "# nimbus:ignore NG-AWS-S3-001\n" + "code\n" * 10 + 'resource "aws_s3_bucket" "data" {\n}\n'
    ds = parse_inline_ignores(text, [(12, "aws_s3_bucket.data")])
    assert ds == []  # a stray directive is not force-attached


def test_inline_expires_converts_to_end_of_day_iso():
    text = "# nimbus:ignore NG-AWS-S3-001 reason=risk_accepted expires=2026-12-31\nresource \"aws_s3_bucket\" \"data\" {\n}\n"
    d = parse_inline_ignores(text, [(2, "aws_s3_bucket.data")])[0]
    assert d.reason_type == "risk_accepted"
    assert d.expires_at.startswith("2026-12-31T23:59:59")


# --------------------------- .nimbusignore ---------------------------


def test_nimbusignore_grammar_and_comments():
    text = (
        "# this is a comment\n"
        "\n"
        "NG-AWS-S3-001 aws_s3_bucket.legacy_* reason=risk_accepted expires=2026-12-31 note=\"migrating Q4\"\n"
    )
    ds = parse_nimbusignore_lines(text)
    assert len(ds) == 1
    d = ds[0]
    assert d.control_id == "NG-AWS-S3-001" and d.identifier == "aws_s3_bucket.legacy_*"
    assert d.source == "nimbusignore" and d.reason_type == "risk_accepted" and d.note == "migrating Q4"


def test_nimbusignore_line_needs_control_and_glob():
    ds = parse_nimbusignore_lines("NG-AWS-S3-001\n")  # missing the identifier glob
    assert ds == []


# --------------------------- resolve_directives ----------------------


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


def test_resolve_inline_from_real_file(tmp_path):
    tf = _write(tmp_path, "main.tf", "# nimbus:ignore NG-AWS-S3-001\nresource \"aws_s3_bucket\" \"data\" {\n}\n")
    mapped = [{"identifier": "aws_s3_bucket.data", "source_file": tf, "source_line": 2}]
    payloads = resolve_directives(str(tmp_path), mapped)
    assert payloads == [{"control_id": "NG-AWS-S3-001", "source": "inline", "identifier": "aws_s3_bucket.data"}]


def test_no_inline_ignores_flag_disables_inline_but_keeps_nimbusignore(tmp_path):
    tf = _write(tmp_path, "main.tf", "# nimbus:ignore NG-AWS-S3-001\nresource \"aws_s3_bucket\" \"data\" {\n}\n")
    _write(tmp_path, ".nimbusignore", "NG-AWS-EC2-001 aws_security_group.*\n")
    mapped = [{"identifier": "aws_s3_bucket.data", "source_file": tf, "source_line": 2}]
    payloads = resolve_directives(str(tmp_path), mapped, inline_enabled=False)
    # inline dropped; the .nimbusignore glob directive survives
    assert payloads == [{"control_id": "NG-AWS-EC2-001", "source": "nimbusignore", "identifier": "aws_security_group.*"}]


def test_nimbusignore_glob_directive_sent_as_is(tmp_path):
    _write(tmp_path, ".nimbusignore", "NG-AWS-S3-001 aws_s3_bucket.*\n")
    payloads = resolve_directives(str(tmp_path), [{"identifier": "aws_s3_bucket.data", "source_file": "main.tf", "source_line": 1}])
    assert payloads == [{"control_id": "NG-AWS-S3-001", "source": "nimbusignore", "identifier": "aws_s3_bucket.*"}]


def test_nimbusignore_file_filter_resolves_to_exact_addresses(tmp_path):
    _write(tmp_path, ".nimbusignore", "NG-AWS-S3-001 aws_s3_bucket.* file=terraform/legacy.tf\n")
    mapped = [
        {"identifier": "aws_s3_bucket.a", "source_file": "terraform/legacy.tf", "source_line": 1},
        {"identifier": "aws_s3_bucket.b", "source_file": "terraform/new.tf", "source_line": 1},  # different file, excluded
    ]
    payloads = resolve_directives(str(tmp_path), mapped)
    assert payloads == [{"control_id": "NG-AWS-S3-001", "source": "nimbusignore", "identifier": "aws_s3_bucket.a"}]
