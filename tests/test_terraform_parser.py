from nimbus_iac_scanner.terraform_parser import (
    parse_directory,
    parse_source,
    parse_variable_defaults,
    resolve_reference,
    resolve_variable_references,
)


def test_parses_a_single_resource_block():
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
''')
    assert ("aws_s3_bucket", "data") in resources
    assert resources[("aws_s3_bucket", "data")]["bucket"] == "my-bucket"


def test_parses_multiple_resources_of_different_types():
    resources = parse_source('''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

resource "aws_security_group" "web" {
  name = "web-sg"
}
''')
    assert set(resources) == {("aws_s3_bucket", "data"), ("aws_security_group", "web")}


def test_resolve_reference_handles_dollar_brace_wrapped_expression():
    assert resolve_reference("${aws_s3_bucket.data.id}") == ("aws_s3_bucket", "data", "id")


def test_resolve_reference_handles_bare_expression_without_dollar_brace():
    assert resolve_reference("aws_s3_bucket.data.id") == ("aws_s3_bucket", "data", "id")


def test_resolve_reference_returns_none_for_a_literal_string():
    assert resolve_reference("my-literal-bucket-name") is None


def test_resolve_reference_returns_none_for_a_variable_reference():
    assert resolve_reference("${var.bucket_name}") is None


def test_resolve_reference_returns_none_for_a_non_string_value():
    assert resolve_reference(False) is None
    assert resolve_reference(42) is None
    assert resolve_reference(None) is None


def test_parse_directory_merges_every_tf_file(tmp_path):
    (tmp_path / "buckets.tf").write_text('''
resource "aws_s3_bucket" "a" {
  bucket = "bucket-a"
}
''')
    (tmp_path / "sgs.tf").write_text('''
resource "aws_security_group" "b" {
  name = "sg-b"
}
''')
    resources = parse_directory(str(tmp_path))
    assert set(resources) == {("aws_s3_bucket", "a"), ("aws_security_group", "b")}


def test_parse_directory_recurses_into_subdirectories(tmp_path):
    nested = tmp_path / "modules" / "network"
    nested.mkdir(parents=True)
    (nested / "sg.tf").write_text('''
resource "aws_security_group" "nested" {
  name = "nested-sg"
}
''')
    resources = parse_directory(str(tmp_path))
    assert ("aws_security_group", "nested") in resources


def test_parse_directory_only_files_restricts_to_the_given_files(tmp_path):
    from nimbus_iac_scanner import terraform_parser
    (tmp_path / "a.tf").write_text('resource "aws_s3_bucket" "a" {}\n')
    (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    only = {str((tmp_path / "a.tf").resolve())}
    resources = terraform_parser.parse_directory(str(tmp_path), only_files=only)
    assert set(resources.keys()) == {("aws_s3_bucket", "a")}  # b.tf skipped


# --------------------------------------------------------------------------
# Variable resolution -- a real gap found live 2026-09-29: a tag value like
# `Name = "${var.prefix}-suffix"` used to reach nimbus_app completely
# unresolved, silently defeating Ownership Resolution Phase 2's own
# tag-based correlation (a declared tag that could never match the real,
# already-deployed resource's own resolved tag value).
# --------------------------------------------------------------------------

def test_parse_variable_defaults_reads_a_real_default():
    defaults = parse_variable_defaults('''
variable "prefix" {
  default = "nbg-toxic-combo"
}
''')
    assert defaults == {"prefix": "nbg-toxic-combo"}


def test_parse_variable_defaults_omits_a_variable_with_no_default():
    defaults = parse_variable_defaults('''
variable "region" {
  type = string
}
''')
    assert defaults == {}


def test_resolve_variable_references_substitutes_interpolated_string():
    result = resolve_variable_references("${var.prefix}-cwpp-fixtures", {"prefix": "nbg-toxic-combo"})
    assert result == "nbg-toxic-combo-cwpp-fixtures"


def test_resolve_variable_references_substitutes_the_bare_shorthand():
    # python-hcl2 normalizes `Name = var.prefix` (no braces) to the exact
    # same "${var.prefix}" string as the interpolated form -- confirmed by
    # direct introspection, not assumed -- so one substitution path covers
    # both real Terraform syntaxes.
    result = resolve_variable_references("${var.prefix}", {"prefix": "nbg-toxic-combo"})
    assert result == "nbg-toxic-combo"


def test_resolve_variable_references_leaves_an_unknown_variable_untouched():
    result = resolve_variable_references("${var.undeclared}-x", {"prefix": "nbg-toxic-combo"})
    assert result == "${var.undeclared}-x"  # never guessed


def test_resolve_variable_references_leaves_a_non_scalar_default_untouched():
    result = resolve_variable_references("${var.tags_map}-x", {"tags_map": {"a": "b"}})
    assert result == "${var.tags_map}-x"  # no honest string representation to splice in


def test_resolve_variable_references_recurses_into_nested_dicts_and_lists():
    body = {"tags": {"Name": "${var.prefix}-fixtures"}, "vpc_security_group_ids": ["${var.sg_id}"]}
    resolved = resolve_variable_references(body, {"prefix": "nbg", "sg_id": "sg-123"})
    assert resolved == {"tags": {"Name": "nbg-fixtures"}, "vpc_security_group_ids": ["sg-123"]}


def test_parse_directory_resolves_a_variable_declared_in_a_different_file(tmp_path):
    # Deliberately named so plain alphabetical iteration would visit the
    # resource file BEFORE the variable file -- the exact real-world
    # ordering (e.g. "100-fixtures.tf" before "variables.tf") that made
    # this bug possible in the first place; parse_directory's own real
    # first pass over every file must collect variable defaults before
    # any resource is resolved, regardless of iteration order.
    (tmp_path / "100-fixtures.tf").write_text('''
resource "aws_instance" "cwpp_fixtures" {
  tags = {
    Name = "${var.prefix}-cwpp-fixtures"
  }
}
''')
    (tmp_path / "variables.tf").write_text('''
variable "prefix" {
  default = "nbg-toxic-combo"
}
''')
    resources = parse_directory(str(tmp_path))
    assert resources[("aws_instance", "cwpp_fixtures")]["tags"]["Name"] == "nbg-toxic-combo-cwpp-fixtures"


def test_parse_directory_only_files_still_uses_variables_from_a_skipped_file(tmp_path):
    from nimbus_iac_scanner import terraform_parser
    (tmp_path / "fixtures.tf").write_text('''
resource "aws_instance" "x" {
  tags = { Name = "${var.prefix}-x" }
}
''')
    (tmp_path / "variables.tf").write_text('variable "prefix" { default = "nbg" }\n')
    only = {str((tmp_path / "fixtures.tf").resolve())}  # variables.tf itself is "unchanged" and skipped
    resources = terraform_parser.parse_directory(str(tmp_path), only_files=only)
    assert resources[("aws_instance", "x")]["tags"]["Name"] == "nbg-x"
