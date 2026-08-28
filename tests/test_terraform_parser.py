from nimbus_iac_scanner.terraform_parser import parse_directory, parse_source, resolve_reference


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
