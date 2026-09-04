"""Source (file, line) capture for a finding's clickable back-link."""
from nimbus_iac_scanner import (
    bicep_mapping, cloudformation_mapping, cloudformation_parser,
    resource_mapping, source_location, terraform_parser,
)


def test_terraform_decl_line():
    text = 'variable "x" {}\n\nresource "aws_s3_bucket" "data" {\n  bucket = "b"\n}\n'
    assert source_location.terraform_decl_line(text, "aws_s3_bucket", "data") == 3
    assert source_location.terraform_decl_line(text, "aws_s3_bucket", "nope") is None


def test_cloudformation_decl_line_yaml_and_json():
    yaml_text = "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n"
    assert source_location.cloudformation_decl_line(yaml_text, "MyBucket") == 2
    json_text = '{\n  "Resources": {\n    "MyBucket": {\n      "Type": "AWS::S3::Bucket"\n    }\n  }\n}\n'
    assert source_location.cloudformation_decl_line(json_text, "MyBucket") == 3


def test_bicep_decl_line_anchors_on_literal_name():
    text = "resource sa 'Microsoft.Storage/storageAccounts@2022-09-01' = {\n  name: 'acmedemo'\n}\n"
    assert source_location.bicep_decl_line(text, "acmedemo") == 2
    # a non-literal name (a param) can't be located -> None, never a wrong line
    assert source_location.bicep_decl_line(text, "someParamValue") is None


def test_terraform_parse_directory_attaches_source(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {\n  bucket = "b"\n}\n')
    resources = terraform_parser.parse_directory(str(tmp_path))
    body = resources[("aws_s3_bucket", "data")]
    assert body[source_location.SOURCE_FILE_KEY].endswith("main.tf")
    assert body[source_location.SOURCE_LINE_KEY] == 1
    # and map_resources moves it onto the mapped resource
    mapped = resource_mapping.map_resources(resources)
    s3 = next(r for r in mapped if r["identifier"] == "aws_s3_bucket.data")
    assert s3["source_file"].endswith("main.tf") and s3["source_line"] == 1


def test_cloudformation_map_resources_carries_source(tmp_path):
    (tmp_path / "t.yaml").write_text("Resources:\n  B:\n    Type: AWS::S3::Bucket\n")
    resources = cloudformation_parser.parse_directory(str(tmp_path))
    mapped = cloudformation_mapping.map_resources(resources)
    b = next(r for r in mapped if r["resource_type"] == "s3_bucket")
    assert b["source_file"].endswith("t.yaml") and b["source_line"] == 2
