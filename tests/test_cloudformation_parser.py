from nimbus_iac_scanner.cloudformation_parser import parse_directory, parse_source


def test_parses_a_json_template():
    resources = parse_source(
        '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "b"}}}}',
        is_yaml=False, file_key="t.json",
    )
    assert ("t.json", "Bucket") in resources
    assert resources[("t.json", "Bucket")]["Type"] == "AWS::S3::Bucket"


def test_parses_a_yaml_template():
    resources = parse_source('''
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: b
''', is_yaml=True, file_key="t.yaml")
    assert ("t.yaml", "Bucket") in resources


def test_yaml_short_form_intrinsic_functions_never_crash_the_parser():
    """!Sub/!Ref/!GetAtt etc. are real, common CloudFormation YAML
    syntax on properties this tool never reads -- parsing the whole
    template must never fail just because they're present elsewhere."""
    resources = parse_source('''
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "my-bucket-${AWS::AccountId}"
      Tags:
        - Key: Owner
          Value: !Ref OwnerParam
''', is_yaml=True, file_key="t.yaml")
    assert ("t.yaml", "Bucket") in resources


def test_a_document_with_no_resources_key_returns_empty():
    resources = parse_source('{"SomeOtherThing": {}}', is_yaml=False, file_key="t.json")
    assert resources == {}


def test_a_non_dict_document_returns_empty():
    resources = parse_source("- just\n- a\n- list\n", is_yaml=True, file_key="t.yaml")
    assert resources == {}


def test_a_resource_with_no_type_is_skipped():
    resources = parse_source(
        '{"Resources": {"Bad": {"Properties": {}}}}', is_yaml=False, file_key="t.json",
    )
    assert resources == {}


def test_parse_directory_merges_json_and_yaml_files(tmp_path):
    (tmp_path / "bucket.json").write_text(
        '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}'
    )
    (tmp_path / "sg.yaml").write_text('''
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties: {}
''')
    resources = parse_directory(str(tmp_path))
    types = {body["Type"] for body in resources.values()}
    assert types == {"AWS::S3::Bucket", "AWS::EC2::SecurityGroup"}


def test_parse_directory_disambiguates_the_same_logical_id_across_two_files(tmp_path):
    """Two independent stack templates can both legitimately declare a
    resource named "MyBucket" -- keying by file path too must keep them
    as two distinct entries, never silently clobbering one with the
    other."""
    (tmp_path / "stack_a.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a"}}}}'
    )
    (tmp_path / "stack_b.json").write_text(
        '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "b"}}}}'
    )
    resources = parse_directory(str(tmp_path))
    assert len(resources) == 2
    bucket_names = {body["Properties"]["BucketName"] for body in resources.values()}
    assert bucket_names == {"a", "b"}


def test_a_plain_non_cloudformation_json_file_contributes_nothing(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "not-a-cfn-template", "version": "1.0.0"}')
    resources = parse_directory(str(tmp_path))
    assert resources == {}
