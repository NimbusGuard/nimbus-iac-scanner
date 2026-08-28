from nimbus_iac_scanner.cloudformation_mapping import map_resources, unmapped_resource_types
from nimbus_iac_scanner.cloudformation_parser import parse_source


def test_s3_bucket_maps_an_inline_public_access_block_configuration():
    resources = parse_source('''
Resources:
  InsecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: false
        IgnorePublicAcls: false
        RestrictPublicBuckets: false
      Tags:
        - Key: Environment
          Value: prod
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["provider"] == "aws"
    assert entry["resource_type"] == "s3_bucket"
    assert entry["configuration"]["public_access_block"] == {
        "block_public_acls": False, "block_public_policy": False,
        "ignore_public_acls": False, "restrict_public_buckets": False,
    }
    assert entry["tags"] == {"Environment": "prod"}
    assert entry["identifier"] == "AWS::S3::Bucket.InsecureBucket"


def test_s3_bucket_with_no_public_access_block_property_omits_the_field():
    resources = parse_source('''
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert "public_access_block" not in entry["configuration"]


def test_security_group_maps_ingress_rules():
    resources = parse_source('''
Resources:
  OpenSsh:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "security_group"
    assert entry["configuration"]["ingress_rules"] == [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": [{"type": "ipv4", "value": "0.0.0.0/0"}]}
    ]


def test_security_group_with_a_single_bare_ingress_object_not_a_list():
    resources = parse_source('''
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 10.0.0.0/8
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert len(entry["configuration"]["ingress_rules"]) == 1


def test_rds_storage_encrypted_defaults_false_but_publicly_accessible_omitted_when_absent():
    """StorageEncrypted has a real, confirmed CFN default (false);
    PubliclyAccessible has NO confirmed CFN default at all -- a real,
    disclosed difference from the Terraform mapper's own behavior for
    the equivalent concept."""
    resources = parse_source('''
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"storage_encrypted": False}
    assert "publicly_accessible" not in entry["configuration"]


def test_rds_maps_explicit_publicly_accessible():
    resources = parse_source('''
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: true
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"publicly_accessible": True, "storage_encrypted": True}


def test_kms_key_omitted_attributes_use_the_real_confirmed_cfn_defaults():
    resources = parse_source('''
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {
        "key_manager": "CUSTOMER", "key_spec": "SYMMETRIC_DEFAULT", "key_rotation_enabled": False,
    }


def test_cloudtrail_omits_is_logging_when_genuinely_absent():
    """IsLogging is a REQUIRED CFN property with no documented default
    -- a template missing it is malformed, but this must still never
    guess true or false."""
    resources = parse_source('''
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {}


def test_cloudtrail_maps_explicit_is_logging():
    resources = parse_source('''
Resources:
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: false
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"is_logging": False}


def test_ebs_volume_omits_encrypted_when_absent():
    resources = parse_source('''
Resources:
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      AvailabilityZone: us-east-1a
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {}


def test_iam_role_maps_managed_policy_arns_and_native_inline_policy_document():
    """PolicyDocument arrives already as a native, parsed object in
    CloudFormation -- no JSON-string parsing needed at all, unlike the
    Terraform mapper's own equivalent."""
    resources = parse_source('''
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
      Policies:
        - PolicyName: inline-admin
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "iam_role"
    assert entry["configuration"]["attached_policies"] == [{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    assert entry["configuration"]["inline_policies"][0]["policy_document"]["Statement"][0]["Action"] == "*"


def test_iam_user_with_no_policies_gets_empty_lists():
    resources = parse_source('''
Resources:
  PlainUser:
    Type: AWS::IAM::User
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "iam_user"
    assert entry["configuration"] == {"attached_policies": [], "inline_policies": []}


def test_unrecognized_resource_type_is_skipped_not_fabricated():
    resources = parse_source('''
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"AWS::Lambda::Function"}
