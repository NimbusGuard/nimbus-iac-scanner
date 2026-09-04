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
    # AWS::Lambda::LayerVersion has no Evaluation Engine control -> never mapped.
    resources = parse_source('''
Resources:
  Layer:
    Type: AWS::Lambda::LayerVersion
    Properties: {}
''', is_yaml=True, file_key="t.yaml")
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"AWS::Lambda::LayerVersion"}


# --- load_balancer (NG-AWS-ELB-001..007) ----------------------------------

def test_load_balancer_all_fields():
    entry = map_resources(parse_source('''
Resources:
  PublicLb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internet-facing
      Type: application
      LoadBalancerAttributes:
        - Key: deletion_protection.enabled
          Value: "true"
        - Key: access_logs.s3.enabled
          Value: "true"
      Tags:
        - Key: Environment
          Value: prod
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["provider"] == "aws"
    assert entry["resource_type"] == "load_balancer"
    assert entry["configuration"] == {
        "scheme": "internet-facing",
        "type": "application",
        "deletion_protection_enabled": True,
        "access_logs_enabled": True,
    }
    assert entry["tags"] == {"Environment": "prod"}
    assert entry["identifier"] == "AWS::ElasticLoadBalancingV2::LoadBalancer.PublicLb"


def test_load_balancer_defaults_when_omitted():
    entry = map_resources(parse_source('''
Resources:
  BareLb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties: {}
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "scheme": "internet-facing",
        "type": "application",
        "deletion_protection_enabled": False,
        "access_logs_enabled": False,
    }


def test_load_balancer_internal_and_attributes_false():
    entry = map_resources(parse_source('''
Resources:
  InternalLb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internal
      Type: network
      LoadBalancerAttributes:
        - Key: deletion_protection.enabled
          Value: "false"
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["scheme"] == "internal"
    assert cfg["type"] == "network"
    assert cfg["deletion_protection_enabled"] is False
    assert cfg["access_logs_enabled"] is False


# --- eks_cluster (NG-AWS-EKS-001..005) ------------------------------------

def test_eks_cluster_all_fields():
    entry = map_resources(parse_source('''
Resources:
  Cluster:
    Type: AWS::EKS::Cluster
    Properties:
      Version: "1.29"
      ResourcesVpcConfig:
        EndpointPublicAccess: false
        EndpointPrivateAccess: true
      Logging:
        ClusterLogging:
          EnabledTypes:
            - Type: api
            - Type: audit
      EncryptionConfig:
        - Resources: [secrets]
          Provider:
            KeyArn: arn:aws:kms:us-east-1:1:key/abc
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["endpoint_public_access"] is False
    assert cfg["endpoint_private_access"] is True
    assert cfg["enabled_log_types"] == ["api", "audit"]
    assert cfg["secrets_encryption_enabled"] is True
    assert cfg["version"] == "1.29"
    assert entry["identifier"] == "AWS::EKS::Cluster.Cluster"


def test_eks_cluster_defaults_when_minimal():
    entry = map_resources(parse_source('''
Resources:
  Bare:
    Type: AWS::EKS::Cluster
    Properties:
      ResourcesVpcConfig: {}
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["endpoint_public_access"] is True
    assert cfg["endpoint_private_access"] is False
    assert cfg["enabled_log_types"] == []
    assert cfg["secrets_encryption_enabled"] is False
    assert "version" not in cfg


# --- dynamodb_table (NG-AWS-DYNAMODB-001..003) ----------------------------

def test_dynamodb_table_all_fields_with_cmk():
    entry = map_resources(parse_source('''
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      DeletionProtectionEnabled: true
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: true
      SSESpecification:
        SSEEnabled: true
        SSEType: KMS
        KMSMasterKeyId: arn:aws:kms:us-east-1:1:key/abc
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "deletion_protection_enabled": True, "pitr_enabled": True, "encrypted_with_cmk": True,
    }


def test_dynamodb_table_sse_without_key_is_not_cmk_and_defaults():
    entry = map_resources(parse_source('''
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      SSESpecification:
        SSEEnabled: true
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "deletion_protection_enabled": False, "pitr_enabled": False, "encrypted_with_cmk": False,
    }


# --- ec2_instance (NG-AWS-EC2-010/011/023) --------------------------------

def test_ec2_instance_monitoring_metadata_and_nic_public_ip():
    entry = map_resources(parse_source('''
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      Monitoring: true
      MetadataOptions:
        HttpTokens: required
      NetworkInterfaces:
        - DeviceIndex: "0"
          AssociatePublicIpAddress: true
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["detailed_monitoring_enabled"] is True
    assert cfg["metadata_options"]["http_tokens"] == "required"
    assert cfg["public_ip_address"] is True
    assert entry["identifier"] == "AWS::EC2::Instance.Web"


def test_ec2_instance_defaults_no_nic_no_metadata():
    entry = map_resources(parse_source('''
Resources:
  Bare:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-1
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["detailed_monitoring_enabled"] is False
    assert cfg["metadata_options"] == {"http_tokens": "optional"}
    assert "public_ip_address" not in cfg


# --- lambda_function (NG-AWS-AWSLAMBDA-003/004/005 inline subset) ----------

def test_lambda_function_inline_fields():
    entry = map_resources(parse_source('''
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      KmsKeyArn: arn:aws:kms:us-east-1:1:key/abc
      TracingConfig:
        Mode: Active
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["runtime"] == "python3.12"
    assert cfg["env_encrypted_with_cmk"] is True
    assert cfg["xray_tracing_enabled"] is True
    assert "function_url_auth_none" not in cfg  # CFN cross-resource not correlated
    assert entry["identifier"] == "AWS::Lambda::Function.Fn"


def test_lambda_function_defaults():
    entry = map_resources(parse_source('''
Resources:
  Bare:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs18.x
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["env_encrypted_with_cmk"] is False
    assert cfg["xray_tracing_enabled"] is False


# --- ecr / efs / elasticache / redshift -----------------------------------

def test_ecr_repository_cfn():
    entry = map_resources(parse_source('''
Resources:
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: true
      LifecyclePolicy:
        LifecyclePolicyText: "{}"
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "scan_on_push_enabled": True, "tag_immutability_enabled": True, "lifecycle_policy_enabled": True,
    }


def test_efs_file_system_cfn():
    entry = map_resources(parse_source('''
Resources:
  Fs:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
      BackupPolicy:
        Status: ENABLED
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {"encrypted": True, "backup_enabled": True}


def test_elasticache_replication_group_cfn():
    entry = map_resources(parse_source('''
Resources:
  Rg:
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      AtRestEncryptionEnabled: true
      TransitEncryptionEnabled: true
      AutoMinorVersionUpgrade: false
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "at_rest_encryption_enabled": True, "transit_encryption_enabled": True, "auto_minor_version_upgrade": False,
    }


def test_redshift_cluster_cfn_omits_public_when_absent():
    entry = map_resources(parse_source('''
Resources:
  C:
    Type: AWS::Redshift::Cluster
    Properties:
      Encrypted: true
      LoggingProperties:
        BucketName: my-logs
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg["encrypted"] is True
    assert cfg["audit_logging_enabled"] is True
    assert "publicly_accessible" not in cfg


# --- sns / sqs / secretsmanager / acm -------------------------------------

def test_sns_topic_cfn():
    entry = map_resources(parse_source('''
Resources:
  T:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {"kms_encryption_enabled": True}


def test_sqs_queue_cfn_sse_managed():
    entry = map_resources(parse_source('''
Resources:
  Q:
    Type: AWS::SQS::Queue
    Properties:
      SqsManagedSseEnabled: true
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {"encryption_enabled": True}


def test_secretsmanager_secret_cfn_omits_rotation():
    entry = map_resources(parse_source('''
Resources:
  S:
    Type: AWS::SecretsManager::Secret
    Properties:
      KmsKeyId: arn:aws:kms:...:key/abc
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {"encrypted_with_cmk": True}
    assert "rotation_enabled" not in entry["configuration"]


def test_acm_certificate_cfn_default_enabled_and_disabled():
    default = map_resources(parse_source('''
Resources:
  C:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: example.com
''', is_yaml=True, file_key="t.yaml"))[0]
    assert default["configuration"] == {"transparency_logging_enabled": True}
    disabled = map_resources(parse_source('''
Resources:
  C:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: example.com
      CertificateTransparencyLoggingPreference: DISABLED
''', is_yaml=True, file_key="t.yaml"))[0]
    assert disabled["configuration"] == {"transparency_logging_enabled": False}


# --- cloudfront_distribution ----------------------------------------------

def test_cloudfront_cfn_hardened():
    entry = map_resources(parse_source('''
Resources:
  Cdn:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          ViewerProtocolPolicy: redirect-to-https
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021
        Logging:
          Bucket: logs.s3.amazonaws.com
''', is_yaml=True, file_key="t.yaml"))[0]
    cfg = entry["configuration"]
    assert cfg == {"viewer_https_enforced": True, "minimum_tls_1_2": True, "access_logging_enabled": True}
    assert "origin_access_controlled" not in cfg


def test_cloudfront_cfn_insecure():
    entry = map_resources(parse_source('''
Resources:
  Cdn:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          ViewerProtocolPolicy: allow-all
        ViewerCertificate:
          CloudFrontDefaultCertificate: true
''', is_yaml=True, file_key="t.yaml"))[0]
    assert entry["configuration"] == {
        "viewer_https_enforced": False, "minimum_tls_1_2": False, "access_logging_enabled": False,
    }
