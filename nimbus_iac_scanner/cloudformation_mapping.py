"""CloudFormation resource type -> nimbus_app's own `{provider,
resource_type, configuration, tags, identifier}` shape -- the same 8
resource-type concepts `resource_mapping.py` (Terraform) already
covers, confirmed field-by-field against the real evaluation-engine
control source AND against AWS's own current CloudFormation User Guide
(fetched live, cited inline per mapper below), never guessed.

**Genuinely simpler than the Terraform mapper for several of these
concepts** -- CloudFormation expresses most of what Terraform needs a
SEPARATE, cross-referenced resource for as a single, already-inline
property on the SAME resource: `AWS::S3::Bucket`'s own
`PublicAccessBlockConfiguration` property (vs. Terraform's separate
`aws_s3_bucket_public_access_block` resource), and `AWS::IAM::Role`/
`AWS::IAM::User`'s own `ManagedPolicyArns` (a plain list of ARN
strings, no separate attachment resource) and `Policies` (a list of
`{PolicyName, PolicyDocument}` where `PolicyDocument` is ALREADY a
native, parsed JSON object -- no `jsonencode(...)`/heredoc/escaped-
string parsing dance at all, unlike Terraform's own inline-policy
correlation).

**Several confirmed-different defaults from Terraform's own, a real,
disclosed difference between formats, not an inconsistency**:
`PubliclyAccessible` on `AWS::RDS::DBInstance` has NO single documented
CloudFormation default (confirmed live: "depends on your VPC setup and
the database subnet group") -- omitted entirely if absent, unlike
Terraform's own confirmed `false` default for the equivalent argument.
`IsLogging` on `AWS::CloudTrail::Trail` is a REQUIRED property with no
documented default at all (unlike Terraform's `enable_logging`, which
defaults `true`) -- a template genuinely missing it is malformed, and
this module still never guesses, it omits."""
from typing import Any, Optional

ResourceKey = tuple[str, str]  # (template_file_path, logical_id)


def _tags_from_cfn_list(raw_tags: Any) -> dict[str, str]:
    """CloudFormation tags are a LIST of `{Key, Value}` objects, not a
    plain map the way Terraform's `tags = {}` argument is -- confirmed
    real shape, not guessed."""
    if not isinstance(raw_tags, list):
        return {}
    result: dict[str, str] = {}
    for tag in raw_tags:
        if isinstance(tag, dict) and isinstance(tag.get("Key"), str):
            result[tag["Key"]] = tag.get("Value")
    return result


# ---------------------------------------------------------------------------
# S3 bucket public access (NG-AWS-S3-001) -- PublicAccessBlockConfiguration
# is an INLINE property on the bucket itself, confirmed real property
# names (BlockPublicAcls/BlockPublicPolicy/IgnorePublicAcls/
# RestrictPublicBuckets) against AWS's own current CFN docs.
# ---------------------------------------------------------------------------

def _map_s3_bucket(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {}
    pab = properties.get("PublicAccessBlockConfiguration")
    if isinstance(pab, dict):
        configuration["public_access_block"] = {
            "block_public_acls": bool(pab.get("BlockPublicAcls", False)),
            "block_public_policy": bool(pab.get("BlockPublicPolicy", False)),
            "ignore_public_acls": bool(pab.get("IgnorePublicAcls", False)),
            "restrict_public_buckets": bool(pab.get("RestrictPublicBuckets", False)),
        }
    # else: no PublicAccessBlockConfiguration property at all -- omitted
    # entirely, same "no confirmed configuration, honestly NOT_EVALUATED"
    # outcome as the Terraform mapper's own equivalent case.
    return {
        "provider": "aws",
        "resource_type": "s3_bucket",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::S3::Bucket.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Security group ingress rules (NG-AWS-EC2-001/002) -- confirmed real
# property names (IpProtocol/FromPort/ToPort/CidrIp) against AWS's own
# current CFN docs. Only CidrIp (ipv4) is mapped, matching the Terraform
# mapper's own scope -- CidrIpv6/SourcePrefixListId/SourceSecurityGroupId
# aren't, since NG-AWS-EC2-001/002's own real matching logic never
# inspects anything but an ipv4 CIDR source either.
# ---------------------------------------------------------------------------

def _normalize_cfn_ingress_rule(rule: dict[str, Any]) -> dict[str, Any]:
    cidr = rule.get("CidrIp")
    return {
        "protocol": rule.get("IpProtocol"),
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "sources": [{"type": "ipv4", "value": cidr}] if cidr else [],
    }


def _map_security_group(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    ingress = properties.get("SecurityGroupIngress") or []
    if isinstance(ingress, dict):  # a single rule object, not wrapped in a list
        ingress = [ingress]
    rules = [_normalize_cfn_ingress_rule(r) for r in ingress if isinstance(r, dict)]
    return {
        "provider": "aws",
        "resource_type": "security_group",
        "configuration": {"ingress_rules": rules},
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::EC2::SecurityGroup.{key[1]}",
    }


# ---------------------------------------------------------------------------
# RDS (NG-AWS-RDS-001/002) -- StorageEncrypted has a real, confirmed CFN
# default of false; PubliclyAccessible has NO single documented CFN
# default at all (confirmed live: depends on VPC/subnet setup) -- omitted
# entirely when absent, a real, disclosed difference from the Terraform
# mapper's own confirmed-false default for the equivalent argument.
# ---------------------------------------------------------------------------

def _map_rds_instance(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {"storage_encrypted": bool(properties.get("StorageEncrypted", False))}
    if "PubliclyAccessible" in properties:
        configuration["publicly_accessible"] = bool(properties["PubliclyAccessible"])
    return {
        "provider": "aws",
        "resource_type": "rds_instance",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::RDS::DBInstance.{key[1]}",
    }


# ---------------------------------------------------------------------------
# KMS key rotation (NG-AWS-KMS-001) -- KeySpec defaults SYMMETRIC_DEFAULT,
# EnableKeyRotation defaults false, both confirmed live against AWS's own
# current CFN docs (same confirmed defaults as the Terraform equivalent
# arguments). key_manager is always "CUSTOMER" for a CloudFormation-
# declared key, the same structural fact as the Terraform mapper.
# ---------------------------------------------------------------------------

def _map_kms_key(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    return {
        "provider": "aws",
        "resource_type": "kms_key",
        "configuration": {
            "key_manager": "CUSTOMER",
            "key_spec": properties.get("KeySpec", "SYMMETRIC_DEFAULT"),
            "key_rotation_enabled": bool(properties.get("EnableKeyRotation", False)),
        },
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::KMS::Key.{key[1]}",
    }


# ---------------------------------------------------------------------------
# CloudTrail logging (NG-AWS-CLOUDTRAIL-001) -- IsLogging is a REQUIRED
# CFN property with no documented default at all (confirmed live) --
# genuinely different from Terraform's own enable_logging, which
# defaults true. Omitted if genuinely absent, never guessed.
# ---------------------------------------------------------------------------

def _map_cloudtrail(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {}
    if "IsLogging" in properties:
        configuration["is_logging"] = bool(properties["IsLogging"])
    return {
        "provider": "aws",
        "resource_type": "cloudtrail_trail",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::CloudTrail::Trail.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EBS volume encryption -- Encrypted has no documented CFN default
# (confirmed live, same finding as the Terraform equivalent argument) --
# omitted entirely unless the template sets it explicitly.
# ---------------------------------------------------------------------------

def _map_ebs_volume(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {}
    if "Encrypted" in properties:
        configuration["encrypted"] = bool(properties["Encrypted"])
    return {
        "provider": "aws",
        "resource_type": "ebs_volume",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::EC2::Volume.{key[1]}",
    }


# ---------------------------------------------------------------------------
# IAM admin-privilege detection (NG-AWS-IAM-001 users / NG-AWS-IAM-012
# roles) -- ManagedPolicyArns (a plain list of ARN strings) and Policies
# (a list of {PolicyName, PolicyDocument}, PolicyDocument ALREADY a
# native parsed JSON object) confirmed identical on both AWS::IAM::Role
# and AWS::IAM::User against AWS's own current CFN docs -- no separate
# attachment resource, no JSON-string parsing needed at all, unlike the
# Terraform mapper's own real correlation/parsing complexity for the
# identical concept.
# ---------------------------------------------------------------------------

def _map_iam_principal(cfn_type: str, resource_type: str, key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    attached_policies = [
        {"policy_arn": arn} for arn in (properties.get("ManagedPolicyArns") or []) if isinstance(arn, str)
    ]
    inline_policies = [
        {"policy_document": policy["PolicyDocument"]}
        for policy in (properties.get("Policies") or [])
        if isinstance(policy, dict) and isinstance(policy.get("PolicyDocument"), dict)
    ]
    return {
        "provider": "aws",
        "resource_type": resource_type,
        "configuration": {"attached_policies": attached_policies, "inline_policies": inline_policies},
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"{cfn_type}.{key[1]}",
    }


def _map_iam_role(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    return _map_iam_principal("AWS::IAM::Role", "iam_role", key, body)


def _map_iam_user(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    return _map_iam_principal("AWS::IAM::User", "iam_user", key, body)


# Registry keyed by the real CFN "Type" string -- same "registry over
# hardcoded chain" shape resource_mapping.py's own _MAPPERS already
# establishes.

# ---------------------------------------------------------------------------
# Load balancer (NG-AWS-ELB-001..007). Scheme/Type are direct properties
# (defaults 'internet-facing'/'application' per AWS's own CFN docs);
# deletion_protection.enabled and access_logs.s3.enabled live in the
# LoadBalancerAttributes list of {Key, Value} (Value a "true"/"false"
# STRING), absent -> false. Listener/WAF-level checks aren't correlated
# (their fields omitted, so those controls read NOT_EVALUATED).
# ---------------------------------------------------------------------------

def _lb_attribute_bool(attributes: Any, key_name: str) -> bool:
    if not isinstance(attributes, list):
        return False
    for attr in attributes:
        if isinstance(attr, dict) and attr.get("Key") == key_name:
            return str(attr.get("Value")).lower() == "true"
    return False


def _map_load_balancer(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    attributes = properties.get("LoadBalancerAttributes")
    return {
        "provider": "aws",
        "resource_type": "load_balancer",
        "configuration": {
            "scheme": properties.get("Scheme", "internet-facing"),
            "type": properties.get("Type", "application"),
            "deletion_protection_enabled": _lb_attribute_bool(attributes, "deletion_protection.enabled"),
            "access_logs_enabled": _lb_attribute_bool(attributes, "access_logs.s3.enabled"),
        },
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::ElasticLoadBalancingV2::LoadBalancer.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EKS cluster (NG-AWS-EKS-001..005). ResourcesVpcConfig.EndpointPublicAccess
# (default true) / EndpointPrivateAccess (default false); Logging.
# ClusterLogging.EnabledTypes is a list of {Type}; EncryptionConfig is a list
# of {Resources:[...], Provider:{KeyArn}} -> secrets_encryption_enabled when
# any entry covers "secrets"; Version. Confirmed against AWS's CFN docs.
# ---------------------------------------------------------------------------

def _map_eks_cluster(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {}
    vpc = properties.get("ResourcesVpcConfig")
    if isinstance(vpc, dict):
        configuration["endpoint_public_access"] = bool(vpc.get("EndpointPublicAccess", True))
        configuration["endpoint_private_access"] = bool(vpc.get("EndpointPrivateAccess", False))
    else:
        configuration["endpoint_public_access"] = True
        configuration["endpoint_private_access"] = False
    enabled_types: list[str] = []
    logging = properties.get("Logging")
    if isinstance(logging, dict):
        cluster_logging = logging.get("ClusterLogging")
        if isinstance(cluster_logging, dict):
            for entry in cluster_logging.get("EnabledTypes") or []:
                if isinstance(entry, dict) and isinstance(entry.get("Type"), str):
                    enabled_types.append(entry["Type"])
    configuration["enabled_log_types"] = enabled_types
    secrets_encrypted = False
    enc = properties.get("EncryptionConfig")
    if isinstance(enc, list):
        for entry in enc:
            if isinstance(entry, dict) and "secrets" in (entry.get("Resources") or []):
                secrets_encrypted = True
    configuration["secrets_encryption_enabled"] = secrets_encrypted
    version = properties.get("Version")
    if version is not None:
        configuration["version"] = str(version)
    return {
        "provider": "aws",
        "resource_type": "eks_cluster",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::EKS::Cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# DynamoDB table (NG-AWS-DYNAMODB-001..003). DeletionProtectionEnabled;
# PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled;
# encrypted_with_cmk = SSESpecification with SSEEnabled AND a KMSMasterKeyId
# (a customer key -- an SSE spec with no KMSMasterKeyId is the AWS-owned
# key, not a CMK). Confirmed against the DynamoDB CMK control + AWS CFN docs.
# ---------------------------------------------------------------------------

def _map_dynamodb_table(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    pitr = properties.get("PointInTimeRecoverySpecification")
    sse = properties.get("SSESpecification")
    encrypted_with_cmk = bool(
        isinstance(sse, dict) and sse.get("SSEEnabled") and sse.get("KMSMasterKeyId")
    )
    return {
        "provider": "aws",
        "resource_type": "dynamodb_table",
        "configuration": {
            "deletion_protection_enabled": bool(properties.get("DeletionProtectionEnabled", False)),
            "pitr_enabled": bool(isinstance(pitr, dict) and pitr.get("PointInTimeRecoveryEnabled", False)),
            "encrypted_with_cmk": encrypted_with_cmk,
        },
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::DynamoDB::Table.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EC2 instance (NG-AWS-EC2-010/011/023, the statically-knowable subset).
# Monitoring -> detailed_monitoring_enabled; MetadataOptions ->
# metadata_options (mapped to the snake_case http_tokens the control reads,
# absent -> {"http_tokens":"optional"} documented default). Public IP intent
# on AWS::EC2::Instance lives on a NetworkInterfaces entry's
# AssociatePublicIpAddress (there's no top-level property) -> public_ip_address
# when present, omitted otherwise. ssm_managed / secrets_detected omitted.
# ---------------------------------------------------------------------------

def _map_ec2_instance(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {
        "detailed_monitoring_enabled": bool(properties.get("Monitoring", False)),
    }
    nics = properties.get("NetworkInterfaces")
    if isinstance(nics, list):
        for nic in nics:
            if isinstance(nic, dict) and "AssociatePublicIpAddress" in nic:
                configuration["public_ip_address"] = bool(nic.get("AssociatePublicIpAddress"))
                break
    meta = properties.get("MetadataOptions")
    if isinstance(meta, dict):
        md: dict[str, Any] = {}
        if "HttpTokens" in meta:
            md["http_tokens"] = meta["HttpTokens"]
        if "HttpEndpoint" in meta:
            md["http_endpoint"] = meta["HttpEndpoint"]
        if "HttpPutResponseHopLimit" in meta:
            md["http_put_response_hop_limit"] = meta["HttpPutResponseHopLimit"]
        md.setdefault("http_tokens", "optional")
        configuration["metadata_options"] = md
    else:
        configuration["metadata_options"] = {"http_tokens": "optional"}
    return {
        "provider": "aws",
        "resource_type": "ec2_instance",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::EC2::Instance.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Lambda function (NG-AWS-AWSLAMBDA-003/004/005 -- the inline subset).
# Runtime; TracingConfig.Mode == "Active" -> xray_tracing_enabled; KmsKeyArn
# -> env_encrypted_with_cmk. function_url_auth_none is OMITTED: AWS::Lambda::Url
# is a separate resource and CloudFormation mappers here take no all_resources
# for cross-resource correlation (a real, disclosed gap -> AWSLAMBDA-002 reads
# NOT_EVALUATED, never a false verdict). resource_policy_allows_public /
# secrets_detected omitted for the same reasons as the Terraform mapper.
# ---------------------------------------------------------------------------

def _map_lambda_function(key: ResourceKey, body: dict[str, Any]) -> dict[str, Any]:
    properties = body.get("Properties") or {}
    configuration: dict[str, Any] = {
        "env_encrypted_with_cmk": bool(properties.get("KmsKeyArn")),
    }
    runtime = properties.get("Runtime")
    if runtime is not None:
        configuration["runtime"] = runtime
    tracing = properties.get("TracingConfig")
    configuration["xray_tracing_enabled"] = bool(
        isinstance(tracing, dict) and tracing.get("Mode") == "Active"
    )
    return {
        "provider": "aws",
        "resource_type": "lambda_function",
        "configuration": configuration,
        "tags": _tags_from_cfn_list(properties.get("Tags")),
        "identifier": f"AWS::Lambda::Function.{key[1]}",
    }


_MAPPERS = {
    "AWS::S3::Bucket": _map_s3_bucket,
    "AWS::EC2::SecurityGroup": _map_security_group,
    "AWS::RDS::DBInstance": _map_rds_instance,
    "AWS::KMS::Key": _map_kms_key,
    "AWS::CloudTrail::Trail": _map_cloudtrail,
    "AWS::EC2::Volume": _map_ebs_volume,
    "AWS::IAM::Role": _map_iam_role,
    "AWS::IAM::User": _map_iam_user,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": _map_load_balancer,
    "AWS::EKS::Cluster": _map_eks_cluster,
    "AWS::DynamoDB::Table": _map_dynamodb_table,
    "AWS::EC2::Instance": _map_ec2_instance,
    "AWS::Lambda::Function": _map_lambda_function,
}


def map_resources(all_resources: dict[ResourceKey, dict[str, Any]]) -> list[dict[str, Any]]:
    """Every recognized resource, mapped to nimbus_app's own gate-check
    shape. An unrecognized CloudFormation resource type is silently
    skipped -- never sent, never fabricated as a trivially-passing
    resource, same discipline as the Terraform mapper."""
    mapped = []
    for key, body in all_resources.items():
        mapper = _MAPPERS.get(body.get("Type"))
        if mapper is None:
            continue
        mapped.append(mapper(key, body))
    return mapped


def unmapped_resource_types(all_resources: dict[ResourceKey, dict[str, Any]]) -> set[str]:
    """The real, distinct set of CloudFormation resource types this
    parse run saw but doesn't know how to map."""
    return {
        resource_type for resource_type in
        (body.get("Type") for body in all_resources.values())
        if isinstance(resource_type, str) and resource_type not in _MAPPERS
    }
