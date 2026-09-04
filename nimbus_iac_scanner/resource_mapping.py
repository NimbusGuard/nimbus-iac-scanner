"""Terraform resource type -> nimbus_app's own `{provider, resource_type,
configuration, tags, identifier}` shape -- the SAME field vocabulary
`GET /v1/controls`' own `target.required_fields` documents per real
resource_type, confirmed against the actual evaluation-engine control
source (never guessed) before writing this file:

- `s3_bucket` / `configuration.public_access_block` (NG-AWS-S3-001):
  `{block_public_acls, block_public_policy, ignore_public_acls,
  restrict_public_buckets}`, all bool.
- `security_group` / `configuration.ingress_rules` (NG-AWS-EC2-001/002):
  `[{protocol, from_port, to_port, sources: [{type: "ipv4", value}]}]`.
- `rds_instance` / `configuration.publicly_accessible` (NG-AWS-RDS-001),
  `configuration.storage_encrypted` (NG-AWS-RDS-002), both bool.
- `kms_key` / `configuration.key_manager`, `.key_spec`,
  `.key_rotation_enabled` (NG-AWS-KMS-001).
- `cloudtrail_trail` / `configuration.is_logging` (NG-AWS-CLOUDTRAIL-001).
- `ebs_volume` / `configuration.encrypted`.
- `iam_user`/`iam_role` / `configuration.attached_policies`,
  `.inline_policies` (NG-AWS-IAM-001/012, admin-privilege detection).

**Deliberately a curated set of Terraform resource types -- not an
attempt at exhaustive Terraform/AWS/Azure coverage.** A resource type
this module doesn't recognize is silently skipped (never sent to the
gate-check at all, never fabricated as an empty/passing resource) --
see README.md's own "known gaps" section for the full, disclosed list
of what's not covered yet, same "omit, don't fabricate" discipline
nimbus_app's own real cloud collectors already follow for exactly this
reason. Every default value used when a Terraform attribute is omitted
was confirmed against the AWS provider's own current documentation
(fetched live, cited inline per mapper below) before being coded --
never guessed."""
import json
from typing import Any, Optional

from nimbus_iac_scanner.terraform_parser import resolve_reference

ResourceKey = tuple[str, str]


def _references_resource(value: Any, resource_type: str, resource_name: str, own_literal_names: set[str]) -> bool:
    """True if `value` (a raw HCL attribute) refers to the given
    resource -- either via a real Terraform reference expression, or by
    matching one of that resource's own literal name-shaped attribute
    values (Terraform allows either form, e.g. `bucket =
    aws_s3_bucket.data.id` vs. `bucket = "my-literal-bucket-name"`)."""
    ref = resolve_reference(value)
    if ref is not None:
        return ref[0] == resource_type and ref[1] == resource_name
    return isinstance(value, str) and value in own_literal_names


# ---------------------------------------------------------------------------
# S3 bucket public access (NG-AWS-S3-001)
# ---------------------------------------------------------------------------

def _find_public_access_block(
    bucket_key: ResourceKey, all_resources: dict[ResourceKey, dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Returns the `aws_s3_bucket_public_access_block` resource whose own
    `bucket` attribute resolves to `bucket_key` (via a Terraform
    reference), or references the bucket's own literal name string.
    `None` if no such resource exists in this parse -- the caller omits
    `public_access_block` entirely rather than guessing, same as every
    other collector-side omission in this codebase."""
    _, bucket_name = bucket_key
    bucket_body = all_resources[bucket_key]
    own_names = {bucket_body["bucket"]} if isinstance(bucket_body.get("bucket"), str) and resolve_reference(bucket_body["bucket"]) is None else set()
    for (resource_type, _resource_name), body in all_resources.items():
        if resource_type != "aws_s3_bucket_public_access_block":
            continue
        if _references_resource(body.get("bucket"), "aws_s3_bucket", bucket_name, own_names):
            return body
    return None


def _map_s3_bucket(
    key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]],
) -> dict[str, Any]:
    configuration: dict[str, Any] = {}
    pab = _find_public_access_block(key, all_resources)
    if pab is not None:
        configuration["public_access_block"] = {
            "block_public_acls": bool(pab.get("block_public_acls", False)),
            "block_public_policy": bool(pab.get("block_public_policy", False)),
            "ignore_public_acls": bool(pab.get("ignore_public_acls", False)),
            "restrict_public_buckets": bool(pab.get("restrict_public_buckets", False)),
        }
    # else: no aws_s3_bucket_public_access_block resource references this
    # bucket at all -- public_access_block stays OMITTED (a real,
    # confirmed "this bucket has no explicit Block Public Access
    # configuration in this Terraform" fact), never fabricated as all-
    # True (a false PASS) or all-False (a false FAIL). NG-AWS-S3-001
    # correctly evaluates NOT_EVALUATED for this resource, exactly the
    # honest outcome for genuinely missing data.
    return {
        "provider": "aws",
        "resource_type": "s3_bucket",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_s3_bucket.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Security group ingress rules (NG-AWS-EC2-001/002 and any other
# security_group-targeted control) -- both the classic inline `ingress {}`
# block AND the newer, decomposed aws_vpc_security_group_ingress_rule
# resource (AWS provider v5+), merged into the same ingress_rules list.
# ---------------------------------------------------------------------------

def _normalize_ingress_block(block: dict[str, Any]) -> dict[str, Any]:
    cidr_blocks = block.get("cidr_blocks") or []
    return {
        "protocol": block.get("protocol"),
        "from_port": block.get("from_port"),
        "to_port": block.get("to_port"),
        "sources": [{"type": "ipv4", "value": cidr} for cidr in cidr_blocks],
    }


def _find_standalone_ingress_rules(
    sg_key: ResourceKey, all_resources: dict[ResourceKey, dict[str, Any]],
) -> list[dict[str, Any]]:
    """`aws_vpc_security_group_ingress_rule` resources (the newer,
    decomposed AWS provider v5+ shape) referencing this security group
    via `security_group_id` -- confirmed real argument names
    (`security_group_id`/`cidr_ipv4`/`ip_protocol`/`from_port`/`to_port`)
    against the AWS provider's own current docs before writing this,
    not guessed. Only a resource REFERENCE to this same-parse security
    group is ever resolvable here -- unlike the classic resource's own
    `ingress {}` block, Terraform never exposes a security group's
    eventual real `sg-xxxx` id statically, so a literal `security_group_id`
    string can never be correlated back to a Terraform resource name;
    such a rule (referencing an externally-managed or data-sourced
    security group) is silently skipped, a real, disclosed gap.
    `cidr_ipv6`/`prefix_list_id`/`referenced_security_group_id` sources
    are not mapped either -- only `cidr_ipv4`, matching the ONLY source
    type NG-AWS-EC2-001/002's own real matching logic ever inspects
    (confirmed by reading controls/aws/ec2/_security_group_rules.py
    directly)."""
    _, sg_name = sg_key
    rules = []
    for (resource_type, _name), body in all_resources.items():
        if resource_type != "aws_vpc_security_group_ingress_rule":
            continue
        ref = resolve_reference(body.get("security_group_id"))
        if ref is None or ref[0] != "aws_security_group" or ref[1] != sg_name:
            continue
        cidr = body.get("cidr_ipv4")
        rules.append({
            "protocol": body.get("ip_protocol"),
            "from_port": body.get("from_port"),
            "to_port": body.get("to_port"),
            "sources": [{"type": "ipv4", "value": cidr}] if cidr else [],
        })
    return rules


def _map_security_group(
    key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]],
) -> dict[str, Any]:
    ingress_blocks = body.get("ingress") or []
    if isinstance(ingress_blocks, dict):  # a single ingress {} block parses as a bare dict, not a list
        ingress_blocks = [ingress_blocks]
    rules = [_normalize_ingress_block(b) for b in ingress_blocks]
    rules.extend(_find_standalone_ingress_rules(key, all_resources))
    return {
        "provider": "aws",
        "resource_type": "security_group",
        "configuration": {"ingress_rules": rules},
        "tags": body.get("tags") or {},
        "identifier": f"aws_security_group.{key[1]}",
    }


# ---------------------------------------------------------------------------
# RDS (NG-AWS-RDS-001/002) -- both real, confirmed Terraform defaults
# ("Default is false if not specified" for both, fetched live from the
# AWS provider's own current docs, not assumed).
# ---------------------------------------------------------------------------

def _map_rds_instance(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "rds_instance",
        "configuration": {
            "publicly_accessible": bool(body.get("publicly_accessible", False)),
            "storage_encrypted": bool(body.get("storage_encrypted", False)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_db_instance.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Load balancer (NG-AWS-ELB-001..007). Config shape confirmed against
# controls/aws/elb/*.py: `scheme` ('internet-facing' | 'internal'), `type`
# ('application'|'network'|'gateway'), `deletion_protection_enabled` (bool),
# `access_logs_enabled` (bool). All four Terraform defaults confirmed
# against the AWS provider's own aws_lb docs: `internal` defaults false ->
# 'internet-facing'; `load_balancer_type` defaults 'application';
# `enable_deletion_protection` defaults false; the `access_logs {}` block is
# absent by default and its own `enabled` defaults false. Listener-level
# checks (ELB-005 HTTP redirect) and WAF association (ELB-007) need separate
# aws_lb_listener / aws_wafv2_web_acl_association resources not correlated
# here -- those fields are OMITTED (a real gap, not fabricated), so their
# controls read NOT_EVALUATED rather than a false verdict.
# ---------------------------------------------------------------------------

def _access_logs_enabled(body: dict[str, Any]) -> bool:
    block = body.get("access_logs")
    if isinstance(block, list):
        block = block[0] if block else None
    if not isinstance(block, dict):
        return False
    return bool(block.get("enabled", False))


def _map_load_balancer(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "load_balancer",
        "configuration": {
            "scheme": "internal" if bool(body.get("internal", False)) else "internet-facing",
            "type": body.get("load_balancer_type", "application"),
            "deletion_protection_enabled": bool(body.get("enable_deletion_protection", False)),
            "access_logs_enabled": _access_logs_enabled(body),
        },
        "tags": body.get("tags") or {},
        # key[0] (aws_lb or its aws_alb alias) so the identifier reflects
        # how the resource was actually declared.
        "identifier": f"{key[0]}.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EKS cluster (NG-AWS-EKS-001..005). Confirmed against controls/aws/eks/*.py:
# endpoint_public_access / endpoint_private_access (bool), enabled_log_types
# (list of api/audit/authenticator/controllerManager/scheduler),
# secrets_encryption_enabled (bool -> an encryption_config covering
# "secrets"), version (string, omitted if absent). AWS provider documented
# defaults: vpc_config.endpoint_public_access = true, endpoint_private_access
# = false (real data, included); enabled_cluster_log_types absent -> [];
# no encryption_config -> secrets not encrypted.
# ---------------------------------------------------------------------------

def _first_block(body: dict[str, Any], name: str) -> Optional[dict[str, Any]]:
    """A nested Terraform block parses as either a single dict or a
    one-element list (hcl2 varies) -- normalize to the first dict, or None."""
    block = body.get(name)
    if isinstance(block, list):
        block = block[0] if block else None
    return block if isinstance(block, dict) else None


def _map_eks_cluster(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "enabled_log_types": body.get("enabled_cluster_log_types") or [],
    }
    vpc = _first_block(body, "vpc_config")
    if vpc is not None:
        configuration["endpoint_public_access"] = bool(vpc.get("endpoint_public_access", True))
        configuration["endpoint_private_access"] = bool(vpc.get("endpoint_private_access", False))
    else:
        # No vpc_config block at all is invalid Terraform for aws_eks_cluster
        # (it's required), but if absent we fall back to the provider's own
        # documented defaults rather than omitting -- these are real defaults.
        configuration["endpoint_public_access"] = True
        configuration["endpoint_private_access"] = False
    enc = _first_block(body, "encryption_config")
    if enc is not None:
        resources = enc.get("resources") or []
        configuration["secrets_encryption_enabled"] = "secrets" in resources
    else:
        configuration["secrets_encryption_enabled"] = False
    version = body.get("version")
    if version is not None:
        configuration["version"] = str(version)
    return {
        "provider": "aws",
        "resource_type": "eks_cluster",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_eks_cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Lambda function (NG-AWS-AWSLAMBDA-002/003/004/005 -- the statically-
# knowable subset). Confirmed against controls/aws/awslambda/*.py:
#  - runtime (AWSLAMBDA-003, checked vs a deprecated-runtimes list): emit the
#    `runtime` string; a container-image function has none -> omit.
#  - xray_tracing_enabled (AWSLAMBDA-004, require_flag): tracing_config block
#    with mode == "Active" (no block -> tracing off). "Active" is the
#    unambiguous "tracing enabled" state; anything else -> false, which errs
#    toward flagging, never a false PASS.
#  - env_encrypted_with_cmk (AWSLAMBDA-005, require_flag): a customer
#    `kms_key_arn` set on the function.
#  - function_url_auth_none (AWSLAMBDA-002, forbid_flag): correlated from a
#    separate aws_lambda_function_url resource whose authorization_type is
#    "NONE" -- True only for a genuinely unauthenticated URL; no URL resource
#    referencing this function -> False (no unauthenticated URL exists).
#  - resource_policy_allows_public (AWSLAMBDA-001) and secrets_detected
#    (AWSLAMBDA-006, the Engine's own env-var scan) are OMITTED (a
#    aws_lambda_permission principal analysis / a secret scan this mapper
#    doesn't reproduce) -> those two read NOT_EVALUATED.
# ---------------------------------------------------------------------------

def _function_url_auth_none(fn_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), body in all_resources.items():
        if resource_type != "aws_lambda_function_url":
            continue
        ref = resolve_reference(body.get("function_name"))
        matches_ref = ref is not None and ref[0] == "aws_lambda_function" and ref[1] == fn_name
        matches_literal = body.get("function_name") == fn_name
        if matches_ref or matches_literal:
            if str(body.get("authorization_type")).upper() == "NONE":
                return True
    return False


def _map_lambda_function(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "env_encrypted_with_cmk": bool(body.get("kms_key_arn")),
        "function_url_auth_none": _function_url_auth_none(key[1], all_resources),
    }
    runtime = body.get("runtime")
    if runtime is not None:
        configuration["runtime"] = runtime
    tracing = _first_block(body, "tracing_config")
    configuration["xray_tracing_enabled"] = bool(tracing is not None and tracing.get("mode") == "Active")
    return {
        "provider": "aws",
        "resource_type": "lambda_function",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_lambda_function.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EC2 instance (NG-AWS-EC2-010/011/023 -- the statically-knowable subset of
# its 6 controls). Confirmed against controls/aws/ec2/*.py:
#  - public_ip_address: forbid_flag (truthy = FAIL). From IaC we know INTENT,
#    not the assigned IP -- `associate_public_ip_address=true` => it will get
#    one (emit True, a truthful flag, not a fabricated IP); `=false` => none
#    (False); ABSENT => depends on the subnet's map_public_ip_on_launch,
#    genuinely unknowable from the instance alone => OMITTED (NOT_EVALUATED).
#  - metadata_options: EC2-011 reads metadata_options.http_tokens=="required".
#    Passed through as a dict. Absent block => http_tokens defaults to
#    "optional" per the AWS provider's own docs (a real documented default,
#    so IMDSv1-allowed is included as data, not omitted -> EC2-011 FAILs).
#  - detailed_monitoring_enabled: require_flag, from `monitoring` (default
#    false).
#  - ssm_managed (runtime registration) and secrets_detected (the Engine's
#    own user_data scan) are NOT knowable from static IaC => OMITTED, never
#    fabricated. Their controls read NOT_EVALUATED.
# ---------------------------------------------------------------------------

def _map_ec2_instance(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "detailed_monitoring_enabled": bool(body.get("monitoring", False)),
    }
    if "associate_public_ip_address" in body:
        configuration["public_ip_address"] = bool(body.get("associate_public_ip_address"))
    meta = _first_block(body, "metadata_options")
    if meta is not None:
        md: dict[str, Any] = {}
        for k in ("http_tokens", "http_endpoint", "http_put_response_hop_limit"):
            if k in meta:
                md[k] = meta[k]
        md.setdefault("http_tokens", "optional")  # provider default within a block
        configuration["metadata_options"] = md
    else:
        configuration["metadata_options"] = {"http_tokens": "optional"}
    return {
        "provider": "aws",
        "resource_type": "ec2_instance",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_instance.{key[1]}",
    }


# ---------------------------------------------------------------------------
# DynamoDB table (NG-AWS-DYNAMODB-001..003). deletion_protection_enabled
# (bool), pitr_enabled (point_in_time_recovery block), encrypted_with_cmk
# (a server_side_encryption block that is enabled AND names a customer
# kms_key_arn -- an SSE block with no kms_key_arn is the AWS-managed key,
# NOT a CMK; the control is specifically about a customer-managed key,
# confirmed against controls/aws/dynamodb/ng_aws_dynamodb_003.py). All
# defaults (deletion protection false, no PITR block -> false, no SSE
# block -> AWS-owned key, not CMK) confirmed against the AWS provider docs.
# ---------------------------------------------------------------------------

def _map_dynamodb_table(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    pitr = _first_block(body, "point_in_time_recovery")
    sse = _first_block(body, "server_side_encryption")
    encrypted_with_cmk = bool(
        sse is not None and sse.get("enabled", False) and sse.get("kms_key_arn")
    )
    return {
        "provider": "aws",
        "resource_type": "dynamodb_table",
        "configuration": {
            "deletion_protection_enabled": bool(body.get("deletion_protection_enabled", False)),
            "pitr_enabled": bool(pitr is not None and pitr.get("enabled", False)),
            "encrypted_with_cmk": encrypted_with_cmk,
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_dynamodb_table.{key[1]}",
    }


# ---------------------------------------------------------------------------
# ECR repository (NG-AWS-ECR-001/002/004; 003 policy_allows_public omitted).
# scan_on_push_enabled (image_scanning_configuration block), tag_immutability
# _enabled (image_tag_mutability == "IMMUTABLE", default "MUTABLE"),
# lifecycle_policy_enabled (a separate aws_ecr_lifecycle_policy resource
# referencing this repo). policy_allows_public (aws_ecr_repository_policy
# principal analysis) omitted -> NG-AWS-ECR-003 NOT_EVALUATED.
# ---------------------------------------------------------------------------

def _ecr_has_lifecycle_policy(repo_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), body in all_resources.items():
        if resource_type != "aws_ecr_lifecycle_policy":
            continue
        ref = resolve_reference(body.get("repository"))
        if (ref is not None and ref[0] == "aws_ecr_repository" and ref[1] == repo_name) \
                or body.get("repository") == repo_name:
            return True
    return False


def _map_ecr_repository(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    scan = _first_block(body, "image_scanning_configuration")
    return {
        "provider": "aws",
        "resource_type": "ecr_repository",
        "configuration": {
            "scan_on_push_enabled": bool(scan is not None and scan.get("scan_on_push", False)),
            "tag_immutability_enabled": body.get("image_tag_mutability", "MUTABLE") == "IMMUTABLE",
            "lifecycle_policy_enabled": _ecr_has_lifecycle_policy(key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_ecr_repository.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EFS file system (NG-AWS-EFS-001/002; 003 policy_allows_anonymous_access
# omitted). encrypted (bool, default false); backup_enabled (a separate
# aws_efs_backup_policy resource with backup_policy.status == "ENABLED").
# policy_allows_anonymous_access (aws_efs_file_system_policy principal
# analysis) omitted -> NG-AWS-EFS-003 NOT_EVALUATED.
# ---------------------------------------------------------------------------

def _efs_backup_enabled(fs_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), body in all_resources.items():
        if resource_type != "aws_efs_backup_policy":
            continue
        ref = resolve_reference(body.get("file_system_id"))
        if not ((ref is not None and ref[0] == "aws_efs_file_system" and ref[1] == fs_name)
                or body.get("file_system_id") == fs_name):
            continue
        policy = _first_block(body, "backup_policy")
        if policy is not None and str(policy.get("status")).upper() == "ENABLED":
            return True
    return False


def _map_efs_file_system(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "efs_file_system",
        "configuration": {
            "encrypted": bool(body.get("encrypted", False)),
            "backup_enabled": _efs_backup_enabled(key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_efs_file_system.{key[1]}",
    }


# ---------------------------------------------------------------------------
# ElastiCache (NG-AWS-ELASTICACHE-001/002/003). at_rest_encryption_enabled /
# transit_encryption_enabled (Redis, on the replication group; default
# false) and auto_minor_version_upgrade (default true). A bare
# aws_elasticache_cluster (memcached/legacy) carries no encryption fields --
# only auto_minor_version_upgrade is emitted there, the two encryption keys
# omitted (NOT_EVALUATED), never fabricated.
# ---------------------------------------------------------------------------

def _map_elasticache_replication_group(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "elasticache_cluster",
        "configuration": {
            "at_rest_encryption_enabled": bool(body.get("at_rest_encryption_enabled", False)),
            "transit_encryption_enabled": bool(body.get("transit_encryption_enabled", False)),
            "auto_minor_version_upgrade": bool(body.get("auto_minor_version_upgrade", True)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_elasticache_replication_group.{key[1]}",
    }


def _map_elasticache_cluster(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "elasticache_cluster",
        "configuration": {
            "auto_minor_version_upgrade": bool(body.get("auto_minor_version_upgrade", True)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_elasticache_cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Redshift cluster (NG-AWS-REDSHIFT-002/003; 001 publicly_accessible only
# when explicitly set). encrypted (bool, default false); audit_logging_enabled
# (the inline `logging { enable = true }` block). publicly_accessible has a
# version-dependent provider default (historically true, docs say false --
# confirmed ambiguous), so it is OMITTED unless explicitly set -> a genuine
# NOT_EVALUATED rather than a guessed default that could be a false PASS/FAIL.
# ---------------------------------------------------------------------------

def _map_redshift_cluster(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    logging = _first_block(body, "logging")
    configuration: dict[str, Any] = {
        "encrypted": bool(body.get("encrypted", False)),
        "audit_logging_enabled": bool(logging is not None and logging.get("enable", False)),
    }
    if "publicly_accessible" in body:
        configuration["publicly_accessible"] = bool(body.get("publicly_accessible"))
    return {
        "provider": "aws",
        "resource_type": "redshift_cluster",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_redshift_cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# CloudFront distribution (NG-AWS-CLOUDFRONT-001/002/003). Matches the
# collector's own semantics exactly:
#   viewer_https_enforced  = no cache behavior (default or ordered) allows
#                            "allow-all" viewer_protocol_policy
#   minimum_tls_1_2        = viewer_certificate.minimum_protocol_version
#                            >= "TLSv1.2" (string compare, same as the
#                            collector); a default cert / absent value -> False
#   access_logging_enabled = a logging_config block is present
# NG-AWS-CLOUDFRONT-004 (origin_access_controlled) is DELIBERATELY OMITTED
# (-> NOT_EVALUATED): the collector detects an S3 origin by the presence of
# an S3OriginConfig on the live API object, but Terraform's modern
# Origin Access Control pattern routinely declares an S3 origin with neither
# an s3_origin_config nor a custom_origin_config block, so "is this an S3
# origin, and is it access-controlled" is not reliably derivable from the
# HCL -- and this is an all()-across-origins boolean where one misclassified
# origin flips the whole verdict, i.e. a real false-PASS risk. Honest
# NOT_EVALUATED beats a guessed pass here.
# ---------------------------------------------------------------------------

def _cloudfront_cache_behaviors(body: dict[str, Any]) -> list[dict[str, Any]]:
    behaviors: list[dict[str, Any]] = []
    default = _first_block(body, "default_cache_behavior")
    if default is not None:
        behaviors.append(default)
    ordered = body.get("ordered_cache_behavior")
    if isinstance(ordered, list):
        behaviors.extend(b for b in ordered if isinstance(b, dict))
    elif isinstance(ordered, dict):
        behaviors.append(ordered)
    return behaviors


def _map_cloudfront_distribution(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    behaviors = _cloudfront_cache_behaviors(body)
    viewer_https = not any(str(b.get("viewer_protocol_policy") or "") == "allow-all" for b in behaviors)
    vc = _first_block(body, "viewer_certificate")
    min_tls = bool(vc is not None and str(vc.get("minimum_protocol_version") or "") >= "TLSv1.2")
    return {
        "provider": "aws",
        "resource_type": "cloudfront_distribution",
        "configuration": {
            "viewer_https_enforced": viewer_https,
            "minimum_tls_1_2": min_tls,
            "access_logging_enabled": _first_block(body, "logging_config") is not None,
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_cloudfront_distribution.{key[1]}",
    }


# ---------------------------------------------------------------------------
# IAM account password policy (NG-AWS-IAM-008/009/010). Direct attributes on
# aws_iam_account_password_policy. TF defaults confirmed: minimum_password_
# length 6, require_* false, max_password_age 0 (no expiry). TF spells two of
# them require_lowercase_characters / require_uppercase_characters; the
# controls read require_lowercase / require_uppercase. No CloudFormation
# equivalent (the account password policy is not a CFN resource type).
# ---------------------------------------------------------------------------

def _map_iam_password_policy(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "iam_password_policy",
        "configuration": {
            "minimum_password_length": int(body.get("minimum_password_length", 6)),
            "require_symbols": bool(body.get("require_symbols", False)),
            "require_numbers": bool(body.get("require_numbers", False)),
            "require_lowercase": bool(body.get("require_lowercase_characters", False)),
            "require_uppercase": bool(body.get("require_uppercase_characters", False)),
            "max_password_age_days": int(body.get("max_password_age", 0)),
        },
        "tags": {},  # the account password policy carries no tags
        "identifier": f"aws_iam_account_password_policy.{key[1]}",
    }


# ---------------------------------------------------------------------------
# SNS topic (NG-AWS-SNS-001; 002 policy_allows_public omitted). kms_encryption
# _enabled = a kms_master_key_id is set. SQS queue (NG-AWS-SQS-001; 002
# omitted). encryption_enabled = a kms_master_key_id OR sqs_managed_sse.
# ---------------------------------------------------------------------------

def _map_sns_topic(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "sns_topic",
        "configuration": {"kms_encryption_enabled": bool(body.get("kms_master_key_id"))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_sns_topic.{key[1]}",
    }


def _map_sqs_queue(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    encrypted = bool(body.get("kms_master_key_id")) or bool(body.get("sqs_managed_sse_enabled", False))
    return {
        "provider": "aws",
        "resource_type": "sqs_queue",
        "configuration": {"encryption_enabled": encrypted},
        "tags": body.get("tags") or {},
        "identifier": f"aws_sqs_queue.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Secrets Manager secret (NG-AWS-SECRETSMANAGER-001/002). encrypted_with_cmk
# = a customer kms_key_id is set; rotation_enabled correlated from a separate
# aws_secretsmanager_secret_rotation resource (TF). CFN has no inline rotation
# on the secret (AWS::SecretsManager::RotationSchedule is separate), so CFN
# omits rotation_enabled (NOT_EVALUATED).
# ---------------------------------------------------------------------------

def _secret_rotation_enabled(secret_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), body in all_resources.items():
        if resource_type != "aws_secretsmanager_secret_rotation":
            continue
        ref = resolve_reference(body.get("secret_id"))
        if (ref is not None and ref[0] == "aws_secretsmanager_secret" and ref[1] == secret_name) \
                or body.get("secret_id") == secret_name:
            return True
    return False


def _map_secretsmanager_secret(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "secretsmanager_secret",
        "configuration": {
            "encrypted_with_cmk": bool(body.get("kms_key_id")),
            "rotation_enabled": _secret_rotation_enabled(key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_secretsmanager_secret.{key[1]}",
    }


# ---------------------------------------------------------------------------
# ACM certificate (NG-AWS-ACM-002; 001 days_to_expiry omitted -- a runtime
# value the certificate doesn't have at IaC time). transparency_logging_enabled
# = the options.certificate_transparency_logging_preference is not "DISABLED"
# (AWS default is ENABLED, so an absent options block == enabled).
# ---------------------------------------------------------------------------

def _map_acm_certificate(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    options = _first_block(body, "options")
    if options is not None and "certificate_transparency_logging_preference" in options:
        transparency = str(options.get("certificate_transparency_logging_preference")).upper() != "DISABLED"
    else:
        transparency = True  # AWS default is ENABLED when unspecified
    return {
        "provider": "aws",
        "resource_type": "acm_certificate",
        "configuration": {"transparency_logging_enabled": transparency},
        "tags": body.get("tags") or {},
        "identifier": f"aws_acm_certificate.{key[1]}",
    }


# ---------------------------------------------------------------------------
# SageMaker notebook instance (NG-AWS-SAGEMAKER-001/002/003). root_access /
# direct_internet_access are "Enabled"/"Disabled" strings (both default
# "Enabled"); encrypted_with_kms = a kms_key_id is set.
# ---------------------------------------------------------------------------

def _map_sagemaker_notebook_instance(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "sagemaker_notebook_instance",
        "configuration": {
            "root_access_enabled": str(body.get("root_access", "Enabled")) == "Enabled",
            "direct_internet_access_enabled": str(body.get("direct_internet_access", "Enabled")) == "Enabled",
            "encrypted_with_kms": bool(body.get("kms_key_id")),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_sagemaker_notebook_instance.{key[1]}",
    }


# ---------------------------------------------------------------------------
# DocumentDB cluster (NG-AWS-DOCDB-001/002). storage_encrypted (default
# false); backup_retention_period (int, default 1).
# ---------------------------------------------------------------------------

def _map_docdb_cluster(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "docdb_cluster",
        "configuration": {
            "storage_encrypted": bool(body.get("storage_encrypted", False)),
            "backup_retention_period": int(body.get("backup_retention_period", 1)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_docdb_cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# WAFv2 Web ACL (NG-AWS-WAF-001/002). has_rules = at least one rule block;
# logging_enabled correlated from a separate aws_wafv2_web_acl_logging_
# configuration referencing this ACL (default false). CFN omits
# logging_enabled (AWS::WAFv2::LoggingConfiguration is a separate resource,
# no cross-resource view there).
# ---------------------------------------------------------------------------

def _waf_logging_enabled(acl_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), lc in all_resources.items():
        if resource_type != "aws_wafv2_web_acl_logging_configuration":
            continue
        ref = resolve_reference(lc.get("resource_arn"))
        if ref is not None and ref[0] == "aws_wafv2_web_acl" and ref[1] == acl_name:
            return True
    return False


def _map_waf_web_acl(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    rule = body.get("rule")
    if isinstance(rule, list):
        has_rules = len([r for r in rule if isinstance(r, dict)]) > 0
    else:
        has_rules = isinstance(rule, dict)
    return {
        "provider": "aws",
        "resource_type": "waf_web_acl",
        "configuration": {
            "has_rules": has_rules,
            "logging_enabled": _waf_logging_enabled(key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_wafv2_web_acl.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Athena workgroup (NG-AWS-ATHENA-001/002). results_encryption_enabled = a
# configuration.result_configuration.encryption_configuration is present.
# enforce_workgroup_configuration: Terraform's own attribute default is true
# (per its provider docs), so absent == true here. (The CloudFormation
# mapper uses the AWS API's own default of false -- a real, documented
# divergence between the two.)
# ---------------------------------------------------------------------------

def _map_athena_workgroup(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration = _first_block(body, "configuration")
    if configuration is not None:
        enforce = bool(configuration.get("enforce_workgroup_configuration", True))
        result_cfg = _first_block(configuration, "result_configuration")
        enc = result_cfg is not None and _first_block(result_cfg, "encryption_configuration") is not None
    else:
        enforce = True  # Terraform's documented attribute default
        enc = False
    return {
        "provider": "aws",
        "resource_type": "athena_workgroup",
        "configuration": {
            "results_encryption_enabled": enc,
            "enforce_workgroup_configuration": enforce,
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_athena_workgroup.{key[1]}",
    }


# ===========================================================================
# Azure (Terraform azurerm provider). provider="azure". Defaults confirmed
# against the azurerm provider's own current docs (fetched live), never
# guessed; a version-ambiguous default (one that has changed across provider
# major versions and could flip a verdict) is OMITTED when the attribute is
# absent, exactly like the AWS-side redshift publicly_accessible case.
# ===========================================================================

# ---------------------------------------------------------------------------
# Redis cache (NG-AZURE-REDIS-001/002/003). azurerm defaults (current docs):
# non_ssl_port_enabled false (stable), public_network_access_enabled true
# (stable). minimum_tls_version's default changed 1.0 -> 1.2 across provider
# versions, so minimum_tls_1_2 is OMITTED when the attribute is absent
# (would be a false PASS on an older provider).
# ---------------------------------------------------------------------------

def _map_azure_redis_cache(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        # both the current (non_ssl_port_enabled) and legacy
        # (enable_non_ssl_port) attribute names, both default false
        "non_ssl_port_enabled": bool(
            body.get("non_ssl_port_enabled", body.get("enable_non_ssl_port", False))
        ),
        "public_network_access_enabled": bool(body.get("public_network_access_enabled", True)),
    }
    if "minimum_tls_version" in body:
        configuration["minimum_tls_1_2"] = str(body.get("minimum_tls_version") or "") >= "1.2"
    return {
        "provider": "azure",
        "resource_type": "redis_cache",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_redis_cache.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Cosmos DB account (NG-AZURE-COSMOSDB-001/002/003/004). Collector semantics:
# network_access_restricted = public access disabled OR any IP/VNet rule
# narrows it; encrypted_with_cmk = a key_vault_key_id is set; local_auth_
# disabled = NOT local_authentication_enabled (default true -> not disabled);
# continuous_backup_enabled = a backup block of type "Continuous".
# ---------------------------------------------------------------------------

def _map_azure_cosmosdb_account(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    public_enabled = bool(body.get("public_network_access_enabled", True))
    vnet_filter = bool(body.get("is_virtual_network_filter_enabled", False))
    ip_filter = bool(body.get("ip_range_filter"))
    vnet_rules = bool(body.get("virtual_network_rule"))
    backup = _first_block(body, "backup")
    continuous = backup is not None and str(backup.get("type") or "").lower() == "continuous"
    return {
        "provider": "azure",
        "resource_type": "cosmosdb_account",
        "configuration": {
            "network_access_restricted": (not public_enabled) or vnet_filter or ip_filter or vnet_rules,
            "local_auth_disabled": not bool(body.get("local_authentication_enabled", True)),
            "encrypted_with_cmk": bool(body.get("key_vault_key_id")),
            "continuous_backup_enabled": continuous,
        },
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_cosmosdb_account.{key[1]}",
    }


# ---------------------------------------------------------------------------
# PostgreSQL / MySQL Flexible Server (NG-AZURE-POSTGRESQL/MYSQL-001..004).
# nimbus_app models these as the flexible-server generation. ssl_enforced
# comes from the require_secure_transport server parameter -- a separate
# *_flexible_server_configuration resource; that parameter defaults ON for
# flexible servers, so absent-config == enforced (a confirmed, stable
# default, not a guess). public_network_access_enabled defaults true, but a
# server with a delegated_subnet_id is VNet-integrated and therefore private
# (avoids a false FAIL on a legitimately-private server). geo_redundant_
# backup defaults false; backup_retention_days defaults 7.
# ---------------------------------------------------------------------------

def _flexible_db_ssl_enforced(server_tf_type: str, server_tf_name: str, config_tf_type: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), config in all_resources.items():
        if resource_type != config_tf_type:
            continue
        if str(config.get("name") or "") != "require_secure_transport":
            continue
        ref = resolve_reference(config.get("server_id"))
        if ref is not None and ref[0] == server_tf_type and ref[1] == server_tf_name:
            return str(config.get("value") or "").lower() == "on"
    return True  # require_secure_transport defaults ON for flexible servers


def _map_flexible_db(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]], *, resource_type: str, tf_type: str, config_tf_type: str) -> dict[str, Any]:
    if "public_network_access_enabled" in body:
        public = bool(body["public_network_access_enabled"])
    elif body.get("delegated_subnet_id"):
        public = False  # VNet-integrated -> private
    else:
        public = True
    return {
        "provider": "azure",
        "resource_type": resource_type,
        "configuration": {
            "ssl_enforced": _flexible_db_ssl_enforced(tf_type, key[1], config_tf_type, all_resources),
            "public_network_access_enabled": public,
            "geo_redundant_backup_enabled": bool(body.get("geo_redundant_backup_enabled", False)),
            "backup_retention_days": int(body.get("backup_retention_days", 7)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"{tf_type}.{key[1]}",
    }


def _map_azure_postgresql_server(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return _map_flexible_db(
        key, body, all_resources, resource_type="postgresql_server",
        tf_type="azurerm_postgresql_flexible_server",
        config_tf_type="azurerm_postgresql_flexible_server_configuration",
    )


def _map_azure_mysql_server(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return _map_flexible_db(
        key, body, all_resources, resource_type="mysql_server",
        tf_type="azurerm_mysql_flexible_server",
        config_tf_type="azurerm_mysql_flexible_server_configuration",
    )


# ---------------------------------------------------------------------------
# Key Vault (NG-AZURE-KEYVAULT-002/003/004/005/007). purge_protection
# (default false), public_network_access (default true), rbac_authorization
# (default false; both current rbac_authorization_enabled and legacy
# enable_rbac_authorization), soft_delete_retention_days (default 90).
# logging_enabled correlates an azurerm_monitor_diagnostic_setting targeting
# the vault with at least one enabled log. access_policies (NG-AZURE-
# KEYVAULT-008, custom) is OMITTED (its control-side shape isn't a simple
# flag) -> NOT_EVALUATED rather than a fabricated verdict.
# ---------------------------------------------------------------------------

def _diagnostic_setting_has_enabled_log(target_tf_type: str, target_tf_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), ds in all_resources.items():
        if resource_type != "azurerm_monitor_diagnostic_setting":
            continue
        ref = resolve_reference(ds.get("target_resource_id"))
        if not (ref is not None and ref[0] == target_tf_type and ref[1] == target_tf_name):
            continue
        # newer azurerm: any enabled_log {} block means that log is on
        if _as_block_list(ds.get("enabled_log")):
            return True
        # legacy: a log {} block with enabled = true
        for log in _as_block_list(ds.get("log")):
            if bool(log.get("enabled", False)):
                return True
    return False


def _map_azure_key_vault(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    rbac = body.get("rbac_authorization_enabled", body.get("enable_rbac_authorization", False))
    return {
        "provider": "azure",
        "resource_type": "key_vault",
        "configuration": {
            "purge_protection_enabled": bool(body.get("purge_protection_enabled", False)),
            "public_network_access_enabled": bool(body.get("public_network_access_enabled", True)),
            "rbac_authorization_enabled": bool(rbac),
            "soft_delete_retention_days": int(body.get("soft_delete_retention_days", 90)),
            "logging_enabled": _diagnostic_setting_has_enabled_log("azurerm_key_vault", key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_key_vault.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Service Bus / Event Hub / Automation / Synapse / Log Analytics. All
# public_network_access_enabled default true; local-auth attribute names
# differ per resource (confirmed live). minimum_tls / retention defaults are
# version-ambiguous -> omitted when absent.
# ---------------------------------------------------------------------------

def _map_azure_service_bus_namespace(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "local_auth_disabled": not bool(body.get("local_auth_enabled", True)),
        "public_network_access_enabled": bool(body.get("public_network_access_enabled", True)),
    }
    if "minimum_tls_version" in body:
        configuration["minimum_tls_1_2"] = str(body.get("minimum_tls_version") or "") >= "1.2"
    return {
        "provider": "azure", "resource_type": "service_bus_namespace",
        "configuration": configuration, "tags": body.get("tags") or {},
        "identifier": f"azurerm_servicebus_namespace.{key[1]}",
    }


def _map_azure_event_hub_namespace(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "azure", "resource_type": "event_hub_namespace",
        "configuration": {
            "local_auth_disabled": not bool(body.get("local_authentication_enabled", True)),
            "public_network_access_enabled": bool(body.get("public_network_access_enabled", True)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_eventhub_namespace.{key[1]}",
    }


def _map_azure_automation_account(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "azure", "resource_type": "automation_account",
        "configuration": {
            "local_auth_disabled": not bool(body.get("local_authentication_enabled", True)),
            "public_network_access_enabled": bool(body.get("public_network_access_enabled", True)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_automation_account.{key[1]}",
    }


def _map_azure_synapse_workspace(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "azure", "resource_type": "synapse_workspace",
        "configuration": {"public_network_access_enabled": bool(body.get("public_network_access_enabled", True))},
        "tags": body.get("tags") or {},
        "identifier": f"azurerm_synapse_workspace.{key[1]}",
    }


def _map_azure_log_analytics_workspace(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {}
    if "retention_in_days" in body:
        configuration["retention_days"] = int(body["retention_in_days"])
    return {
        "provider": "azure", "resource_type": "log_analytics_workspace",
        "configuration": configuration, "tags": body.get("tags") or {},
        "identifier": f"azurerm_log_analytics_workspace.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Network ACL (NG-AWS-EC2-024). The control reads configuration.entries as
# the flattened rule list from describe_network_acls, and matches protocol
# by the AWS NUMERIC string ("6"=TCP, "-1"=all) -- NOT the name -- so this
# mapper normalizes Terraform's own protocol name/number to the numeric
# form. Entries come from both inline ingress/egress blocks and standalone
# aws_network_acl_rule resources referencing this ACL. NO CloudFormation
# mapper: AWS::EC2::NetworkAclEntry entries are separate resources with no
# cross-resource view in the CFN mapper, and emitting an empty entries list
# would be a false PASS -- so a CFN network ACL is left unmapped (honest)
# rather than fabricated as having no rules.
# ---------------------------------------------------------------------------

_NACL_PROTOCOL_NUMBERS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "58": "58", "all": "-1", "-1": "-1"}


def _as_block_list(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [b for b in raw if isinstance(b, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def _nacl_protocol(value: Any) -> Optional[str]:
    if value is None:
        return None
    return _NACL_PROTOCOL_NUMBERS.get(str(value).lower(), str(value))


def _nacl_entry_from_block(block: dict[str, Any], egress: bool) -> dict[str, Any]:
    return {
        "rule_number": block.get("rule_no"),
        "egress": egress,
        "protocol": _nacl_protocol(block.get("protocol")),
        "rule_action": block.get("action"),
        "cidr_block": block.get("cidr_block") or block.get("ipv6_cidr_block"),
        "from_port": block.get("from_port"),
        "to_port": block.get("to_port"),
    }


def _nacl_entry_from_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_number": rule.get("rule_number"),
        "egress": bool(rule.get("egress", False)),
        "protocol": _nacl_protocol(rule.get("protocol")),
        "rule_action": rule.get("rule_action"),
        "cidr_block": rule.get("cidr_block") or rule.get("ipv6_cidr_block"),
        "from_port": rule.get("from_port"),
        "to_port": rule.get("to_port"),
    }


def _map_network_acl(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    entries = [_nacl_entry_from_block(b, False) for b in _as_block_list(body.get("ingress"))]
    entries.extend(_nacl_entry_from_block(b, True) for b in _as_block_list(body.get("egress")))
    for (resource_type, _name), rule in all_resources.items():
        if resource_type != "aws_network_acl_rule":
            continue
        ref = resolve_reference(rule.get("network_acl_id"))
        if (ref is not None and ref[0] == "aws_network_acl" and ref[1] == key[1]) or rule.get("network_acl_id") == key[1]:
            entries.append(_nacl_entry_from_rule(rule))
    return {
        "provider": "aws",
        "resource_type": "network_acl",
        "configuration": {"entries": entries},
        "tags": body.get("tags") or {},
        "identifier": f"aws_network_acl.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Route53 registered domain (NG-AWS-ROUTE53-002): transfer_lock_enabled.
# Terraform's aws_route53domains_registered_domain.transfer_lock defaults to
# true. No CloudFormation resource type exists for a registered domain.
# ---------------------------------------------------------------------------

def _map_route53_domain(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "route53_domain",
        "configuration": {"transfer_lock_enabled": bool(body.get("transfer_lock", True))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_route53domains_registered_domain.{key[1]}",
    }


# ---------------------------------------------------------------------------
# API Gateway stage (NG-AWS-APIGATEWAY-001/002/003).
#   xray_tracing_enabled   = the stage's own xray_tracing_enabled (direct)
#   execution_logging_enabled = an aws_api_gateway_method_settings for this
#       stage sets a logging_level of INFO or ERROR (the collector counts
#       any method-level override, including the "*/*" stage default)
#   waf_attached           = an aws_wafv2_web_acl_association targets this
#       stage
# The latter two are separate Terraform resources correlated back to the
# stage. In CloudFormation, MethodSettings is inline on the stage (so
# execution logging is derivable there), but the WAF association is a
# separate resource -> the CFN mapper omits waf_attached.
# ---------------------------------------------------------------------------

def _apigw_execution_logging_enabled(stage_tf_name: str, stage_name_literal: Any, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), ms in all_resources.items():
        if resource_type != "aws_api_gateway_method_settings":
            continue
        sn = ms.get("stage_name")
        ref = resolve_reference(sn)
        matches_ref = ref is not None and ref[0] == "aws_api_gateway_stage" and ref[1] == stage_tf_name
        matches_literal = isinstance(sn, str) and isinstance(stage_name_literal, str) and sn == stage_name_literal
        if not (matches_ref or matches_literal):
            continue
        settings = _first_block(ms, "settings")
        if settings is not None and str(settings.get("logging_level") or "").upper() in ("INFO", "ERROR"):
            return True
    return False


def _apigw_waf_attached(stage_tf_name: str, all_resources: dict[ResourceKey, dict[str, Any]]) -> bool:
    for (resource_type, _name), assoc in all_resources.items():
        if resource_type != "aws_wafv2_web_acl_association":
            continue
        ref = resolve_reference(assoc.get("resource_arn"))
        if ref is not None and ref[0] == "aws_api_gateway_stage" and ref[1] == stage_tf_name:
            return True
    return False


def _map_api_gateway_stage(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "api_gateway_stage",
        "configuration": {
            "execution_logging_enabled": _apigw_execution_logging_enabled(key[1], body.get("stage_name"), all_resources),
            "xray_tracing_enabled": bool(body.get("xray_tracing_enabled", False)),
            "waf_attached": _apigw_waf_attached(key[1], all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_api_gateway_stage.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Glue Data Catalog encryption settings (NG-AWS-GLUE-001/002).
# ---------------------------------------------------------------------------

def _map_glue_data_catalog(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    settings = _first_block(body, "data_catalog_encryption_settings")
    metadata_enc = False
    conn_pw_enc = False
    if settings is not None:
        at_rest = _first_block(settings, "encryption_at_rest")
        if at_rest is not None:
            mode = str(at_rest.get("catalog_encryption_mode") or "").upper()
            metadata_enc = mode not in ("", "DISABLED")
        conn = _first_block(settings, "connection_password_encryption")
        if conn is not None:
            conn_pw_enc = bool(conn.get("return_connection_password_encrypted", False))
    return {
        "provider": "aws",
        "resource_type": "glue_data_catalog",
        "configuration": {
            "metadata_encryption_enabled": metadata_enc,
            "connection_password_encryption_enabled": conn_pw_enc,
        },
        "tags": {},
        "identifier": f"aws_glue_data_catalog_encryption_settings.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Kinesis stream (NG-AWS-KINESIS-001): encryption_enabled = encryption_type
# is KMS. Firehose delivery stream (NG-AWS-FIREHOSE-001): a
# server_side_encryption block enabled (collector reads the stream's own
# DeliveryStreamEncryptionConfiguration.Status == ENABLED).
# ---------------------------------------------------------------------------

def _map_kinesis_stream(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "kinesis_stream",
        "configuration": {"encryption_enabled": str(body.get("encryption_type") or "").upper() == "KMS"},
        "tags": body.get("tags") or {},
        "identifier": f"aws_kinesis_stream.{key[1]}",
    }


def _map_firehose_delivery_stream(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    sse = _first_block(body, "server_side_encryption")
    enabled = sse is not None and bool(sse.get("enabled", False))
    return {
        "provider": "aws",
        "resource_type": "firehose_delivery_stream",
        "configuration": {"encryption_enabled": enabled},
        "tags": body.get("tags") or {},
        "identifier": f"aws_kinesis_firehose_delivery_stream.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Step Functions state machine (NG-AWS-SFN-001): logging_enabled = a
# logging_configuration block with level != "OFF" (default OFF).
# ---------------------------------------------------------------------------

def _map_sfn_state_machine(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    log = _first_block(body, "logging_configuration")
    enabled = log is not None and str(log.get("level") or "OFF").upper() != "OFF"
    return {
        "provider": "aws",
        "resource_type": "sfn_state_machine",
        "configuration": {"logging_enabled": enabled},
        "tags": body.get("tags") or {},
        "identifier": f"aws_sfn_state_machine.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Backup vault (NG-AWS-BACKUP-002): encrypted_with_cmk = a customer
# kms_key_arn is set (a vault is always encrypted with an AWS-managed key
# by default; the control wants a customer-managed one).
# ---------------------------------------------------------------------------

def _map_backup_vault(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "backup_vault",
        "configuration": {"encrypted_with_cmk": bool(body.get("kms_key_arn"))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_backup_vault.{key[1]}",
    }


# ---------------------------------------------------------------------------
# DMS replication instance (NG-AWS-DMS-001): publicly_accessible, TF/AWS
# default TRUE (a real, confirmed insecure default). MQ broker
# (NG-AWS-MQ-001): publicly_accessible, default false.
# ---------------------------------------------------------------------------

def _map_dms_replication_instance(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "dms_replication_instance",
        "configuration": {"publicly_accessible": bool(body.get("publicly_accessible", True))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_dms_replication_instance.{key[1]}",
    }


def _map_mq_broker(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "mq_broker",
        "configuration": {"publicly_accessible": bool(body.get("publicly_accessible", False))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_mq_broker.{key[1]}",
    }


# ---------------------------------------------------------------------------
# CodeBuild project (NG-AWS-CODEBUILD-001): privileged_mode inside the
# environment block (default false). ECS cluster (NG-AWS-ECS-001):
# container_insights_enabled via a setting { name = "containerInsights" }.
# ---------------------------------------------------------------------------

def _map_codebuild_project(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    env = _first_block(body, "environment")
    privileged = env is not None and bool(env.get("privileged_mode", False))
    return {
        "provider": "aws",
        "resource_type": "codebuild_project",
        "configuration": {"privileged_mode": privileged},
        "tags": body.get("tags") or {},
        "identifier": f"aws_codebuild_project.{key[1]}",
    }


def _map_ecs_cluster(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    settings = body.get("setting")
    if isinstance(settings, dict):
        settings = [settings]
    elif not isinstance(settings, list):
        settings = []
    insights = any(
        isinstance(s, dict) and str(s.get("name") or "") == "containerInsights"
        and str(s.get("value") or "").lower() in ("enabled", "enhanced")
        for s in settings
    )
    return {
        "provider": "aws",
        "resource_type": "ecs_cluster",
        "configuration": {"container_insights_enabled": insights},
        "tags": body.get("tags") or {},
        "identifier": f"aws_ecs_cluster.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Subnet (NG-AWS-VPC-002): map_public_ip_on_launch (default false).
# ---------------------------------------------------------------------------

def _map_subnet(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "subnet",
        "configuration": {"map_public_ip_on_launch": bool(body.get("map_public_ip_on_launch", False))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_subnet.{key[1]}",
    }


# ---------------------------------------------------------------------------
# AMI (NG-AWS-EC2-012): public = a launch permission grants group "all".
# An AMI with no aws_ami_launch_permission granting group=all is private
# (the real, confirmed default). No CloudFormation resource type exists for
# an AMI, so Terraform only.
# ---------------------------------------------------------------------------

def _map_ami(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    public = False
    for (resource_type, _name), lp in all_resources.items():
        if resource_type != "aws_ami_launch_permission":
            continue
        if str(lp.get("group") or "") != "all":
            continue
        ref = resolve_reference(lp.get("image_id"))
        if (ref is not None and ref[0] == "aws_ami" and ref[1] == key[1]) or lp.get("image_id") == key[1]:
            public = True
            break
    return {
        "provider": "aws",
        "resource_type": "ami",
        "configuration": {"public": public},
        "tags": body.get("tags") or {},
        "identifier": f"aws_ami.{key[1]}",
    }


# ---------------------------------------------------------------------------
# VPC (NG-AWS-VPC-001): flow_logs_enabled = an aws_flow_log targets this
# VPC. CloudFormation flow logs are a separate AWS::EC2::FlowLog resource
# with no cross-resource view here, so the CFN mapper doesn't cover this
# (a bare AWS::EC2::VPC has no flow-log property) -> Terraform only.
# ---------------------------------------------------------------------------

def _map_vpc(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    flow_logs = False
    for (resource_type, _name), fl in all_resources.items():
        if resource_type != "aws_flow_log":
            continue
        ref = resolve_reference(fl.get("vpc_id"))
        if (ref is not None and ref[0] == "aws_vpc" and ref[1] == key[1]) or fl.get("vpc_id") == key[1]:
            flow_logs = True
            break
    return {
        "provider": "aws",
        "resource_type": "vpc",
        "configuration": {"flow_logs_enabled": flow_logs},
        "tags": body.get("tags") or {},
        "identifier": f"aws_vpc.{key[1]}",
    }


# ---------------------------------------------------------------------------
# Route53 hosted zone (NG-AWS-ROUTE53-001): query_logging_enabled = an
# aws_route53_query_log targets this zone (default false). CFN's own
# AWS::Route53::HostedZone carries a QueryLoggingConfig property directly.
# ---------------------------------------------------------------------------

def _map_route53_hosted_zone(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    query_logging = False
    for (resource_type, _name), ql in all_resources.items():
        if resource_type != "aws_route53_query_log":
            continue
        ref = resolve_reference(ql.get("zone_id"))
        if (ref is not None and ref[0] == "aws_route53_zone" and ref[1] == key[1]) or ql.get("zone_id") == key[1]:
            query_logging = True
            break
    return {
        "provider": "aws",
        "resource_type": "route53_hosted_zone",
        "configuration": {"query_logging_enabled": query_logging},
        "tags": body.get("tags") or {},
        "identifier": f"aws_route53_zone.{key[1]}",
    }


# ---------------------------------------------------------------------------
# KMS key rotation (NG-AWS-KMS-001) -- `key_manager` is always "CUSTOMER"
# for a Terraform-declared key (a structural fact: AWS-managed keys are
# never created as a Terraform resource, they're implicit per-service
# keys), `customer_master_key_spec` defaults to "SYMMETRIC_DEFAULT" and
# `enable_key_rotation` defaults to false, both confirmed live against
# the AWS provider's own current docs.
# ---------------------------------------------------------------------------

def _map_kms_key(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "kms_key",
        "configuration": {
            "key_manager": "CUSTOMER",
            "key_spec": body.get("customer_master_key_spec", "SYMMETRIC_DEFAULT"),
            "key_rotation_enabled": bool(body.get("enable_key_rotation", False)),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_kms_key.{key[1]}",
    }


# ---------------------------------------------------------------------------
# CloudTrail logging (NG-AWS-CLOUDTRAIL-001) -- `enable_logging` defaults
# to true, confirmed live against the AWS provider's own current docs.
# ---------------------------------------------------------------------------

def _map_cloudtrail(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "cloudtrail_trail",
        "configuration": {"is_logging": bool(body.get("enable_logging", True))},
        "tags": body.get("tags") or {},
        "identifier": f"aws_cloudtrail.{key[1]}",
    }


# ---------------------------------------------------------------------------
# EBS volume encryption -- `encrypted` has NO documented Terraform-level
# default (confirmed live: the AWS provider's own docs describe the
# argument without stating a default), so it's omitted entirely unless
# the customer's own Terraform explicitly sets it -- never guessed
# either direction.
# ---------------------------------------------------------------------------

def _map_ebs_volume(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    configuration: dict[str, Any] = {}
    if "encrypted" in body:
        configuration["encrypted"] = bool(body["encrypted"])
    return {
        "provider": "aws",
        "resource_type": "ebs_volume",
        "configuration": configuration,
        "tags": body.get("tags") or {},
        "identifier": f"aws_ebs_volume.{key[1]}",
    }


# ---------------------------------------------------------------------------
# IAM admin-privilege detection (NG-AWS-IAM-001 users / NG-AWS-IAM-012
# roles) -- correlates a principal against its own attached-policy and
# inline-policy resources. Real argument names
# (role/user + policy_arn on the *_policy_attachment resources;
# role/user + policy on the *_policy resources) confirmed live against
# the AWS provider's own current docs for both the role and user
# variants, not assumed symmetric.
# ---------------------------------------------------------------------------

def _principal_own_literal_names(body: dict[str, Any]) -> set[str]:
    name = body.get("name")
    if isinstance(name, str) and resolve_reference(name) is None:
        return {name}
    return set()


def _attached_policies(
    principal_type: str, principal_key: ResourceKey, attachment_resource_type: str,
    reference_field: str, all_resources: dict[ResourceKey, dict[str, Any]],
) -> list[dict[str, Any]]:
    _, principal_name = principal_key
    own_names = _principal_own_literal_names(all_resources[principal_key])
    policies = []
    for (resource_type, _name), body in all_resources.items():
        if resource_type != attachment_resource_type:
            continue
        if _references_resource(body.get(reference_field), principal_type, principal_name, own_names):
            policies.append({"policy_arn": body.get("policy_arn")})
    return policies


def _parse_inline_policy_document(raw_policy: Any) -> Optional[dict[str, Any]]:
    """Best-effort JSON parse of an inline policy's own `policy`
    attribute -- confirmed live (not guessed) that this genuinely has 2
    different real shapes depending on how the customer wrote it:
    (1) a heredoc or a plain JSON string literal parses cleanly with a
    direct `json.loads`; (2) a JSON string literal using escaped `\"`
    characters comes back from hcl2 with the backslashes literally
    preserved (a confirmed hcl2 parser quirk, not a bug in this
    function) -- a second attempt with `\\"` normalized to `"` recovers
    this case. A `jsonencode(...)` function-call expression (confirmed
    live to be the OTHER common, idiomatic way this is written) can
    never be evaluated by a static parser at all -- both attempts
    correctly fail and this returns `None`, the policy is omitted
    entirely from `inline_policies` rather than fabricated, a real,
    disclosed limitation, not a crash."""
    if not isinstance(raw_policy, str):
        return None
    for candidate in (raw_policy, raw_policy.replace('\\"', '"')):
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _inline_policies(
    principal_type: str, principal_key: ResourceKey, inline_resource_type: str,
    reference_field: str, all_resources: dict[ResourceKey, dict[str, Any]],
) -> list[dict[str, Any]]:
    _, principal_name = principal_key
    own_names = _principal_own_literal_names(all_resources[principal_key])
    policies = []
    for (resource_type, _name), body in all_resources.items():
        if resource_type != inline_resource_type:
            continue
        if not _references_resource(body.get(reference_field), principal_type, principal_name, own_names):
            continue
        document = _parse_inline_policy_document(body.get("policy"))
        if document is not None:
            policies.append({"policy_document": document})
        # else: a jsonencode(...) (or otherwise unparseable) policy body
        # is silently omitted from this one principal's inline_policies
        # -- never fabricated, never crashes the whole scan.
    return policies


def _map_iam_user(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "iam_user",
        "configuration": {
            "attached_policies": _attached_policies("aws_iam_user", key, "aws_iam_user_policy_attachment", "user", all_resources),
            "inline_policies": _inline_policies("aws_iam_user", key, "aws_iam_user_policy", "user", all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_iam_user.{key[1]}",
    }


def _map_iam_role(key: ResourceKey, body: dict[str, Any], all_resources: dict[ResourceKey, dict[str, Any]]) -> dict[str, Any]:
    return {
        "provider": "aws",
        "resource_type": "iam_role",
        "configuration": {
            "attached_policies": _attached_policies("aws_iam_role", key, "aws_iam_role_policy_attachment", "role", all_resources),
            "inline_policies": _inline_policies("aws_iam_role", key, "aws_iam_role_policy", "role", all_resources),
        },
        "tags": body.get("tags") or {},
        "identifier": f"aws_iam_role.{key[1]}",
    }


# Registry, not an if/elif chain -- same "registry over hardcoded chain"
# shape nimbus_app's own RESOURCE_COLLECTORS/DELIVERY_CONNECTORS/
# _EdgeRule already establish. A Terraform resource type present here
# has real, confirmed evidence in the evaluation-engine's own control
# source for the exact configuration shape it produces (see this
# module's own docstring) -- never invented from a guessed field name.
_MAPPERS = {
    "aws_s3_bucket": _map_s3_bucket,
    "aws_security_group": _map_security_group,
    "aws_db_instance": _map_rds_instance,
    "aws_kms_key": _map_kms_key,
    "aws_cloudtrail": _map_cloudtrail,
    "aws_ebs_volume": _map_ebs_volume,
    "aws_iam_user": _map_iam_user,
    "aws_iam_role": _map_iam_role,
    "aws_lb": _map_load_balancer,
    "aws_alb": _map_load_balancer,  # legacy alias for aws_lb (same schema)
    "aws_eks_cluster": _map_eks_cluster,
    "aws_dynamodb_table": _map_dynamodb_table,
    "aws_instance": _map_ec2_instance,
    "aws_lambda_function": _map_lambda_function,
    "aws_ecr_repository": _map_ecr_repository,
    "aws_efs_file_system": _map_efs_file_system,
    "aws_elasticache_replication_group": _map_elasticache_replication_group,
    "aws_elasticache_cluster": _map_elasticache_cluster,
    "aws_redshift_cluster": _map_redshift_cluster,
    "aws_iam_account_password_policy": _map_iam_password_policy,
    "aws_sns_topic": _map_sns_topic,
    "aws_sqs_queue": _map_sqs_queue,
    "aws_secretsmanager_secret": _map_secretsmanager_secret,
    "aws_acm_certificate": _map_acm_certificate,
    "aws_cloudfront_distribution": _map_cloudfront_distribution,
    "aws_sagemaker_notebook_instance": _map_sagemaker_notebook_instance,
    "aws_docdb_cluster": _map_docdb_cluster,
    "aws_wafv2_web_acl": _map_waf_web_acl,
    "aws_athena_workgroup": _map_athena_workgroup,
    "aws_glue_data_catalog_encryption_settings": _map_glue_data_catalog,
    "aws_kinesis_stream": _map_kinesis_stream,
    "aws_kinesis_firehose_delivery_stream": _map_firehose_delivery_stream,
    "aws_sfn_state_machine": _map_sfn_state_machine,
    "aws_backup_vault": _map_backup_vault,
    "aws_dms_replication_instance": _map_dms_replication_instance,
    "aws_mq_broker": _map_mq_broker,
    "aws_codebuild_project": _map_codebuild_project,
    "aws_ecs_cluster": _map_ecs_cluster,
    "aws_subnet": _map_subnet,
    "aws_ami": _map_ami,
    "aws_vpc": _map_vpc,
    "aws_route53_zone": _map_route53_hosted_zone,
    "aws_api_gateway_stage": _map_api_gateway_stage,
    "aws_network_acl": _map_network_acl,
    "aws_route53domains_registered_domain": _map_route53_domain,
    # --- Azure (azurerm) ---
    "azurerm_redis_cache": _map_azure_redis_cache,
    "azurerm_cosmosdb_account": _map_azure_cosmosdb_account,
    "azurerm_postgresql_flexible_server": _map_azure_postgresql_server,
    "azurerm_mysql_flexible_server": _map_azure_mysql_server,
    "azurerm_key_vault": _map_azure_key_vault,
    "azurerm_servicebus_namespace": _map_azure_service_bus_namespace,
    "azurerm_eventhub_namespace": _map_azure_event_hub_namespace,
    "azurerm_automation_account": _map_azure_automation_account,
    "azurerm_synapse_workspace": _map_azure_synapse_workspace,
    "azurerm_log_analytics_workspace": _map_azure_log_analytics_workspace,
}

# Resources consumed BY another mapper above (merged into an owning
# resource's own configuration), never emitted as their own top-level
# gate-check resource -- none of them has an independent resource_type/
# control of its own in nimbus_app's real catalog.
_CONSUMED_ONLY = {
    "aws_s3_bucket_public_access_block",
    "aws_vpc_security_group_ingress_rule",
    "aws_iam_user_policy_attachment",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy",
    "aws_iam_role_policy",
    "aws_lambda_function_url",  # merged into its function's function_url_auth_none
    "aws_ecr_lifecycle_policy",  # merged into its repo's lifecycle_policy_enabled
    "aws_efs_backup_policy",  # merged into its file system's backup_enabled
    "aws_secretsmanager_secret_rotation",  # merged into its secret's rotation_enabled
    "aws_wafv2_web_acl_logging_configuration",  # merged into its ACL's logging_enabled
    "aws_ami_launch_permission",  # merged into its AMI's public flag
    "aws_flow_log",  # merged into its VPC's flow_logs_enabled
    "aws_route53_query_log",  # merged into its zone's query_logging_enabled
    "aws_api_gateway_method_settings",  # merged into a stage's execution_logging_enabled
    "aws_wafv2_web_acl_association",  # merged into a stage's waf_attached
    "aws_network_acl_rule",  # merged into its NACL's entries
    "azurerm_postgresql_flexible_server_configuration",  # merged into ssl_enforced
    "azurerm_mysql_flexible_server_configuration",  # merged into ssl_enforced
    "azurerm_monitor_diagnostic_setting",  # merged into a target resource's logging_enabled
}


def map_resources(all_resources: dict[ResourceKey, dict[str, Any]]) -> list[dict[str, Any]]:
    """Every recognized resource in `all_resources`, mapped to
    nimbus_app's own gate-check shape. An unrecognized Terraform
    resource type (anything not in `_MAPPERS`/`_CONSUMED_ONLY`) is
    silently skipped -- never sent, never fabricated as a trivially-
    passing resource."""
    mapped = []
    for key, body in all_resources.items():
        resource_type, _name = key
        if resource_type in _CONSUMED_ONLY:
            continue
        mapper = _MAPPERS.get(resource_type)
        if mapper is None:
            continue
        mapped.append(mapper(key, body, all_resources))
    return mapped


def unmapped_resource_types(all_resources: dict[ResourceKey, dict[str, Any]]) -> set[str]:
    """The real, distinct set of Terraform resource types this parse run
    saw but doesn't know how to map -- surfaced by the CLI as an
    explicit "not evaluated, not covered yet" notice, never silently
    dropped without a trace."""
    known = set(_MAPPERS) | _CONSUMED_ONLY
    return {resource_type for resource_type, _name in all_resources if resource_type not in known}
