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
