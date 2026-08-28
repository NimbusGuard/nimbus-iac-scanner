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

**Deliberately a curated, narrow set of Terraform resource types this
first slice maps** -- not an attempt at exhaustive Terraform/AWS/Azure
coverage. A resource type this module doesn't recognize is silently
skipped (never sent to the gate-check at all, never fabricated as an
empty/passing resource) -- see README.md's own "known gaps" section for
the full, disclosed list of what's not covered yet, same "omit, don't
fabricate" discipline nimbus_app's own real cloud collectors already
follow for exactly this reason.

Terraform's own newer, decomposed ingress-rule resources
(`aws_vpc_security_group_ingress_rule`, AWS provider v5+) are NOT
mapped this pass -- only the classic inline `ingress {}` block on
`aws_security_group` itself. A real, disclosed gap, not silently
assumed covered."""
from typing import Any

from nimbus_iac_scanner.terraform_parser import resolve_reference

ResourceKey = tuple[str, str]


def _s3_bucket_own_name_attributes(body: dict[str, Any]) -> set[str]:
    """A public_access_block resource's own `bucket` attribute can
    reference the bucket by its Terraform `.id`/`.bucket`/`.arn`
    attribute, OR by the bucket's own literal name string (Terraform
    allows either) -- both are checked."""
    names = set()
    literal_bucket_name = body.get("bucket")
    if isinstance(literal_bucket_name, str) and resolve_reference(literal_bucket_name) is None:
        names.add(literal_bucket_name)
    return names


def _find_public_access_block(
    bucket_key: ResourceKey, all_resources: dict[ResourceKey, dict[str, Any]],
) -> dict[str, Any] | None:
    """Returns the `aws_s3_bucket_public_access_block` resource whose own
    `bucket` attribute resolves to `bucket_key` (via a Terraform
    reference), or references the bucket's own literal name string.
    `None` if no such resource exists in this parse -- the caller omits
    `public_access_block` entirely rather than guessing, same as every
    other collector-side omission in this codebase."""
    _, bucket_name = bucket_key
    bucket_own_names = _s3_bucket_own_name_attributes(all_resources[bucket_key])
    for (resource_type, _resource_name), body in all_resources.items():
        if resource_type != "aws_s3_bucket_public_access_block":
            continue
        ref = resolve_reference(body.get("bucket"))
        if ref is not None and ref[0] == "aws_s3_bucket" and ref[1] == bucket_name:
            return body
        if isinstance(body.get("bucket"), str) and body["bucket"] in bucket_own_names:
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


def _normalize_ingress_block(block: dict[str, Any]) -> dict[str, Any]:
    cidr_blocks = block.get("cidr_blocks") or []
    return {
        "protocol": block.get("protocol"),
        "from_port": block.get("from_port"),
        "to_port": block.get("to_port"),
        "sources": [{"type": "ipv4", "value": cidr} for cidr in cidr_blocks],
    }


def _map_security_group(key: ResourceKey, body: dict[str, Any], _all_resources) -> dict[str, Any]:
    ingress_blocks = body.get("ingress") or []
    if isinstance(ingress_blocks, dict):  # a single ingress {} block parses as a bare dict, not a list
        ingress_blocks = [ingress_blocks]
    return {
        "provider": "aws",
        "resource_type": "security_group",
        "configuration": {"ingress_rules": [_normalize_ingress_block(b) for b in ingress_blocks]},
        "tags": body.get("tags") or {},
        "identifier": f"aws_security_group.{key[1]}",
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
}

# aws_s3_bucket_public_access_block is consumed BY _map_s3_bucket above
# (merged into the owning bucket's own configuration), never emitted as
# its own top-level gate-check resource -- it has no independent
# resource_type/control of its own in nimbus_app's real catalog.
_CONSUMED_ONLY = {"aws_s3_bucket_public_access_block"}


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
