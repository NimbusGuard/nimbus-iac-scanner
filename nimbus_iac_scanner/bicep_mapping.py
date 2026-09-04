"""Compiled-Bicep (ARM JSON) resource type -> nimbus_app's own
`{provider, resource_type, configuration, tags, identifier}` shape.

**Deliberately a narrower slice than the AWS-side mappers** (2 Azure
resource types, not 8) -- the same "narrower first, real and working
over exhaustive" precedent this whole project already applies
repeatedly to Azure coverage (e.g. nimbus_app's own collector history:
AWS ships a control/field first, Azure follows narrower or stays a
declared, disclosed gap). Both confirmed field-by-field against the
real evaluation-engine control source before writing this file:

- `network_security_group` / `configuration.rules` (NG-AZURE-NET-001
  and every other network_security_group-targeted control): a list of
  `{direction, access, protocol, destination_port_range,
  source_address_prefix, name}` -- SNAKE_CASE, confirmed against
  `controls/azure/network/_nsg_rules.py` directly, genuinely different
  from ARM's own camelCase property names, which this module maps.
- `storage_account` / `configuration.allow_blob_public_access`
  (NG-AZURE-STORAGE-001): bool. ARM's own `allowBlobPublicAccess`
  property has no single, formally-labeled default in Microsoft's own
  docs, but its description states "the default interpretation is
  false for this property" -- confirmed live, cited here, not guessed;
  omitted entirely as `False` when absent."""
from typing import Any


def _map_network_security_group(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    properties = resource.get("properties") or {}
    raw_rules = properties.get("securityRules") or []
    rules = []
    for rule in raw_rules:
        if not isinstance(rule, dict):
            continue
        rule_properties = rule.get("properties") or {}
        rules.append({
            "name": rule.get("name"),
            "direction": rule_properties.get("direction"),
            "access": rule_properties.get("access"),
            "protocol": rule_properties.get("protocol"),
            "destination_port_range": rule_properties.get("destinationPortRange"),
            "source_address_prefix": rule_properties.get("sourceAddressPrefix"),
        })
    return {
        "provider": "azure",
        "resource_type": "network_security_group",
        "configuration": {"rules": rules},
        "tags": resource.get("tags") or {},  # a top-level ARM resource property, never nested under properties
        "identifier": f"Microsoft.Network/networkSecurityGroups.{key[1]}",
    }


def _map_storage_account(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    properties = resource.get("properties") or {}
    return {
        "provider": "azure",
        "resource_type": "storage_account",
        "configuration": {
            # "the default interpretation is false for this property" --
            # Microsoft's own current ARM template reference for
            # Microsoft.Storage/storageAccounts, confirmed live, not guessed.
            "allow_blob_public_access": bool(properties.get("allowBlobPublicAccess", False)),
        },
        "tags": resource.get("tags") or {},
        "identifier": f"Microsoft.Storage/storageAccounts.{key[1]}",
    }


def _map_redis_cache(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    """Microsoft.Cache/redis (NG-AZURE-REDIS-001/002/003). publicNetworkAccess
    defaults "Enabled" and enableNonSslPort defaults false (stable); the
    minimum TLS version's default is version-ambiguous, so minimum_tls_1_2 is
    omitted when minimumTlsVersion is absent (a false PASS otherwise)."""
    properties = resource.get("properties") or {}
    configuration: dict[str, Any] = {
        "non_ssl_port_enabled": bool(properties.get("enableNonSslPort", False)),
        "public_network_access_enabled": str(properties.get("publicNetworkAccess", "Enabled")).lower() != "disabled",
    }
    if "minimumTlsVersion" in properties:
        configuration["minimum_tls_1_2"] = str(properties.get("minimumTlsVersion") or "") >= "1.2"
    return {
        "provider": "azure",
        "resource_type": "redis_cache",
        "configuration": configuration,
        "tags": resource.get("tags") or {},
        "identifier": f"Microsoft.Cache/redis.{key[1]}",
    }


_MAPPERS = {
    "Microsoft.Network/networkSecurityGroups": _map_network_security_group,
    "Microsoft.Storage/storageAccounts": _map_storage_account,
    "Microsoft.Cache/redis": _map_redis_cache,
}


def map_resources(all_resources: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    mapped = []
    for key, resource in all_resources.items():
        mapper = _MAPPERS.get(resource.get("type"))
        if mapper is None:
            continue
        mapped.append(mapper(key, resource))
    return mapped


def unmapped_resource_types(all_resources: dict[tuple[str, str], dict[str, Any]]) -> set[str]:
    return {
        resource_type for resource_type in
        (resource.get("type") for resource in all_resources.values())
        if isinstance(resource_type, str) and resource_type not in _MAPPERS
    }
