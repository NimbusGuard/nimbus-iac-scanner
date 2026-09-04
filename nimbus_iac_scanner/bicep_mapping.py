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


def _map_cosmosdb_account(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    """Microsoft.DocumentDB/databaseAccounts (NG-AZURE-COSMOSDB-001..004)."""
    properties = resource.get("properties") or {}
    public_disabled = str(properties.get("publicNetworkAccess", "Enabled")).lower() == "disabled"
    vnet_filter = bool(properties.get("isVirtualNetworkFilterEnabled", False))
    ip_rules = bool(properties.get("ipRules"))
    vnet_rules = bool(properties.get("virtualNetworkRules"))
    backup = properties.get("backupPolicy") or {}
    return {
        "provider": "azure",
        "resource_type": "cosmosdb_account",
        "configuration": {
            "network_access_restricted": public_disabled or vnet_filter or ip_rules or vnet_rules,
            "local_auth_disabled": bool(properties.get("disableLocalAuth", False)),
            "encrypted_with_cmk": bool(properties.get("keyVaultKeyUri")),
            "continuous_backup_enabled": str(backup.get("type") or "").lower() == "continuous",
        },
        "tags": resource.get("tags") or {},
        "identifier": f"Microsoft.DocumentDB/databaseAccounts.{key[1]}",
    }


def _map_flexible_db(key: tuple[str, str], resource: dict[str, Any], resource_type: str, arm_type: str) -> dict[str, Any]:
    """Microsoft.DBfor{PostgreSQL,MySQL}/flexibleServers (NG-AZURE-*-002/003/
    004). ssl_enforced (require_secure_transport) is a separate configurations
    sub-resource with no cross-resource view here, so it's omitted (the TF
    mapper covers it). publicNetworkAccess lives under properties.network."""
    properties = resource.get("properties") or {}
    network = properties.get("network") or {}
    backup = properties.get("backup") or {}
    configuration: dict[str, Any] = {
        "geo_redundant_backup_enabled": str(backup.get("geoRedundantBackup", "Disabled")).lower() == "enabled",
        "backup_retention_days": int(backup.get("backupRetentionDays", 7)),
    }
    pna = network.get("publicNetworkAccess")
    if pna is not None:
        configuration["public_network_access_enabled"] = str(pna).lower() != "disabled"
    return {
        "provider": "azure",
        "resource_type": resource_type,
        "configuration": configuration,
        "tags": resource.get("tags") or {},
        "identifier": f"{arm_type}.{key[1]}",
    }


def _map_postgresql_server(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    return _map_flexible_db(key, resource, "postgresql_server", "Microsoft.DBforPostgreSQL/flexibleServers")


def _map_mysql_server(key: tuple[str, str], resource: dict[str, Any]) -> dict[str, Any]:
    return _map_flexible_db(key, resource, "mysql_server", "Microsoft.DBforMySQL/flexibleServers")


_MAPPERS = {
    "Microsoft.Network/networkSecurityGroups": _map_network_security_group,
    "Microsoft.Storage/storageAccounts": _map_storage_account,
    "Microsoft.Cache/redis": _map_redis_cache,
    "Microsoft.DocumentDB/databaseAccounts": _map_cosmosdb_account,
    "Microsoft.DBforPostgreSQL/flexibleServers": _map_postgresql_server,
    "Microsoft.DBforMySQL/flexibleServers": _map_mysql_server,
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
