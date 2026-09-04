from nimbus_iac_scanner.bicep_mapping import map_resources, unmapped_resource_types


def _one(resource):
    return map_resources({("main.bicep", "r"): resource})[0]


# --- network_security_group (existing mapper, previously untested) ---------

def test_nsg_maps_arm_camelcase_rules_to_snake_case():
    entry = _one({
        "type": "Microsoft.Network/networkSecurityGroups",
        "name": "nsg",
        "tags": {"env": "prod"},
        "properties": {
            "securityRules": [{
                "name": "allow-ssh",
                "properties": {
                    "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                    "destinationPortRange": "22", "sourceAddressPrefix": "*",
                },
            }],
        },
    })
    assert entry["provider"] == "azure"
    assert entry["resource_type"] == "network_security_group"
    assert entry["configuration"]["rules"] == [{
        "name": "allow-ssh", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "destination_port_range": "22", "source_address_prefix": "*",
    }]
    assert entry["tags"] == {"env": "prod"}
    assert entry["identifier"] == "Microsoft.Network/networkSecurityGroups.r"


def test_nsg_with_no_rules_is_empty_list():
    entry = _one({"type": "Microsoft.Network/networkSecurityGroups", "properties": {}})
    assert entry["configuration"]["rules"] == []


# --- storage_account (existing mapper, previously untested) ----------------

def test_storage_account_allow_blob_public_access_true():
    entry = _one({
        "type": "Microsoft.Storage/storageAccounts",
        "properties": {"allowBlobPublicAccess": True},
    })
    assert entry["resource_type"] == "storage_account"
    assert entry["configuration"]["allow_blob_public_access"] is True


def test_storage_account_allow_blob_public_access_defaults_false_when_absent():
    entry = _one({"type": "Microsoft.Storage/storageAccounts", "properties": {}})
    assert entry["configuration"]["allow_blob_public_access"] is False


def test_unrecognized_bicep_type_is_skipped():
    resources = {("main.bicep", "x"): {"type": "Microsoft.Foo/bars", "properties": {}}}
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"Microsoft.Foo/bars"}


# --- redis_cache -----------------------------------------------------------

def test_redis_cache_hardened():
    entry = _one({
        "type": "Microsoft.Cache/redis",
        "properties": {"minimumTlsVersion": "1.2", "enableNonSslPort": False, "publicNetworkAccess": "Disabled"},
    })
    assert entry["provider"] == "azure"
    assert entry["resource_type"] == "redis_cache"
    assert entry["configuration"] == {
        "non_ssl_port_enabled": False, "public_network_access_enabled": False, "minimum_tls_1_2": True,
    }


def test_redis_cache_defaults_omit_version_ambiguous_tls():
    entry = _one({"type": "Microsoft.Cache/redis", "properties": {}})
    cfg = entry["configuration"]
    assert cfg == {"non_ssl_port_enabled": False, "public_network_access_enabled": True}
    assert "minimum_tls_1_2" not in cfg


# --- cosmosdb_account ------------------------------------------------------

def test_cosmosdb_hardened():
    entry = _one({
        "type": "Microsoft.DocumentDB/databaseAccounts",
        "properties": {
            "publicNetworkAccess": "Disabled", "disableLocalAuth": True,
            "keyVaultKeyUri": "https://kv.vault.azure.net/keys/k",
            "backupPolicy": {"type": "Continuous"},
        },
    })
    assert entry["configuration"] == {
        "network_access_restricted": True, "local_auth_disabled": True,
        "encrypted_with_cmk": True, "continuous_backup_enabled": True,
    }


def test_cosmosdb_insecure_defaults():
    entry = _one({"type": "Microsoft.DocumentDB/databaseAccounts", "properties": {}})
    assert entry["configuration"] == {
        "network_access_restricted": False, "local_auth_disabled": False,
        "encrypted_with_cmk": False, "continuous_backup_enabled": False,
    }


# --- postgresql/mysql flexible server (Bicep) -----------------------------

def test_postgresql_flexible_bicep():
    entry = _one({
        "type": "Microsoft.DBforPostgreSQL/flexibleServers",
        "properties": {
            "network": {"publicNetworkAccess": "Disabled"},
            "backup": {"geoRedundantBackup": "Enabled", "backupRetentionDays": 30},
        },
    })
    assert entry["resource_type"] == "postgresql_server"
    assert entry["configuration"] == {
        "geo_redundant_backup_enabled": True, "backup_retention_days": 30,
        "public_network_access_enabled": False,
    }
    assert "ssl_enforced" not in entry["configuration"]  # separate configurations sub-resource


def test_mysql_flexible_bicep_defaults():
    entry = _one({"type": "Microsoft.DBforMySQL/flexibleServers", "properties": {}})
    assert entry["resource_type"] == "mysql_server"
    assert entry["configuration"] == {"geo_redundant_backup_enabled": False, "backup_retention_days": 7}
