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


def test_storage_account_bicep_full_field_set():
    entry = _one({
        "type": "Microsoft.Storage/storageAccounts",
        "sku": {"name": "Standard_LRS"},
        "properties": {
            "allowBlobPublicAccess": False, "supportsHttpsTrafficOnly": True,
            "minimumTlsVersion": "TLS1_2", "allowSharedKeyAccess": False,
            "publicNetworkAccess": "Disabled", "allowCrossTenantReplication": False,
            "encryption": {"requireInfrastructureEncryption": True},
            "networkAcls": {"defaultAction": "Deny"},
            "sasPolicy": {"sasExpirationPeriod": "0.01:00:00"},
        },
    })
    c = entry["configuration"]
    assert c["supports_https_traffic_only"] is True
    assert c["infrastructure_encryption_enabled"] is True
    assert c["shared_key_access_disabled"] is True
    assert c["public_network_access_enabled"] is False
    assert c["sas_expiration_policy_set"] is True
    assert c["network_default_action"] == "Deny"
    assert c["minimum_tls_version"] == "TLS1_2"
    assert c["cross_tenant_replication_enabled"] is False
    assert c["account_replication_type"] == "LRS"
    assert c["encryption"] == {"services": {"blob": {"enabled": True}}}


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


# --- key_vault -------------------------------------------------------------

def test_key_vault_hardened_bicep():
    entry = _one({
        "type": "Microsoft.KeyVault/vaults",
        "properties": {
            "enablePurgeProtection": True, "enableRbacAuthorization": True,
            "publicNetworkAccess": "Disabled", "softDeleteRetentionInDays": 90,
        },
    })
    assert entry["configuration"] == {
        "purge_protection_enabled": True, "rbac_authorization_enabled": True,
        "soft_delete_retention_days": 90, "public_network_access_enabled": False,
    }
    assert "logging_enabled" not in entry["configuration"]


def test_key_vault_defaults_bicep():
    entry = _one({"type": "Microsoft.KeyVault/vaults", "properties": {}})
    assert entry["configuration"] == {
        "purge_protection_enabled": False, "rbac_authorization_enabled": False,
        "soft_delete_retention_days": 90, "public_network_access_enabled": True,
    }


# --- servicebus/eventhub/automation/synapse/loganalytics (Bicep) ----------

def test_service_bus_bicep():
    e = _one({"type": "Microsoft.ServiceBus/namespaces",
              "properties": {"disableLocalAuth": True, "minimumTlsVersion": "1.2", "publicNetworkAccess": "Disabled"}})
    assert e["configuration"] == {"local_auth_disabled": True, "public_network_access_enabled": False, "minimum_tls_1_2": True}


def test_event_hub_bicep_defaults():
    e = _one({"type": "Microsoft.EventHub/namespaces", "properties": {}})
    assert e["configuration"] == {"local_auth_disabled": False, "public_network_access_enabled": True}


def test_automation_account_bicep():
    e = _one({"type": "Microsoft.Automation/automationAccounts",
              "properties": {"disableLocalAuth": True, "publicNetworkAccess": "Disabled"}})
    assert e["configuration"] == {"local_auth_disabled": True, "public_network_access_enabled": False}


def test_synapse_bicep_default():
    e = _one({"type": "Microsoft.Synapse/workspaces", "properties": {}})
    assert e["configuration"] == {"public_network_access_enabled": True}


def test_log_analytics_bicep():
    assert _one({"type": "Microsoft.OperationalInsights/workspaces", "properties": {"retentionInDays": 90}})["configuration"] == {"retention_days": 90}
    assert _one({"type": "Microsoft.OperationalInsights/workspaces", "properties": {}})["configuration"] == {}


# --- container_registry / api_management / key_vault key & secret (Bicep) --

def test_container_registry_bicep():
    e = _one({"type": "Microsoft.ContainerRegistry/registries", "properties": {
        "adminUserEnabled": False, "publicNetworkAccess": "Disabled", "anonymousPullEnabled": False,
        "encryption": {"status": "enabled"}, "policies": {"retentionPolicy": {"status": "enabled"}},
    }})
    assert e["configuration"] == {
        "admin_user_enabled": False, "public_network_access_enabled": False,
        "anonymous_pull_enabled": False, "encrypted_with_cmk": True, "retention_policy_enabled": True,
    }


def test_container_registry_bicep_defaults():
    e = _one({"type": "Microsoft.ContainerRegistry/registries", "properties": {}})
    assert e["configuration"] == {
        "admin_user_enabled": False, "public_network_access_enabled": True,
        "anonymous_pull_enabled": False, "encrypted_with_cmk": False, "retention_policy_enabled": False,
    }


def test_api_management_bicep_default():
    assert _one({"type": "Microsoft.ApiManagement/service", "properties": {}})["configuration"] == {"public_network_access_enabled": True}


def test_key_vault_key_bicep():
    e = _one({"type": "Microsoft.KeyVault/vaults/keys", "properties": {"attributes": {"exp": 1893456000}, "rotationPolicy": {}}})
    assert e["configuration"] == {"expiration_set": True, "rotation_policy": True}


def test_key_vault_secret_bicep():
    assert _one({"type": "Microsoft.KeyVault/vaults/secrets", "properties": {"attributes": {"exp": 1893456000}}})["configuration"] == {"expiration_set": True}
    assert _one({"type": "Microsoft.KeyVault/vaults/secrets", "properties": {}})["configuration"] == {"expiration_set": False}


# --- managed_disk / sql_database / storage_container (Bicep) ---------------

def test_managed_disk_bicep():
    e = _one({"type": "Microsoft.Compute/disks", "properties": {"publicNetworkAccess": "Disabled", "networkAccessPolicy": "DenyAll"}})
    assert e["configuration"] == {"public_network_access": "Disabled", "network_access_policy": "DenyAll"}
    e2 = _one({"type": "Microsoft.Compute/disks", "properties": {}})
    assert e2["configuration"] == {"public_network_access": "Enabled", "network_access_policy": "AllowAll"}


def test_sql_database_bicep():
    e = _one({"type": "Microsoft.Sql/servers/databases", "properties": {"requestedBackupStorageRedundancy": "Local", "ledgerOn": True}})
    assert e["configuration"] == {"backup_storage_redundancy": "Local", "ledger_enabled": True}


def test_storage_container_bicep():
    assert _one({"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "properties": {"publicAccess": "Container"}})["configuration"] == {"public_access": "Container"}
    assert _one({"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "properties": {}})["configuration"] == {"public_access": "None"}


# --- sql_server (Bicep, inline only) --------------------------------------

def test_sql_server_bicep_inline():
    e = _one({"type": "Microsoft.Sql/servers", "identity": {"type": "SystemAssigned"}, "properties": {
        "publicNetworkAccess": "Disabled", "minimalTlsVersion": "1.2",
        "administrators": {"administratorType": "ActiveDirectory", "azureADOnlyAuthentication": True},
    }})
    c = e["configuration"]
    assert c == {
        "public_network_access_enabled": False, "entra_admin_configured": True,
        "azuread_only_authentication_enabled": True, "managed_identity_enabled": True, "minimum_tls_1_2": True,
    }


def test_sql_server_bicep_defaults():
    e = _one({"type": "Microsoft.Sql/servers", "properties": {}})
    c = e["configuration"]
    assert c["public_network_access_enabled"] is True
    assert c["entra_admin_configured"] is False
    assert c["managed_identity_enabled"] is False
    assert "minimum_tls_1_2" not in c


# --- Microsoft.Web/sites -> app_service / function_app (by kind) ----------

def test_web_site_app_service_bicep():
    e = _one({"type": "Microsoft.Web/sites", "kind": "app,linux", "identity": {"type": "SystemAssigned"},
              "properties": {"httpsOnly": True, "clientCertEnabled": True,
                             "siteConfig": {"minTlsVersion": "1.2", "http20Enabled": True, "ftpsState": "Disabled"}}})
    assert e["resource_type"] == "app_service"
    assert e["configuration"] == {
        "https_only": True, "client_certs_required": True, "managed_identity_enabled": True,
        "http2_enabled": True, "ftp_deployments_disabled": True, "minimum_tls_1_2": True,
    }


def test_web_site_function_app_bicep():
    e = _one({"type": "Microsoft.Web/sites", "kind": "functionapp,linux",
              "properties": {"httpsOnly": True, "publicNetworkAccess": "Disabled", "siteConfig": {"minTlsVersion": "1.2"}}})
    assert e["resource_type"] == "function_app"
    assert e["configuration"] == {"https_only": True, "public_network_access_enabled": False, "minimum_tls_1_2": True}


def test_web_site_logic_app_workflow_is_app_service_not_function():
    # functionapp,workflowapp is a Logic App Standard -> NOT a function app
    e = _one({"type": "Microsoft.Web/sites", "kind": "functionapp,workflowapp", "properties": {}})
    assert e["resource_type"] == "app_service"


# --- aks_cluster / recovery_services_vault (Bicep) ------------------------

def test_aks_bicep_hardened():
    e = _one({"type": "Microsoft.ContainerService/managedClusters", "identity": {"type": "SystemAssigned"}, "properties": {
        "apiServerAccessProfile": {"enablePrivateCluster": True}, "enableRBAC": True,
        "disableLocalAccounts": True, "networkProfile": {"networkPolicy": "azure"},
        "addonProfiles": {"azurepolicy": {"enabled": True}},
    }})
    assert e["configuration"] == {
        "endpoint_public_access": False, "rbac_enabled": True, "network_policy_enabled": True,
        "local_accounts_disabled": True, "managed_identity_enabled": True, "policy_addon_enabled": True,
    }


def test_aks_bicep_defaults():
    e = _one({"type": "Microsoft.ContainerService/managedClusters", "properties": {}})
    assert e["configuration"]["endpoint_public_access"] is True
    assert e["configuration"]["rbac_enabled"] is True
    assert e["configuration"]["policy_addon_enabled"] is False


def test_recovery_vault_bicep():
    e = _one({"type": "Microsoft.RecoveryServices/vaults", "properties": {
        "publicNetworkAccess": "Disabled",
        "securitySettings": {"immutabilitySettings": {"state": "Locked"}, "softDeleteSettings": {"softDeleteState": "Enabled"}},
        "encryption": {"keyVaultProperties": {"keyUri": "https://kv.vault.azure.net/keys/k"}},
    }})
    assert e["configuration"] == {
        "public_network_access_enabled": False, "immutability_enabled": True,
        "soft_delete_enabled": True, "cmk_encryption_enabled": True,
    }


# --- application_gateway (Bicep) ------------------------------------------

def test_application_gateway_bicep():
    e = _one({"type": "Microsoft.Network/applicationGateways", "properties": {
        "webApplicationFirewallConfiguration": {"enabled": True}, "sslPolicy": {"minProtocolVersion": "TLSv1_2"}}})
    assert e["configuration"] == {"waf_enabled": True, "minimum_tls_1_2": True}


def test_application_gateway_bicep_firewall_policy():
    e = _one({"type": "Microsoft.Network/applicationGateways", "properties": {"firewallPolicy": {"id": "/x"}}})
    assert e["configuration"] == {"waf_enabled": True}
