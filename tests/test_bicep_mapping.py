"""Pure unit tests over already-compiled ARM JSON resource dicts -- no
`bicep` CLI needed at all, since mapping never touches compilation."""
from nimbus_iac_scanner.bicep_mapping import map_resources, unmapped_resource_types


def test_storage_account_maps_allow_blob_public_access():
    resources = {("t.bicep", "insecurestorage"): {
        "type": "Microsoft.Storage/storageAccounts",
        "name": "insecurestorage",
        "properties": {"allowBlobPublicAccess": True},
    }}
    entry = map_resources(resources)[0]
    assert entry["provider"] == "azure"
    assert entry["resource_type"] == "storage_account"
    assert entry["configuration"] == {"allow_blob_public_access": True}
    assert entry["identifier"] == "Microsoft.Storage/storageAccounts.insecurestorage"


def test_storage_account_omitted_property_defaults_to_the_confirmed_false_interpretation():
    resources = {("t.bicep", "sa"): {
        "type": "Microsoft.Storage/storageAccounts", "name": "sa", "properties": {},
    }}
    entry = map_resources(resources)[0]
    assert entry["configuration"] == {"allow_blob_public_access": False}


def test_network_security_group_maps_rules_from_camelcase_to_the_control_snake_case_shape():
    resources = {("t.bicep", "open-nsg"): {
        "type": "Microsoft.Network/networkSecurityGroups",
        "name": "open-nsg",
        "properties": {
            "securityRules": [{
                "name": "AllowSSH",
                "properties": {
                    "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                    "destinationPortRange": "22", "sourceAddressPrefix": "*",
                },
            }],
        },
    }}
    entry = map_resources(resources)[0]
    assert entry["resource_type"] == "network_security_group"
    assert entry["configuration"]["rules"] == [{
        "name": "AllowSSH", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
        "destination_port_range": "22", "source_address_prefix": "*",
    }]


def test_network_security_group_with_no_rules_gets_an_empty_list():
    resources = {("t.bicep", "nsg"): {
        "type": "Microsoft.Network/networkSecurityGroups", "name": "nsg", "properties": {},
    }}
    entry = map_resources(resources)[0]
    assert entry["configuration"]["rules"] == []


def test_tags_are_a_top_level_property_not_nested_under_properties():
    resources = {("t.bicep", "sa"): {
        "type": "Microsoft.Storage/storageAccounts", "name": "sa",
        "properties": {}, "tags": {"Environment": "prod"},
    }}
    entry = map_resources(resources)[0]
    assert entry["tags"] == {"Environment": "prod"}


def test_unrecognized_resource_type_is_skipped_not_fabricated():
    resources = {("t.bicep", "vm"): {"type": "Microsoft.Compute/virtualMachines", "name": "vm", "properties": {}}}
    assert map_resources(resources) == []
    assert unmapped_resource_types(resources) == {"Microsoft.Compute/virtualMachines"}
