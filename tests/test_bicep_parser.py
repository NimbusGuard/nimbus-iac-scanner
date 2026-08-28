"""Some of these tests need the real `bicep` CLI on PATH -- confirmed
live (this is a real compiler, not something worth faking with a mock,
since the whole point of this module is trusting the ONE canonical,
Microsoft-maintained source of truth for what a .bicep file compiles
to). Individually skipped, not failed, when it isn't available --
matching this project's own "don't hard-require an external tool in
every environment, disclose what ran and what didn't" precedent, same
as the pre-existing real-HTTP live-verification passes documented in
CLAUDE.md. The "CLI not found"/"no .bicep files at all" cases below
need no real compiler and always run."""
import pytest

from nimbus_iac_scanner.bicep_parser import (
    BicepCliNotFoundError,
    BicepCompileError,
    is_bicep_cli_available,
    parse_directory,
)

_needs_real_bicep = pytest.mark.skipif(
    not is_bicep_cli_available(), reason="the 'bicep' CLI isn't installed/on PATH in this environment",
)


@_needs_real_bicep
def test_compiles_a_real_bicep_file_and_flattens_its_resources(tmp_path):
    (tmp_path / "main.bicep").write_text('''
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'teststorage001'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
  }
}
''')
    resources = parse_directory(str(tmp_path))
    assert len(resources) == 1
    (_key, resource), = resources.items()
    assert resource["type"] == "Microsoft.Storage/storageAccounts"
    assert resource["properties"]["allowBlobPublicAccess"] is True


@_needs_real_bicep
def test_a_real_bicep_syntax_error_raises_never_silently_skipped(tmp_path):
    (tmp_path / "broken.bicep").write_text("resource sa 'X' = { this is not valid @#$ }")
    with pytest.raises(BicepCompileError):
        parse_directory(str(tmp_path))


@_needs_real_bicep
def test_two_files_reusing_the_same_resource_name_are_disambiguated_by_file_path(tmp_path):
    (tmp_path / "a.bicep").write_text('''
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'samename'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}
''')
    (tmp_path / "b.bicep").write_text('''
resource sa 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'samename'
  location: 'eastus'
  properties: {}
}
''')
    resources = parse_directory(str(tmp_path))
    assert len(resources) == 2
    types = {r["type"] for r in resources.values()}
    assert types == {"Microsoft.Storage/storageAccounts", "Microsoft.Network/networkSecurityGroups"}


def test_no_bicep_files_at_all_returns_empty_without_needing_the_cli(tmp_path):
    (tmp_path / "unrelated.txt").write_text("nothing here")
    assert parse_directory(str(tmp_path)) == {}


def test_bicep_cli_not_found_raises_a_distinct_error_never_silently_returns_empty(tmp_path, monkeypatch):
    """A real .bicep file existing but the CLI being unavailable must
    never look identical to "this project has no Bicep resources" --
    doesn't need the real CLI present, mocked regardless of this
    environment's own actual availability."""
    (tmp_path / "main.bicep").write_text("resource sa 'X' = {}")
    monkeypatch.setattr("nimbus_iac_scanner.bicep_parser.is_bicep_cli_available", lambda: False)
    with pytest.raises(BicepCliNotFoundError):
        parse_directory(str(tmp_path))
