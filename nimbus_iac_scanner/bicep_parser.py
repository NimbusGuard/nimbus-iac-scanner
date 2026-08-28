"""Compiles real Bicep (`.bicep`) source to ARM JSON via the official
`bicep` CLI (`bicep build --stdout <file>`), then returns the same flat
`{(file_path, resource_index): resource_dict}` shape the CloudFormation
parser produces -- Bicep has no independent Python parser worth trusting
(unlike Terraform's mature `python-hcl2`), and the `bicep` CLI IS the
one, canonical, Microsoft-maintained source of truth for what a
`.bicep` file actually compiles to. Confirmed live (not assumed) before
writing this: `bicep build --stdout` writes ONLY the compiled JSON to
stdout, with every warning/diagnostic on stderr -- a real compile
failure (a genuine Bicep syntax error) exits non-zero with an empty
stdout and the real error(s) on stderr.

A compiled ARM resource has no independently stable "logical id" the
way a CloudFormation template's own `Resources` dict keys do -- Bicep's
own SOURCE-level symbolic names (`resource sa '...' = {...}`) are
discarded during compilation, only the resource's own real Azure
`name` property survives into the compiled output. Keyed by
`(file_path, name or index)`, mirroring the same file-path
disambiguation `cloudformation_parser.py` already uses for the
identical "two independent files could plausibly reuse the same
identifier" reason."""
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

ResourceKey = tuple[str, str]

BICEP_CLI_NAME = "bicep"


class BicepCliNotFoundError(Exception):
    """Raised (never silently swallowed into "0 resources found") when
    at least one `.bicep` file exists but the `bicep` CLI itself isn't
    on PATH -- the caller must be told to install it, not shown a
    misleadingly clean, empty result."""


class BicepCompileError(Exception):
    """A real Bicep syntax/type error -- never silently skipped, same
    "never silently skip a file we couldn't read" posture as
    `terraform_parser.py`/`cloudformation_parser.py`."""


def is_bicep_cli_available() -> bool:
    return shutil.which(BICEP_CLI_NAME) is not None


def compile_to_arm(bicep_file: Path) -> dict[str, Any]:
    """Runs the real `bicep` CLI against one file. Raises
    `BicepCompileError` (with the real, actionable stderr message) on
    any non-zero exit -- confirmed live that a real syntax error
    produces exactly this shape (empty stdout, the real diagnostic on
    stderr), never a partial/guessed result."""
    result = subprocess.run(
        [BICEP_CLI_NAME, "build", "--stdout", str(bicep_file)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise BicepCompileError(f"{bicep_file}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def parse_directory(path: str) -> dict[ResourceKey, dict[str, Any]]:
    """Every `.bicep` file under `path` (recursively), compiled to ARM
    JSON and flattened. Returns `{}` (no error) when there are simply
    no `.bicep` files to evaluate at all -- but raises
    `BicepCliNotFoundError` the moment at least one real `.bicep` file
    IS found and the `bicep` CLI itself isn't available, since silently
    returning `{}` in that case would look identical to "this project
    has no Bicep resources," a real, misleading false negative for a
    security tool."""
    bicep_files = sorted(Path(path).rglob("*.bicep"))
    if not bicep_files:
        return {}
    if not is_bicep_cli_available():
        raise BicepCliNotFoundError(
            f"{len(bicep_files)} .bicep file(s) found, but the 'bicep' CLI isn't installed or "
            "isn't on PATH -- install it (e.g. `az bicep install`, or see "
            "https://learn.microsoft.com/azure/azure-resource-manager/bicep/install) to evaluate them."
        )

    resources: dict[ResourceKey, dict[str, Any]] = {}
    for bicep_file in bicep_files:
        arm = compile_to_arm(bicep_file)
        for index, resource in enumerate(arm.get("resources", [])):
            if not isinstance(resource, dict) or "type" not in resource:
                continue
            identity = resource.get("name") if isinstance(resource.get("name"), str) else str(index)
            resources[(str(bicep_file), identity)] = resource
    return resources
