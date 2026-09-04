"""Parses real Terraform (`.tf`) source into a flat
`{(resource_type, resource_name): body}` dict — never a partial mapping
to nimbus_app's own resource_type vocabulary, that's `resource_mapping.py`'s
job (kept as a separate, deliberate concern: this module knows Terraform
syntax, `resource_mapping.py` knows the target `configuration` shape,
neither needs to know the other's internals).

**Pinned to `python-hcl2==4.3.5`, not the latest 8.x, confirmed live
before writing this, not assumed** — 8.1.3 (the current published
version at the time this was written) changed its own output shape
materially: every dict key and string-literal value comes back wrapped
in a literal embedded `"` character (e.g. `'"aws_s3_bucket"'` as a dict
key, not `'aws_s3_bucket'`), plus a `__is_block__` marker on every
block-shaped value — a real, confirmed breaking change from the clean,
widely-documented shape every real-world Terraform-parsing tool (this
module included) is built against. 4.3.5 is the last release before
that shift and gives the standard, predictable shape this module's own
tests assert against directly."""
import io
from pathlib import Path
from typing import Any

import hcl2

from nimbus_iac_scanner import source_location

# A Terraform-native reference expression, e.g. "${aws_s3_bucket.data.id}"
# -- resolved (not evaluated) into its own (resource_type, resource_name,
# attribute) triple by resolve_reference() below. Terraform 0.12+ also
# allows a bare, unwrapped reference as the value of a single-expression
# attribute (no leading/trailing text) -- both shapes are handled.
_REFERENCE_PREFIX = "${"
_REFERENCE_SUFFIX = "}"


def parse_directory(path: str, only_files: "set[str] | None" = None) -> dict[tuple[str, str], dict[str, Any]]:
    """Every `*.tf` file under `path` (recursively), merged into one flat
    dict. A file that fails to parse (a real HCL syntax error) raises --
    a CI check must never silently skip a file it couldn't read, that
    would be a false sense of coverage, not a legitimate skip.

    `only_files` (used by --changed-only): when given, only files whose
    resolved absolute path is in this set are parsed -- the rest are
    skipped. This is why --changed-only restricts the SCAN at parse time
    rather than filtering resources afterwards: the Terraform key is
    (resource_type, resource_name), the source file isn't retained past
    parsing, so the only correct way to scope by file is to not parse the
    unchanged files at all."""
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    for tf_file in sorted(Path(path).rglob("*.tf")):
        if only_files is not None and str(tf_file.resolve()) not in only_files:
            continue
        with open(tf_file, encoding="utf-8") as f:
            text = f.read()
        file_resources = parse_source(text)
        for (resource_type, resource_name), body in file_resources.items():
            source_location.attach(
                body, str(tf_file),
                source_location.terraform_decl_line(text, resource_type, resource_name),
            )
        resources.update(file_resources)
    return resources


def parse_source(text: str) -> dict[tuple[str, str], dict[str, Any]]:
    """One `.tf` file's own content -- exposed separately from
    `parse_directory` so tests never need a real file on disk."""
    parsed = hcl2.loads(text)
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    for block in parsed.get("resource", []):
        for resource_type, named in block.items():
            for resource_name, body in named.items():
                resources[(resource_type, resource_name)] = body
    return resources


def resolve_reference(value: Any) -> tuple[str, str, str] | None:
    """Given a raw HCL attribute value, returns `(resource_type,
    resource_name, attribute)` if it's a reference to another resource's
    own attribute (e.g. `aws_s3_bucket.data.id`), else `None` -- never a
    guess, a value that isn't a real reference expression (a literal
    string, a number, a data-source reference, a variable reference)
    correctly resolves to `None`."""
    if not isinstance(value, str):
        return None
    inner = value
    if inner.startswith(_REFERENCE_PREFIX) and inner.endswith(_REFERENCE_SUFFIX):
        inner = inner[len(_REFERENCE_PREFIX):-len(_REFERENCE_SUFFIX)]
    parts = inner.split(".")
    # A resource reference is always at least 3 segments:
    # resource_type.resource_name.attribute (data sources use a 4-segment
    # "data.TYPE.NAME.attr" shape, deliberately not resolved here -- a
    # public_access_block referencing a data source rather than a
    # resource this same parse run also collected can never be
    # correlated anyway).
    if len(parts) != 3 or parts[0] in ("var", "local", "data", "module"):
        return None
    return parts[0], parts[1], parts[2]
