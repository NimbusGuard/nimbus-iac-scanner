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
import re
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

# A real, previously-unresolved gap found live 2026-09-30: a tag value
# declared as `Name = "${var.prefix}-cwpp-fixtures"` (or the bare,
# unwrapped `Name = var.prefix` shorthand -- confirmed via direct
# python-hcl2 introspection that BOTH shapes normalize to the identical
# "${var.prefix}..." string, so one substitution handles both) used to
# reach nimbus_app's own gate-check payload completely unresolved,
# meaning it could NEVER tag-match a real, already-deployed resource's
# own resolved tag value -- silently defeating Ownership Resolution
# Phase 2's own tag-based correlation (and, for a control that reads a
# tag/attribute value directly rather than just comparing it, this same
# gap could just as easily have produced a wrong PASS/FAIL). Only a
# variable with a real, STATIC `default` declared in a `variable` block
# is ever resolved -- one needing a real tfvars file or a `-var` CLI
# override this scanner has no way to know about is left exactly as
# written, same "omit, don't fabricate" discipline resolve_reference()
# below already established for resource-to-resource references.
_VAR_REFERENCE_RE = re.compile(r"\$\{\s*var\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}")


def parse_variable_defaults(text: str) -> dict[str, Any]:
    """Every `variable` block's own declared `default` in one file's raw
    HCL text -- a variable with no `default` at all is simply omitted,
    never guessed at (it may still be intentionally left unresolved
    everywhere it's referenced, which resolve_variable_references below
    handles by leaving the reference untouched)."""
    parsed = hcl2.loads(text)
    defaults: dict[str, Any] = {}
    for block in parsed.get("variable", []):
        for name, body in block.items():
            if isinstance(body, dict) and "default" in body:
                defaults[name] = body["default"]
    return defaults


def resolve_variable_references(value: Any, variables: dict[str, Any]) -> Any:
    """Recursively substitutes every `${var.NAME}` occurrence found in
    any string within `value` (a resource body's own nested dict/list
    structure -- most importantly its `tags` map) using `variables`'
    own declared defaults. A reference to an undeclared variable, or one
    with no known default, is left exactly as written -- never guessed,
    matching resolve_reference()'s own "a value that isn't confidently
    resolvable resolves to leaving it alone" posture. Only a scalar
    default (str/int/float/bool) is substituted; a default that's itself
    a list/map/object has no single string representation that would be
    honest to splice into an interpolated string, so a reference to one
    of those is also left untouched."""
    if isinstance(value, dict):
        return {k: resolve_variable_references(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_variable_references(v, variables) for v in value]
    if isinstance(value, str):
        def _substitute(match: "re.Match[str]") -> str:
            name = match.group(1)
            default = variables.get(name)
            if isinstance(default, (str, int, float, bool)):
                return str(default)
            return match.group(0)
        return _VAR_REFERENCE_RE.sub(_substitute, value)
    return value


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
    unchanged files at all.

    Variable defaults are collected from EVERY `*.tf` file under `path`
    in a real first pass, regardless of `only_files` -- a `variable`
    block commonly lives in its own file (e.g. `variables.tf`), which a
    narrow --changed-only run may not itself include, and that file
    being unchanged doesn't make its own already-declared defaults any
    less real. Resource parsing (the second pass) still honors
    `only_files` exactly as before -- only which RESOURCES get scanned
    is scoped by it, never which variables can be used to resolve them."""
    all_tf_files = sorted(Path(path).rglob("*.tf"))
    variables: dict[str, Any] = {}
    for tf_file in all_tf_files:
        with open(tf_file, encoding="utf-8") as f:
            variables.update(parse_variable_defaults(f.read()))

    resources: dict[tuple[str, str], dict[str, Any]] = {}
    for tf_file in all_tf_files:
        if only_files is not None and str(tf_file.resolve()) not in only_files:
            continue
        with open(tf_file, encoding="utf-8") as f:
            text = f.read()
        file_resources = parse_source(text)
        for (resource_type, resource_name), body in file_resources.items():
            resolved_body = resolve_variable_references(body, variables)
            file_resources[(resource_type, resource_name)] = resolved_body
            source_location.attach(
                resolved_body, str(tf_file),
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
