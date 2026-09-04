"""Parses real AWS CloudFormation templates (JSON or YAML) into a flat
`{logical_id: {"Type": ..., "Properties": {...}}}` dict -- the
CloudFormation counterpart to `terraform_parser.py`'s own flat resource
dict, kept as a separate module since the two formats' own resolution
concerns are genuinely different (Terraform needs cross-resource
reference correlation for several concepts CloudFormation expresses as
plain, already-inline properties on one resource -- see
`cloudformation_mapping.py`'s own docstring).

**Detection is deliberately conservative**: a `.json`/`.yaml`/`.yml`
file is only treated as a CloudFormation template when it has a
top-level `Resources` key whose value is itself a dict -- the one
structural fact every real CloudFormation template shares
(`AWSTemplateFormatVersion` is genuinely optional per AWS's own docs,
so requiring it would silently skip real templates that omit it). A
JSON/YAML file that doesn't look like a template (no `Resources` key,
or a non-dict value) is silently skipped, never treated as an empty
template."""
from pathlib import Path
from typing import Any

import yaml

from nimbus_iac_scanner import source_location

# (template_file_path, logical_id) -- unlike Terraform, where a
# resource's own (type, name) pair is already globally unique across an
# entire combined configuration by design, a CloudFormation logical id
# is only unique WITHIN its own template file -- two independent stack
# templates in the same directory could easily both declare "MyBucket".
# Keying by the file path too avoids silently clobbering one template's
# resource with another's during the directory-wide merge below.
ResourceKey = tuple[str, str]


class _CfnYamlLoader(yaml.SafeLoader):
    """CloudFormation's own YAML short-form intrinsic-function tags
    (`!Ref`, `!GetAtt`, `!Sub`, ...) aren't valid plain YAML -- a bare
    `yaml.safe_load` raises on them. These constructors exist ONLY so
    parsing a real template doesn't crash when one appears on some
    OTHER, unrelated property elsewhere in the template; none of this
    tool's own mapped properties are ever built from an intrinsic
    function, so the constructed dict is never actually resolved or
    evaluated, just tolerated."""


def _bare_constructor(name: str):
    def constructor(loader: yaml.SafeLoader, node: yaml.Node):
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node)
        else:
            value = loader.construct_mapping(node)
        return {name: value}
    return constructor


# !Ref and !Condition map to a bare key (no "Fn::" prefix) in the real,
# long-form JSON shape -- every other intrinsic function tag maps to
# "Fn::<Name>". Confirmed against AWS's own intrinsic-function reference,
# not guessed.
_CfnYamlLoader.add_constructor("!Ref", _bare_constructor("Ref"))
_CfnYamlLoader.add_constructor("!Condition", _bare_constructor("Condition"))
for _tag in (
    "GetAtt", "GetAZs", "ImportValue", "Join", "Sub", "Select", "Split",
    "FindInMap", "Base64", "Cidr", "If", "Not", "Equals", "And", "Or",
):
    _CfnYamlLoader.add_constructor(f"!{_tag}", _bare_constructor(f"Fn::{_tag}"))


def _load_template(text: str, is_yaml: bool) -> Any:
    if is_yaml:
        return yaml.load(text, Loader=_CfnYamlLoader)
    import json
    return json.loads(text)


def parse_source(text: str, is_yaml: bool, file_key: str = "") -> dict[ResourceKey, dict[str, Any]]:
    """One template file's own content. Returns `{}` (never raises) for
    a file that parses cleanly but doesn't look like a CloudFormation
    template (no top-level `Resources` dict) -- this lets
    `parse_directory` walk every `.json`/`.yaml`/`.yml` file in a
    project without needing to pre-filter which ones are actually
    CloudFormation. `file_key` disambiguates a logical id that could
    collide with another, unrelated template's own use of the same
    name -- callers that only ever handle one template at a time (e.g.
    tests) can safely leave it as the default empty string."""
    document = _load_template(text, is_yaml)
    if not isinstance(document, dict):
        return {}
    resources = document.get("Resources")
    if not isinstance(resources, dict):
        return {}
    return {
        (file_key, logical_id): body for logical_id, body in resources.items()
        if isinstance(body, dict) and "Type" in body
    }


def parse_directory(path: str, only_files: "set[str] | None" = None) -> dict[ResourceKey, dict[str, Any]]:
    """Every `.json`/`.yaml`/`.yml` file under `path` (recursively) that
    parses as a real CloudFormation template, merged into one flat
    dict. A genuinely malformed file (real JSON/YAML syntax error)
    raises -- same "never silently skip a file we couldn't read"
    posture as `terraform_parser.parse_directory`. A well-formed
    JSON/YAML file that just isn't a CloudFormation template (no
    `Resources` key) contributes nothing, not an error.

    `only_files` (used by --changed-only): when given, only files whose
    resolved absolute path is in this set are parsed."""
    resources: dict[ResourceKey, dict[str, Any]] = {}
    for pattern, is_yaml in ((".json", False), (".yaml", True), (".yml", True)):
        for tpl_file in sorted(Path(path).rglob(f"*{pattern}")):
            if only_files is not None and str(tpl_file.resolve()) not in only_files:
                continue
            with open(tpl_file, encoding="utf-8") as f:
                text = f.read()
            file_resources = parse_source(text, is_yaml, file_key=str(tpl_file))
            for (_file_key, logical_id), body in file_resources.items():
                source_location.attach(
                    body, str(tpl_file), source_location.cloudformation_decl_line(text, logical_id),
                )
            resources.update(file_resources)
    return resources
