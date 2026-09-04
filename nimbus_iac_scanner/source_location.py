"""Best-effort source `(file, line)` for a parsed IaC resource, so a finding
can link back to the exact declaration in the repo (a clickable file:line link
in the PR/MR comment, and the same fields sent to nimbus_app for its own UI).

Line lookup is a text scan of the resource's own declaration -- neither
python-hcl2 4.3.5 nor the compiled-ARM Bicep path exposes real source line
numbers, and scanning for the declaration line is reliable enough for a link.
It returns `None` (never a guessed line) when the declaration can't be located
-- the finding then links to the file without a line anchor, still useful."""
import re
from typing import Optional

# Attached to each parsed resource body by the parsers; moved onto the mapped
# resource (`source_file`/`source_line`) by each format's `map_resources`.
SOURCE_FILE_KEY = "__source_file__"
SOURCE_LINE_KEY = "__source_line__"


def terraform_decl_line(text: str, resource_type: str, resource_name: str) -> Optional[int]:
    """The 1-based line of `resource "TYPE" "NAME" {` in a `.tf` file."""
    pattern = re.compile(rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"')
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.match(line):
            return i
    return None


def cloudformation_decl_line(text: str, logical_id: str) -> Optional[int]:
    """The 1-based line where a CloudFormation logical id is declared as a
    mapping key -- YAML `  LogicalId:` or JSON `"LogicalId":`. The first match
    top-down is the declaration under `Resources:` (which precedes any
    `Ref`/`DependsOn` use of the same id in a real template)."""
    yaml_key = re.compile(rf'^\s+{re.escape(logical_id)}\s*:')
    json_key = re.compile(rf'^\s*"{re.escape(logical_id)}"\s*:')
    for i, line in enumerate(text.splitlines(), start=1):
        if yaml_key.match(line) or json_key.match(line):
            return i
    return None


def bicep_decl_line(text: str, name: Optional[str]) -> Optional[int]:
    """Best-effort line of a Bicep resource, anchored on its own
    `name: 'NAME'` property (the one stable value that survives compilation).
    `None` when the name is a non-literal expression (a param/variable), since
    the compiled name then won't appear verbatim in the source -- the finding
    links to the file without a line, never a wrong one."""
    if not name:
        return None
    pattern = re.compile(rf"""\bname\s*:\s*['"]{re.escape(name)}['"]""")
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return i
    return None


def attach(body: dict, file_path: str, line: Optional[int]) -> None:
    body[SOURCE_FILE_KEY] = file_path
    body[SOURCE_LINE_KEY] = line


def enrich(result: dict, body: dict) -> dict:
    """Copy the source (file, line) captured on the parsed `body` onto the
    mapped resource `result` (as `source_file`/`source_line`), so it travels
    both to the gate-check request (nimbus_app persists it) and to the
    client-side PR/MR-comment link builder. A no-op when the parser didn't
    record a source (e.g. a test that maps a hand-built body)."""
    if body.get(SOURCE_FILE_KEY):
        result["source_file"] = body[SOURCE_FILE_KEY]
        result["source_line"] = body.get(SOURCE_LINE_KEY)
    return result
