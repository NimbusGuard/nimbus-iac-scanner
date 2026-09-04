"""Developer self-service IaC suppression: inline `# nimbus:ignore`
comments and a repo-root `.nimbusignore` file. Both are versioned in the
customer's own repo (like `.gitignore`) and re-resolved from source every
run -- they are NOT stored on the platform.

The CLI only RESOLVES these directives from the repo and sends them with
the gate-check request; nimbus_app is the single evaluator (it decides,
per its own org governance, whether each directive actually applies), so
the recorded IacScan.passed always matches the CLI's exit code. See that
repo's app/services/iac_exceptions.py.

Grammar
-------
Inline (on the resource's own declaration line, or the comment line(s)
directly above it -- the checkov/tfsec convention):

    # nimbus:ignore <CONTROL_ID|*> [reason=false_positive|risk_accepted|compensating_control] [expires=YYYY-MM-DD] [note="..."]

`.nimbusignore` (repo root, one directive per line, `#` comments allowed):

    <CONTROL_ID|*> <identifier-glob> [reason=...] [expires=YYYY-MM-DD] [file=<path-glob>] [note="..."]

`<CONTROL_ID>` is an exact id (e.g. NG-AWS-S3-001) or `*` (all controls).
An inline directive maps to the ONE resource it annotates (an exact
address). A `.nimbusignore` `<identifier-glob>` is a glob against the
resource address (e.g. `aws_s3_bucket.*`); an optional `file=<path-glob>`
narrows it to matching source files (resolved here, client-side, to exact
addresses).
"""
import fnmatch
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, time, timezone
from typing import Optional

_INLINE_RE = re.compile(r"(?:#|//)\s*nimbus:ignore\s+(.+?)\s*$")
_COMMENT_OR_BLANK_RE = re.compile(r"^\s*(?:#|//).*$|^\s*$")
_VALID_REASONS = {"false_positive", "risk_accepted", "compensating_control"}
# How many purely comment/blank lines may sit between an inline directive
# and the resource declaration it annotates (0 = inline on the decl line).
_MAX_ABOVE_GAP = 5


@dataclass
class Directive:
    control_id: str
    source: str  # "inline" | "nimbusignore"
    identifier: Optional[str] = None
    reason_type: Optional[str] = None
    expires_at: Optional[str] = None  # ISO 8601, end-of-day UTC of an expires=YYYY-MM-DD
    note: Optional[str] = None

    def to_payload(self) -> dict:
        d = {"control_id": self.control_id, "source": self.source}
        if self.identifier is not None:
            d["identifier"] = self.identifier
        if self.reason_type is not None:
            d["reason_type"] = self.reason_type
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        if self.note is not None:
            d["note"] = self.note
        return d


def _expires_to_iso(value: str) -> Optional[str]:
    """`expires=YYYY-MM-DD` -> end-of-day UTC ISO ('valid through that
    day'). None on a malformed date (the directive then has no expiry,
    which for risk_accepted/compensating_control the server rejects)."""
    try:
        d = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None
    return datetime.combine(d, time(23, 59, 59), tzinfo=timezone.utc).isoformat()


def _parse_kwargs(tokens: list[str]) -> dict:
    """Parse `key=value` tokens into reason_type/expires_at/note. Unknown
    keys are ignored (forward-compat). An invalid reason is dropped (the
    directive falls back to the server's false_positive default)."""
    out: dict = {}
    for tok in tokens:
        if "=" not in tok:
            continue
        key, _, value = tok.partition("=")
        key = key.strip().lower()
        if key == "reason" and value in _VALID_REASONS:
            out["reason_type"] = value
        elif key == "expires":
            iso = _expires_to_iso(value)
            if iso:
                out["expires_at"] = iso
        elif key == "note":
            out["note"] = value
    return out


def _target_identifier_for_comment(
    comment_line: int, lines: list[str], decls: list[tuple[int, str]]
) -> Optional[str]:
    """The resource a `# nimbus:ignore` at `comment_line` (1-based)
    annotates: the nearest resource declaration AT or BELOW the comment
    where every line strictly between is blank/comment (inline on the
    decl, or a comment header directly above it). None if none qualifies
    within _MAX_ABOVE_GAP -- a stray directive is not force-attached."""
    best: Optional[tuple[int, str]] = None
    for decl_line, identifier in decls:
        if decl_line < comment_line:
            continue
        if decl_line - comment_line > _MAX_ABOVE_GAP:
            continue
        # every line strictly between the comment and the decl must be blank/comment
        gap_ok = all(
            _COMMENT_OR_BLANK_RE.match(lines[i - 1] if 0 < i <= len(lines) else "")
            for i in range(comment_line + 1, decl_line)
        )
        if gap_ok and (best is None or decl_line < best[0]):
            best = (decl_line, identifier)
    return best[1] if best else None


def parse_inline_ignores(file_text: str, decls: list[tuple[int, str]]) -> list[Directive]:
    """Scan one source file's text for `# nimbus:ignore` directives and
    map each to the resource it annotates (an exact address). `decls` =
    the (1-based decl line, identifier) of every mapped resource in this
    file. A directive that doesn't map to a resource is dropped."""
    lines = file_text.splitlines()
    directives: list[Directive] = []
    for i, line in enumerate(lines, start=1):
        m = _INLINE_RE.search(line)
        if not m:
            continue
        tokens = shlex.split(m.group(1))
        if not tokens:
            continue
        control_id = tokens[0]
        identifier = _target_identifier_for_comment(i, lines, decls)
        if identifier is None:
            continue
        kwargs = _parse_kwargs(tokens[1:])
        directives.append(Directive(control_id=control_id, source="inline", identifier=identifier, **kwargs))
    return directives


def parse_nimbusignore_lines(text: str) -> list[Directive]:
    """Parse a `.nimbusignore` file's text into directives (identifier is
    the glob as written; `file=` is carried as a kwarg and resolved later
    against real resources). `#` comment lines and blanks are skipped."""
    directives: list[Directive] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = shlex.split(line)
        if len(tokens) < 2:
            continue  # need at least <control_id> <identifier-glob>
        control_id, identifier_glob = tokens[0], tokens[1]
        kwargs = _parse_kwargs(tokens[2:])
        # file= is a client-side narrowing, not a server field -- pull it out.
        file_glob = None
        for tok in tokens[2:]:
            if tok.lower().startswith("file="):
                file_glob = tok.partition("=")[2]
                break
        d = Directive(control_id=control_id, source="nimbusignore", identifier=identifier_glob, **kwargs)
        # stash file_glob on the object for the resolver (not part of to_payload)
        d._file_glob = file_glob  # type: ignore[attr-defined]
        directives.append(d)
    return directives


def find_nimbusignore(path: str, override: Optional[str] = None) -> Optional[str]:
    """Locate a `.nimbusignore`: an explicit --nimbusignore override, else
    the first one found walking up from `path` to the filesystem root."""
    if override:
        return override if os.path.isfile(override) else None
    cur = os.path.abspath(path)
    if os.path.isfile(cur):
        cur = os.path.dirname(cur)
    while True:
        candidate = os.path.join(cur, ".nimbusignore")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def resolve_directives(
    path: str,
    mapped_resources: list[dict],
    *,
    inline_enabled: bool = True,
    nimbusignore_override: Optional[str] = None,
) -> list[dict]:
    """Resolve every inline + `.nimbusignore` directive against the scan's
    mapped resources and return the request-`ignores` payloads.

    Inline directives map to an exact resource address. A `.nimbusignore`
    directive keeps its identifier glob (the server matches it) UNLESS it
    carries a `file=<glob>`, in which case it's resolved here to the exact
    addresses of resources whose source_file matches -- so `file=` scoping
    is precise even though the server only matches by address."""
    payloads: list[dict] = []

    if inline_enabled:
        # group mapped resources by their source file, with (decl_line, identifier)
        by_file: dict[str, list[tuple[int, str]]] = {}
        for r in mapped_resources:
            src_file = r.get("source_file")
            ident = r.get("identifier")
            line = r.get("source_line")
            if not src_file or not ident or not line:
                continue
            by_file.setdefault(src_file, []).append((line, ident))
        for src_file, decls in by_file.items():
            abs_path = src_file if os.path.isabs(src_file) else os.path.join(path, src_file)
            if not os.path.isfile(abs_path):
                # source_file may be repo-root-relative; try path as-is too
                abs_path = src_file
            try:
                with open(abs_path, encoding="utf-8") as f:
                    text = f.read()
            except OSError:
                continue
            for d in parse_inline_ignores(text, decls):
                payloads.append(d.to_payload())

    ni_path = find_nimbusignore(path, nimbusignore_override)
    if ni_path:
        try:
            with open(ni_path, encoding="utf-8") as f:
                ni_text = f.read()
        except OSError:
            ni_text = ""
        for d in parse_nimbusignore_lines(ni_text):
            file_glob = getattr(d, "_file_glob", None)
            if not file_glob:
                payloads.append(d.to_payload())
                continue
            # resolve file= to exact addresses among mapped resources
            for r in mapped_resources:
                ident = r.get("identifier")
                src_file = r.get("source_file") or ""
                if not ident:
                    continue
                if fnmatch.fnmatch(ident, d.identifier or "*") and fnmatch.fnmatch(src_file, file_glob):
                    payloads.append(
                        Directive(
                            control_id=d.control_id, source="nimbusignore", identifier=ident,
                            reason_type=d.reason_type, expires_at=d.expires_at, note=d.note,
                        ).to_payload()
                    )
    return payloads
