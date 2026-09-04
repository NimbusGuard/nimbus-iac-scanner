"""Human-readable report + the configurable "fail the build by
severity" policy -- both pure functions over the gate-check's own
`results` list, no I/O."""
from typing import Any, Optional

# Same severity vocabulary Finding.severity already uses across the
# whole nimbusguard platform (CRITICAL > HIGH > MEDIUM > LOW >
# INFORMATIONAL) -- never a CLI-invented scale.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def should_fail_build(results: list[dict[str, Any]], min_severity: Optional[str] = None) -> bool:
    """No `min_severity` (the default): fails iff at least one control
    genuinely evaluated FAIL -- byte-identical to the gate-check API's
    own `passed` field, so a caller who never sets this flag gets
    exactly the "listo cuando" behavior (any real misconfiguration
    blocks the build).

    With `min_severity` set, only a FAIL at or above that severity
    blocks the build -- a FAIL whose own `severity` is missing/`None`
    is treated as meeting the threshold anyway (fails closed): there's
    no honest way to confirm it's BELOW the threshold, and a security
    gate silently letting an unclassified failure through would be the
    wrong direction to err in."""
    threshold = SEVERITY_RANK.get(min_severity) if min_severity else None
    for r in results:
        if r.get("status") != "FAIL":
            continue
        # An excepted FAIL (a stored exception rule or an inline/.nimbusignore
        # directive the server accepted) never blocks -- the server already
        # decided it doesn't, and the gate must stay consistent with that.
        if r.get("excepted"):
            continue
        if threshold is None:
            return True
        severity = r.get("severity")
        rank = SEVERITY_RANK.get(severity)
        if rank is None or rank >= threshold:
            return True
    return False


def format_report(results: list[dict[str, Any]], unmapped_resource_types: set[str]) -> str:
    lines = []
    all_fail = [r for r in results if r.get("status") == "FAIL"]
    failing = [r for r in all_fail if not r.get("excepted")]
    ignored = [r for r in all_fail if r.get("excepted")]
    other = [r for r in results if r.get("status") != "FAIL"]

    if failing:
        lines.append(f"FAILED ({len(failing)}):")
        for r in sorted(failing, key=lambda r: (r.get("identifier") or "", r.get("control_id") or "")):
            lines.append(
                f"  [{r.get('severity') or 'UNKNOWN'}] {r.get('identifier') or '(no identifier)'} "
                f"-- {r.get('control_id')}: {r.get('control_name')}"
            )
            if r.get("message"):
                lines.append(f"      {r['message']}")

    if ignored:
        lines.append("")
        lines.append(f"IGNORED ({len(ignored)}) -- a real FAIL, suppressed by an exception (does not block):")
        for r in sorted(ignored, key=lambda r: (r.get("identifier") or "", r.get("control_id") or "")):
            reason = r.get("exception_reason") or "excepted"
            src = r.get("exception_source") or ""
            lines.append(
                f"  [{r.get('severity') or 'UNKNOWN'}] {r.get('identifier') or '(no identifier)'} "
                f"-- {r.get('control_id')} ({reason} via {src})"
            )

    lines.append("")
    lines.append(f"Passed/other ({len(other)}), failed ({len(failing)}), ignored ({len(ignored)}).")

    if unmapped_resource_types:
        lines.append("")
        lines.append(
            "Note: the following Terraform resource types were found but aren't "
            "mapped to a nimbus_app control yet, so they were NOT evaluated "
            "(see nimbus-iac-scanner's own README for the current coverage list):"
        )
        for rt in sorted(unmapped_resource_types):
            lines.append(f"  - {rt}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GitHub/GitLab-flavored markdown report -- used ONLY for the PR/MR comment
# (see cli.py). The plain-text `format_report` above stays the terminal/CI-log
# output; a code-host comment renders markdown, so a wall of text there reads
# as noise. This produces a summary badge line, a severity-count table, and
# the full findings as a real, worst-first table inside a collapsible section
# (the same shape CodeQL/Dependabot/tfsec comments use).
# ---------------------------------------------------------------------------

_SEVERITY_BADGE = {
    "CRITICAL": "🔴 Critical",
    "HIGH": "🟠 High",
    "MEDIUM": "🟡 Medium",
    "LOW": "🔵 Low",
    "INFORMATIONAL": "⚪ Info",
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _md_cell(value: Any) -> str:
    """Make a value safe to drop into a markdown table cell: a literal
    `|` would start a new column and a newline would break the row."""
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _resource_link(
    identifier: Optional[str],
    source_by_identifier: Optional[dict],
    blob_base: Optional[str],
) -> str:
    """The Resource table cell: `identifier` in code, made a clickable link
    to `<blob_base>/<file>#L<line>` when the source location is known and the
    file path is repo-root-relative (the standard CI checkout). Falls back to
    plain code otherwise -- never a broken link."""
    code = f"`{_md_cell(identifier or '—')}`"
    if not (identifier and source_by_identifier and blob_base):
        return code
    src = source_by_identifier.get(identifier) or {}
    file = src.get("file")
    if not file or file.startswith("/") or file.startswith(".."):
        return code
    from urllib.parse import quote
    anchor = f"#L{src['line']}" if src.get("line") else ""
    return f"[{code}]({blob_base}/{quote(file)}{anchor})"


def format_markdown_report(
    results: list[dict[str, Any]],
    unmapped_resource_types: set[str],
    source_by_identifier: Optional[dict] = None,
    blob_base: Optional[str] = None,
) -> str:
    from collections import Counter

    all_fail = [r for r in results if r.get("status") == "FAIL"]
    blocking = [r for r in all_fail if not r.get("excepted")]
    ignored = [r for r in all_fail if r.get("excepted")]

    def sort_key(r: dict[str, Any]) -> tuple:
        return (-SEVERITY_RANK.get(r.get("severity"), -1), r.get("identifier") or "", r.get("control_id") or "")

    def _ignored_section() -> list[str]:
        if not ignored:
            return []
        rows = [f"<details><summary><b>{len(ignored)} ignored (suppressed by an exception, not blocking)</b></summary>", "",
                "| Severity | Resource | Control | Suppressed by |", "|:--|:--|:--|:--|"]
        for r in sorted(ignored, key=sort_key):
            badge = _SEVERITY_BADGE.get(r.get("severity") or "UNKNOWN", r.get("severity") or "UNKNOWN")
            resource = _resource_link(r.get("identifier"), source_by_identifier, blob_base)
            src = _md_cell(f"{r.get('exception_reason') or 'excepted'} via {r.get('exception_source') or '—'}")
            rows.append(f"| {badge} | {resource} | `{_md_cell(r.get('control_id') or '—')}` | {src} |")
        rows += ["", "</details>"]
        return ["", *rows]

    def _unmapped_note() -> list[str]:
        if not unmapped_resource_types:
            return []
        return ["", f"<sub>{len(unmapped_resource_types)} resource type(s) aren't mapped to a control yet and were not evaluated.</sub>"]

    if not blocking:
        head = "**✅ Passed** — no blocking misconfigurations found in the evaluated resources."
        if ignored:
            head += f" <sub>({len(ignored)} finding{'s' if len(ignored) != 1 else ''} ignored via an exception.)</sub>"
        return "\n".join([head, *_ignored_section(), *_unmapped_note()])

    counts = Counter(r.get("severity") or "UNKNOWN" for r in blocking)
    present = [s for s in _SEVERITY_ORDER if counts.get(s)]

    out: list[str] = [
        f"**❌ Blocking — {len(blocking)} finding{'s' if len(blocking) != 1 else ''}** "
        f"({len(results)} checks evaluated).",
        "",
    ]
    if present:
        out.append("| " + " | ".join(_SEVERITY_BADGE[s] for s in present) + " |")
        out.append("|" + "|".join([":--:"] * len(present)) + "|")
        out.append("| " + " | ".join(f"**{counts[s]}**" for s in present) + " |")
        out.append("")

    out.append(f"<details><summary><b>View all {len(blocking)} findings</b></summary>")
    out.append("")
    out.append("| Severity | Resource | Control | Issue |")
    out.append("|:--|:--|:--|:--|")
    for r in sorted(blocking, key=sort_key):
        sev = r.get("severity") or "UNKNOWN"
        badge = _SEVERITY_BADGE.get(sev, sev)
        issue = r.get("message") or r.get("control_name") or ""
        resource = _resource_link(r.get("identifier"), source_by_identifier, blob_base)
        out.append(
            f"| {badge} | {resource} "
            f"| `{_md_cell(r.get('control_id') or '—')}` | {_md_cell(issue)} |"
        )
    out += ["", "</details>"]
    out += _ignored_section()
    out += _unmapped_note()

    return "\n".join(out)
