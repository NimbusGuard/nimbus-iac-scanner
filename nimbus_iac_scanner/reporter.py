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
        if threshold is None:
            return True
        severity = r.get("severity")
        rank = SEVERITY_RANK.get(severity)
        if rank is None or rank >= threshold:
            return True
    return False


def format_report(results: list[dict[str, Any]], unmapped_resource_types: set[str]) -> str:
    lines = []
    failing = [r for r in results if r.get("status") == "FAIL"]
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

    lines.append("")
    lines.append(f"Passed/other ({len(other)}), failed ({len(failing)}).")

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
