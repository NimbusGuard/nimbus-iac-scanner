"""Calls nimbus_app's own `POST /iac/gate-check` -- a service-account-
authenticated route (see that repo's `app/routes/iac.py`), the SAME
`X-API-Key` header every other nimbus_app service-account caller
already uses. Batches at 100 resources per call (the route's own
documented max_length) -- a scan with more than 100 resources makes
multiple calls, results concatenated; `passed` is the AND across every
batch."""
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

GATE_CHECK_BATCH_SIZE = 100
DEFAULT_TIMEOUT_SECONDS = 30


class GateCheckError(Exception):
    """Any failure reaching or getting a real response from
    nimbus_app's own gate-check endpoint -- a network error, a non-2xx
    HTTP status, or a malformed response body. The CLI treats this as a
    hard failure (non-zero exit), never as "no findings" -- an
    unreachable API must never look like a clean pass."""


@dataclass
class GateCheckResult:
    passed: bool
    results: list[dict[str, Any]]
    # The nimbus_app IacScan id(s) each batch was recorded as -- one per
    # HTTP call. A scan with <=100 resources (the overwhelming common
    # case) makes one call and gets one id; a larger scan is split into
    # several IacScans that share the same `source` metadata (repo/
    # branch/commit/PR), so the UI can still group them by commit.
    scan_ids: list[str] = field(default_factory=list)
    # The org's central IaC block policy (Organization.iac_block_severity),
    # as returned by the gate-check. The CLI uses this as its default
    # blocking threshold when --min-severity isn't passed. None = "any
    # FAIL blocks". Every batch of one run returns the same value (same
    # org); the last non-None wins.
    block_severity: Optional[str] = None


def run_gate_check(
    api_url: str,
    api_key: str,
    resources: list[dict[str, Any]],
    source: Optional[dict[str, Any]] = None,
) -> GateCheckResult:
    """`api_url` is the base nimbus_app API URL (e.g.
    `https://api.nimbusguard.io/v1` or a local dev URL) -- this function
    appends `/iac/gate-check` itself. `resources` already in nimbus_app's
    own gate-check shape (see resource_mapping.py) -- this function does
    no further transformation. `source` (repo/branch/commit/PR/
    ci_provider, see ci_source.py) is sent unchanged on EVERY batch, so
    the persisted IacScan(s) for one CI run all carry the same origin."""
    if not resources:
        return GateCheckResult(passed=True, results=[])

    passed = True
    all_results: list[dict[str, Any]] = []
    scan_ids: list[str] = []
    block_severity: Optional[str] = None
    for i in range(0, len(resources), GATE_CHECK_BATCH_SIZE):
        batch = resources[i:i + GATE_CHECK_BATCH_SIZE]
        request_body: dict[str, Any] = {"resources": batch}
        if source is not None:
            request_body["source"] = source
        try:
            response = requests.post(
                f"{api_url.rstrip('/')}/iac/gate-check",
                json=request_body,
                headers={"X-API-Key": api_key},
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as e:
            raise GateCheckError(f"Could not reach nimbus_app's gate-check endpoint: {e}") from e

        if response.status_code != 200:
            raise GateCheckError(
                f"Gate-check request failed with HTTP {response.status_code}: {response.text}"
            )

        try:
            body = response.json()
        except ValueError as e:
            raise GateCheckError(f"Gate-check returned a non-JSON response: {response.text}") from e

        if body.get("passed") is False:
            passed = False
        all_results.extend(body.get("results", []))
        scan_id = body.get("scan_id")
        if scan_id:
            scan_ids.append(str(scan_id))
        if body.get("block_severity") is not None:
            block_severity = body["block_severity"]

    return GateCheckResult(passed=passed, results=all_results, scan_ids=scan_ids, block_severity=block_severity)
