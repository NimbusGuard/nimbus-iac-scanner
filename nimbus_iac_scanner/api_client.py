"""Calls nimbus_app's own `POST /iac/gate-check` -- a service-account-
authenticated route (see that repo's `app/routes/iac.py`), the SAME
`X-API-Key` header every other nimbus_app service-account caller
already uses. Batches at 100 resources per call (the route's own
documented max_length) -- a scan with more than 100 resources makes
multiple calls, results concatenated; `passed` is the AND across every
batch."""
from dataclasses import dataclass
from typing import Any

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


def run_gate_check(api_url: str, api_key: str, resources: list[dict[str, Any]]) -> GateCheckResult:
    """`api_url` is the base nimbus_app API URL (e.g.
    `https://api.nimbusguard.io/v1` or a local dev URL) -- this function
    appends `/iac/gate-check` itself. `resources` already in nimbus_app's
    own gate-check shape (see resource_mapping.py) -- this function does
    no further transformation."""
    if not resources:
        return GateCheckResult(passed=True, results=[])

    passed = True
    all_results: list[dict[str, Any]] = []
    for i in range(0, len(resources), GATE_CHECK_BATCH_SIZE):
        batch = resources[i:i + GATE_CHECK_BATCH_SIZE]
        try:
            response = requests.post(
                f"{api_url.rstrip('/')}/iac/gate-check",
                json={"resources": batch},
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

    return GateCheckResult(passed=passed, results=all_results)
