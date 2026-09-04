from unittest.mock import Mock, patch

import pytest
import requests

from nimbus_iac_scanner.api_client import GATE_CHECK_BATCH_SIZE, GateCheckError, run_gate_check


def _fake_response(status_code=200, json_body=None, text="error"):
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    resp.json = Mock(return_value=json_body or {})
    return resp


def test_empty_resource_list_never_calls_the_api():
    with patch("nimbus_iac_scanner.api_client.requests.post") as mock_post:
        result = run_gate_check("https://api.example.com", "key", [])
    mock_post.assert_not_called()
    assert result.passed is True
    assert result.results == []


def test_successful_call_returns_passed_and_results():
    body = {"passed": True, "results": [{"identifier": "x", "status": "PASS"}]}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)):
        result = run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert result.passed is True
    assert result.results == body["results"]


def test_a_real_failure_result_sets_passed_false():
    body = {"passed": False, "results": [{"identifier": "x", "status": "FAIL"}]}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)):
        result = run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert result.passed is False


def test_uses_the_x_api_key_header():
    body = {"passed": True, "results": []}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)) as mock_post:
        run_gate_check("https://api.example.com", "the-real-key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    _, kwargs = mock_post.call_args
    assert kwargs["headers"]["X-API-Key"] == "the-real-key"


def test_non_200_status_raises_gate_check_error():
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(502, text="bad gateway")):
        with pytest.raises(GateCheckError):
            run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])


def test_network_failure_raises_gate_check_error():
    with patch("nimbus_iac_scanner.api_client.requests.post", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(GateCheckError):
            run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])


def test_malformed_json_response_raises_gate_check_error():
    resp = _fake_response(200)
    resp.json = Mock(side_effect=ValueError("not json"))
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=resp):
        with pytest.raises(GateCheckError):
            run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])


def test_batches_over_100_resources_into_multiple_calls():
    resources = [{"provider": "aws", "resource_type": "s3_bucket", "identifier": str(i)} for i in range(GATE_CHECK_BATCH_SIZE + 1)]
    body = {"passed": True, "results": []}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)) as mock_post:
        run_gate_check("https://api.example.com", "key", resources)
    assert mock_post.call_count == 2
    first_batch = mock_post.call_args_list[0].kwargs["json"]["resources"]
    second_batch = mock_post.call_args_list[1].kwargs["json"]["resources"]
    assert len(first_batch) == GATE_CHECK_BATCH_SIZE
    assert len(second_batch) == 1


def test_a_failure_in_any_batch_makes_the_whole_result_fail():
    resources = [{"provider": "aws", "resource_type": "s3_bucket", "identifier": str(i)} for i in range(GATE_CHECK_BATCH_SIZE + 1)]
    responses = [
        _fake_response(200, {"passed": True, "results": []}),
        _fake_response(200, {"passed": False, "results": [{"status": "FAIL"}]}),
    ]
    with patch("nimbus_iac_scanner.api_client.requests.post", side_effect=responses):
        result = run_gate_check("https://api.example.com", "key", resources)
    assert result.passed is False


def test_scan_ids_are_collected_from_the_response():
    body = {"passed": False, "results": [{"status": "FAIL"}], "scan_id": "11111111-1111-1111-1111-111111111111"}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)):
        result = run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert result.scan_ids == ["11111111-1111-1111-1111-111111111111"]


def test_source_is_sent_on_every_batch():
    resources = [{"provider": "aws", "resource_type": "s3_bucket", "identifier": str(i)} for i in range(GATE_CHECK_BATCH_SIZE + 1)]
    source = {"repository": "acme/infra", "branch": "main", "ci_provider": "github"}
    responses = [
        _fake_response(200, {"passed": True, "results": [], "scan_id": "a"}),
        _fake_response(200, {"passed": True, "results": [], "scan_id": "b"}),
    ]
    with patch("nimbus_iac_scanner.api_client.requests.post", side_effect=responses) as mock_post:
        result = run_gate_check("https://api.example.com", "key", resources, source=source)
    assert mock_post.call_count == 2
    for call in mock_post.call_args_list:
        assert call.kwargs["json"]["source"] == source
    assert result.scan_ids == ["a", "b"]


def test_no_source_key_when_source_is_none():
    body = {"passed": True, "results": []}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)) as mock_post:
        run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert "source" not in mock_post.call_args.kwargs["json"]


def test_block_severity_is_captured_from_the_response():
    body = {"passed": True, "results": [], "block_severity": "HIGH"}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)):
        result = run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert result.block_severity == "HIGH"


def test_block_severity_none_when_absent():
    body = {"passed": True, "results": []}
    with patch("nimbus_iac_scanner.api_client.requests.post", return_value=_fake_response(200, body)):
        result = run_gate_check("https://api.example.com", "key", [{"provider": "aws", "resource_type": "s3_bucket"}])
    assert result.block_severity is None
