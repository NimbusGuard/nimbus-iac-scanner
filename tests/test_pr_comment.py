import json
from unittest.mock import Mock, patch

import pytest

from nimbus_iac_scanner.pr_comment import (
    PrCommentError,
    find_pull_request_number,
    post_or_update_comment,
)


def test_find_pull_request_number_reads_the_real_event_payload(tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 42}}))
    assert find_pull_request_number(str(event_file)) == 42


def test_find_pull_request_number_none_for_a_non_pr_event(tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"ref": "refs/heads/main"}))
    assert find_pull_request_number(str(event_file)) is None


def test_find_pull_request_number_none_when_no_event_path_given():
    assert find_pull_request_number(None) is None


def test_find_pull_request_number_none_for_a_missing_file():
    assert find_pull_request_number("/does/not/exist.json") is None


def _fake_response(status_code, json_body=None, text="error"):
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    resp.json = Mock(return_value=json_body or [])
    return resp


def test_posts_a_new_comment_when_none_exists_yet():
    get_resp = _fake_response(200, [])
    post_resp = _fake_response(201)
    with patch("nimbus_iac_scanner.pr_comment.requests.get", return_value=get_resp), \
         patch("nimbus_iac_scanner.pr_comment.requests.post", return_value=post_resp) as mock_post:
        post_or_update_comment("acme/infra", 7, "tok", "report body")
    assert mock_post.called
    assert "report body" in mock_post.call_args.kwargs["json"]["body"]


def test_updates_the_existing_marked_comment_instead_of_posting_a_new_one():
    get_resp = _fake_response(200, [{"id": 999, "body": "<!-- nimbus-iac-scanner:report -->\n\nold report"}])
    patch_resp = _fake_response(200)
    with patch("nimbus_iac_scanner.pr_comment.requests.get", return_value=get_resp), \
         patch("nimbus_iac_scanner.pr_comment.requests.post") as mock_post, \
         patch("nimbus_iac_scanner.pr_comment.requests.patch", return_value=patch_resp) as mock_patch:
        post_or_update_comment("acme/infra", 7, "tok", "new report")
    mock_post.assert_not_called()
    assert mock_patch.called
    assert "new report" in mock_patch.call_args.kwargs["json"]["body"]


def test_raises_on_a_real_api_failure_listing_comments():
    with patch("nimbus_iac_scanner.pr_comment.requests.get", return_value=_fake_response(403)):
        with pytest.raises(PrCommentError):
            post_or_update_comment("acme/infra", 7, "tok", "report")
