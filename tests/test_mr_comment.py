from unittest.mock import Mock, patch

import pytest

from nimbus_iac_scanner.mr_comment import MrCommentError, find_merge_request_iid, post_or_update_comment


def test_find_merge_request_iid_parses_a_real_ci_variable():
    assert find_merge_request_iid("9") == 9


def test_find_merge_request_iid_none_when_not_a_merge_request_pipeline():
    assert find_merge_request_iid(None) is None
    assert find_merge_request_iid("") is None


def test_find_merge_request_iid_none_for_a_malformed_value():
    assert find_merge_request_iid("not-a-number") is None


def _fake_response(status_code, json_body=None, text="error"):
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    resp.json = Mock(return_value=json_body or [])
    return resp


def test_posts_a_new_note_when_none_exists_yet():
    get_resp = _fake_response(200, [])
    post_resp = _fake_response(201)
    with patch("nimbus_iac_scanner.mr_comment.requests.get", return_value=get_resp), \
         patch("nimbus_iac_scanner.mr_comment.requests.post", return_value=post_resp) as mock_post:
        post_or_update_comment("https://gitlab.example.com", "42", 9, "tok", "report body")
    assert mock_post.called
    assert "report body" in mock_post.call_args.kwargs["json"]["body"]
    assert mock_post.call_args.kwargs["headers"]["PRIVATE-TOKEN"] == "tok"


def test_updates_the_existing_marked_note_instead_of_posting_a_new_one():
    get_resp = _fake_response(200, [{"id": 555, "body": "<!-- nimbus-iac-scanner:report -->\n\nold report"}])
    put_resp = _fake_response(200)
    with patch("nimbus_iac_scanner.mr_comment.requests.get", return_value=get_resp), \
         patch("nimbus_iac_scanner.mr_comment.requests.post") as mock_post, \
         patch("nimbus_iac_scanner.mr_comment.requests.put", return_value=put_resp) as mock_put:
        post_or_update_comment("https://gitlab.example.com", "42", 9, "tok", "new report")
    mock_post.assert_not_called()
    assert mock_put.called
    assert "new report" in mock_put.call_args.kwargs["json"]["body"]


def test_raises_on_a_real_api_failure_listing_notes():
    with patch("nimbus_iac_scanner.mr_comment.requests.get", return_value=_fake_response(403)):
        with pytest.raises(MrCommentError):
            post_or_update_comment("https://gitlab.example.com", "42", 9, "tok", "report")


def test_uses_the_real_server_url_never_hardcoded_to_gitlab_com():
    """The GitLab CI template is meant to work against a self-hosted
    instance too, not just SaaS -- the base URL must always come from
    the real, given server URL."""
    get_resp = _fake_response(200, [])
    post_resp = _fake_response(201)
    with patch("nimbus_iac_scanner.mr_comment.requests.get", return_value=get_resp) as mock_get, \
         patch("nimbus_iac_scanner.mr_comment.requests.post", return_value=post_resp):
        post_or_update_comment("https://gitlab.internal.acme.com", "7", 3, "tok", "report")
    assert mock_get.call_args.args[0].startswith("https://gitlab.internal.acme.com/api/v4/")
