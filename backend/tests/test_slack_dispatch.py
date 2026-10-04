import httpx
import pytest

from app.dispatch.slack import dispatch_slack_webhook

pytestmark = pytest.mark.no_db


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://hooks.slack.com/test",
        "https://user:secret@hooks.slack.com/test",
        "https:///missing-host",
    ],
)
def test_invalid_webhook_urls_never_send_a_request(monkeypatch, url):
    def unexpected_request(*args, **kwargs):
        pytest.fail("Invalid URL reached the network")

    monkeypatch.setattr(httpx, "post", unexpected_request)
    assert dispatch_slack_webhook(webhook_url=url, payload={}) == {
        "status": "failed",
        "error": "Invalid Slack webhook URL",
    }


def test_webhook_errors_do_not_expose_the_secret_url(monkeypatch):
    url = "https://hooks.slack.com/services/private-secret"

    def failed_request(*args, **kwargs):
        raise httpx.ConnectError(f"Connection failed: {url}")

    monkeypatch.setattr(httpx, "post", failed_request)
    result = dispatch_slack_webhook(webhook_url=url, payload={})
    assert result == {"status": "failed", "error": "Slack webhook delivery failed"}
    assert url not in str(result)


@pytest.mark.parametrize("status", [200, 302, 500])
def test_https_webhook_delivery_never_follows_redirects(monkeypatch, status):
    url = "https://hooks.slack.com/services/example"
    payload = {"text": "test alert"}

    def fake_request(target, **kwargs):
        assert target == url
        assert kwargs == {"json": payload, "timeout": 2.0, "follow_redirects": False}
        return httpx.Response(status, request=httpx.Request("POST", target))

    monkeypatch.setattr(httpx, "post", fake_request)
    result = dispatch_slack_webhook(webhook_url=url, payload=payload)
    assert result["status"] == ("sent" if status == 200 else "failed")
