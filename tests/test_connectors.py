"""Connector / Webhook 테스트 (httpx MockTransport 사용 — 실제 네트워크 호출 없음)."""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest

from connectors.base_connector import AuthenticationError, PermissionDeniedError
from connectors.github_connector import GitHubConnector
from connectors.github_webhook import (
    GitHubWebhookHandler,
    WebhookVerificationError,
    parse_event,
    verify_signature,
)
from connectors.slack_connector import SlackConnector
from core.models import ResolutionStatus, ScanTarget
from rescan.revalidator import Revalidator
from scanner.scan_service import SecretScanService

SECRET = "test-webhook-secret"
SLACK_BOT_TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# GitHub Connector
# ---------------------------------------------------------------------------
def test_github_validate_credential_parses_scopes():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(
                200,
                json={"login": "octocat", "id": 1, "type": "User", "name": "The Octocat"},
                headers={"X-OAuth-Scopes": "repo, read:org, admin:repo_hook"},
            )
        return httpx.Response(200, json=[])

    with GitHubConnector("ghp_dummy", client=_client(handler)) as gh:
        status = gh.validate_credential()

    assert status.active is True
    assert status.revoked is False
    assert status.raw_scopes == ["repo", "read:org", "admin:repo_hook"]
    assert status.account["login"] == "octocat"


def test_github_401_marks_token_revoked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    with GitHubConnector("ghp_dead", client=_client(handler)) as gh:
        status = gh.validate_credential()

    assert status.active is False
    assert status.revoked is True
    assert "Bad credentials" in status.error


def test_github_403_raises_permission_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible"})

    with GitHubConnector("ghp_x", client=_client(handler)) as gh:
        with pytest.raises(PermissionDeniedError):
            gh.get_repository("org/private-repo")


def test_github_commit_files_filters_deleted():
    payload = {
        "files": [
            {"filename": "config/slack.env", "status": "modified", "additions": 1, "deletions": 0},
            {"filename": "old.env", "status": "removed", "additions": 0, "deletions": 3},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with GitHubConnector("ghp_x", client=_client(handler)) as gh:
        files = gh.get_commit_files("org/repo", "abc123")

    assert [f["path"] for f in files] == ["config/slack.env"]


def test_github_rate_limit_raises_when_wait_too_long():
    import time

    reset = int(time.time()) + 3600

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"message": "API rate limit exceeded"},
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)},
        )

    from connectors.base_connector import RateLimitError

    with GitHubConnector("ghp_x", client=_client(handler)) as gh:
        with pytest.raises(RateLimitError):
            gh.get_repository("org/repo")


def test_github_file_content_decodes_base64():
    import base64

    content = "SLACK_BOT_TOKEN=xoxb-1-2-abc\n"
    encoded = base64.b64encode(content.encode()).decode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"encoding": "base64", "content": encoded})

    with GitHubConnector("ghp_x", client=_client(handler)) as gh:
        assert gh.get_file_content("org/repo", "config/slack.env") == content


# ---------------------------------------------------------------------------
# Slack Connector
# ---------------------------------------------------------------------------
def test_slack_validate_credential_success():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("auth.test"):
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "team": "Hanium",
                    "team_id": "T123",
                    "user": "nhi-bot",
                    "user_id": "U123",
                    "bot_id": "B123",
                    "app_id": "A123",
                },
                headers={"x-oauth-scopes": "chat:write,channels:history"},
            )
        if request.url.path.endswith("conversations.list"):
            return httpx.Response(
                200,
                json={"ok": True, "channels": [{"id": "C1", "name": "general", "is_private": False}]},
            )
        return httpx.Response(200, json={"ok": True})

    with SlackConnector(SLACK_BOT_TOKEN, client=_client(handler)) as slack:
        status = slack.validate_credential()

    assert status.active is True
    assert status.revoked is False
    assert status.raw_scopes == ["chat:write", "channels:history"]
    assert status.account["team"] == "Hanium"
    assert status.account["token_kind"] == "bot"
    assert status.accessible_resources[0]["name"] == "general"


def test_slack_revoked_token_detected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "token_revoked"})

    with SlackConnector(SLACK_BOT_TOKEN, client=_client(handler)) as slack:
        status = slack.validate_credential()
        assert slack.is_revoked() is True

    assert status.active is False
    assert status.revoked is True


def test_slack_missing_scope_raises_permission_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "missing_scope", "needed": "channels:read"})

    with SlackConnector(SLACK_BOT_TOKEN, client=_client(handler)) as slack:
        with pytest.raises(PermissionDeniedError):
            slack.list_channels()


def test_slack_invalid_auth_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})

    with SlackConnector("xoxb-bad", client=_client(handler)) as slack:
        with pytest.raises(AuthenticationError):
            slack.get_workspace_info()


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_signature_accepts_valid_and_rejects_tampered():
    body = json.dumps({"ref": "refs/heads/main"}).encode()
    verify_signature(body, _sign(body), SECRET)

    with pytest.raises(WebhookVerificationError):
        verify_signature(body + b"x", _sign(body), SECRET)

    with pytest.raises(WebhookVerificationError):
        verify_signature(body, None, SECRET)


def test_parse_push_event():
    payload = {
        "ref": "refs/heads/main",
        "before": "a" * 40,
        "after": "b" * 40,
        "commits": [{"id": "c" * 40}],
        "repository": {"full_name": "org/repo"},
        "sender": {"login": "dev"},
    }
    event = parse_event("push", payload, delivery_id="d1")

    assert event.repository == "org/repo"
    assert event.commit_shas == ["c" * 40]
    assert event.is_deleted_branch is False


def test_parse_branch_delete_event_marked():
    payload = {
        "ref": "refs/heads/feature",
        "before": "a" * 40,
        "after": "0" * 40,
        "deleted": True,
        "repository": {"full_name": "org/repo"},
    }
    assert parse_event("push", payload).is_deleted_branch is True


def test_parse_pull_request_event():
    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {"number": 42, "head": {"ref": "feat", "sha": "s" * 40}},
        "repository": {"full_name": "org/repo"},
    }
    event = parse_event("pull_request", payload)

    assert event.pull_request == 42
    assert event.action == "opened"


class _FakeConnector:
    """네트워크 없이 동작하는 GitHubConnector 대체."""

    def __init__(self, files):
        self.files = files

    def compare_commits(self, repo, base, head):
        return [{"path": p} for p in self.files]

    def get_commit_files(self, repo, sha):
        return [{"path": p} for p in self.files]

    def build_scan_targets(self, repo, paths, ref=None):
        return [ScanTarget(path=p, content=self.files[p], ref=ref) for p in paths if p in self.files]

    def scan_targets_for_pull_request(self, repo, pr_number):
        return [ScanTarget(path=p, content=c) for p, c in self.files.items()]


def test_webhook_handler_runs_scan_on_push():
    files = {"config/slack.env": f"SLACK_BOT_TOKEN={SLACK_BOT_TOKEN}\n"}
    results = []
    handler = GitHubWebhookHandler(
        connector=_FakeConnector(files),
        scan_service=SecretScanService(),
        on_result=results.append,
    )

    payload = {
        "ref": "refs/heads/main",
        "before": "a" * 40,
        "after": "b" * 40,
        "commits": [{"id": "b" * 40}],
        "repository": {"full_name": "org/repo"},
    }
    result = handler.handle("push", payload, delivery_id="d-1")

    assert result is not None
    assert result.repository == "org/repo"
    assert any(f.secret_type == "SLACK_BOT_TOKEN" for f in result.findings)
    assert results and results[0] is result


def test_webhook_handler_ignores_duplicate_delivery():
    handler = GitHubWebhookHandler(
        connector=_FakeConnector({"a.env": "X=1"}), scan_service=SecretScanService()
    )
    payload = {"ref": "refs/heads/main", "after": "b" * 40, "repository": {"full_name": "org/repo"}}

    assert handler.handle("push", payload, delivery_id="dup") is not None
    assert handler.handle("push", payload, delivery_id="dup") is None


def test_webhook_handler_skips_unhandled_event():
    handler = GitHubWebhookHandler(connector=_FakeConnector({}), scan_service=SecretScanService())
    assert handler.handle("issues", {"repository": {"full_name": "org/repo"}}) is None


# ---------------------------------------------------------------------------
# 재스캔 판정
# ---------------------------------------------------------------------------
def test_rescan_diff_classifies_resolved_unresolved_recurred_new():
    service = SecretScanService()
    previous = service.scan_targets(
        [
            ScanTarget(path="a.env", content=f"TOKEN={SLACK_BOT_TOKEN}"),
            ScanTarget(path="b.env", content="GITHUB_TOKEN=ghp_" + "Z" * 5 + "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"),
        ],
        repository="org/repo",
    ).findings

    current = service.scan_targets(
        [ScanTarget(path="a.env", content=f"TOKEN={SLACK_BOT_TOKEN}")],
        repository="org/repo",
    ).findings

    revalidator = Revalidator.__new__(Revalidator)  # 네트워크 의존성 없이 diff 만 사용
    report = revalidator.diff(
        "org/repo",
        previous_findings=previous,
        current=current,
        resolved_fingerprints=set(),
    )

    assert len(report.unresolved) == 1
    assert len(report.resolved) == 1
    assert report.unresolved[0].status == ResolutionStatus.UNRESOLVED
    assert report.resolved[0].status == ResolutionStatus.RESOLVED


def test_rescan_detects_recurrence():
    service = SecretScanService()
    findings = service.scan_targets(
        [ScanTarget(path="a.env", content=f"TOKEN={SLACK_BOT_TOKEN}")], repository="org/repo"
    ).findings
    fingerprint = findings[0].fingerprint

    revalidator = Revalidator.__new__(Revalidator)
    report = revalidator.diff(
        "org/repo",
        previous_findings=[],
        current=findings,
        resolved_fingerprints={fingerprint},
    )

    assert len(report.recurred) == 1
    assert report.recurred[0].status == ResolutionStatus.RECURRED
