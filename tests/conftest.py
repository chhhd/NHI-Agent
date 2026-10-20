"""공통 테스트 픽스처.

GitHub NHI 인벤토리 입력은 필드가 많아 테스트마다 다시 쓰면 길어지므로
고위험/저위험 두 시나리오를 픽스처로 둔다.
"""

from __future__ import annotations

import os
import socket
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# 테스트 중 `api.app` 이 어떤 경로로 import 되더라도 프로젝트의 실제 DB(nhi_scanner.db)를 열지 않도록
# 기본 DB 경로를 임시 폴더로 고정한다. API 테스트는 각자 NHI_DB_PATH 를 다시 지정해 격리한다.
os.environ["NHI_DB_PATH"] = os.path.join(
    tempfile.mkdtemp(prefix="nhi-pytest-"), "default.db"
)

# 테스트는 개발자의 `.env` 에 있는 실제 자격 증명을 쓰면 안 된다. core.config 의 load_dotenv() 는 이미
# 설정된 환경 변수를 덮어쓰지 않으므로, 빈 값으로 먼저 고정하면 `.env` 의 토큰이 읽히지 않는다.
# (기본 커넥터를 쓰는 테스트가 api.github.com 등으로 실제 요청을 보내는 것을 막는다.)
# 필요한 테스트는 monkeypatch.setenv 로 가짜 값을 직접 지정한다.
for _name in (
    "GITHUB_TOKEN",
    "GITHUB_INVENTORY_TOKEN",
    "GITHUB_AUDIT_TOKEN",
    "GITHUB_WEBHOOK_SECRET",
    "SLACK_BOT_TOKEN",
    "GITLAB_TOKEN",
    "NOTION_TOKEN",
    "HUGGINGFACE_TOKEN",
    "MICROSOFT_CLIENT_SECRET",
    "MICROSOFT_GRAPH_ACCESS_TOKEN",
    "GOOGLE_WORKSPACE_ACCESS_TOKEN",
    "NHI_ADMIN_API_KEY",
    "NHI_MASTER_KEY",
    "NHI_RUNTIME_TOKEN_SIGNING_KEY",
    "NHI_REQUIRE_VERIFIED_ADMIN",
    "NHI_PRIVACY_PSEUDONYMIZATION_KEY",
):
    os.environ[_name] = ""

from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.nhi_models import Environment


@pytest.fixture
def high_risk_nhi() -> GitHubNHIInput:
    """위험 요소를 모두 가진 GitHub App.

    운영 환경 / Owner 없음 / 민감 저장소 접근 / 광범위 접근 /
    관리자 권한 / 쓰기 권한 / 만료일 없음 / 장기 미사용.
    """
    return GitHubNHIInput(
        nhi_id="github-app-high-risk",
        nhi_name="production-deployment-app",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner=None,
        environment=Environment.PRODUCTION,
        active=True,
        repositories=[
            RepositoryInfo(name="acme/backend", visibility="private", is_sensitive=True),
            RepositoryInfo(name="acme/frontend", visibility="private"),
            RepositoryInfo(name="acme/infrastructure", visibility="private", is_sensitive=True),
            RepositoryInfo(name="acme/devops", visibility="private", is_sensitive=True),
            RepositoryInfo(name="acme/internal-tool", visibility="private"),
        ],
        raw_permissions={
            "contents": "write",
            "actions": "write",
            "administration": "write",
            "metadata": "read",
        },
        # 장기 미사용 판정을 위해 충분히 과거로 둔다.
        last_used_at=datetime.now(timezone.utc) - timedelta(days=400),
        expires_at=None,
    )


@pytest.fixture
def low_risk_nhi() -> GitHubNHIInput:
    """위험 요소가 거의 없는 GitHub App.

    개발 환경 / Owner 있음 / 공개 저장소 1개 / 읽기 권한 / 미래 만료일 / 최근 사용.
    """
    return GitHubNHIInput(
        nhi_id="github-app-low-risk",
        nhi_name="read-only-analysis-app",
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner="security-team",
        environment=Environment.DEVELOPMENT,
        active=True,
        repositories=[
            RepositoryInfo(name="acme/public-documentation", visibility="public"),
        ],
        raw_permissions={"contents": "read", "metadata": "read"},
        last_used_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=60),
        last_rotated_at=datetime.now(timezone.utc) - timedelta(days=10),
    )


# ---------------------------------------------------------------------------
# 외부 네트워크 차단막
# ---------------------------------------------------------------------------
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver", "0.0.0.0", ""}
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect


class ExternalNetworkBlocked(RuntimeError):
    """테스트가 로컬 밖으로 나가려 했다. 커넥터를 stub/MockTransport 로 대체해야 한다."""


def _is_local(host) -> bool:
    return str(host).lower() in _LOCAL_HOSTS or str(host).startswith("127.")


@pytest.fixture(autouse=True)
def _block_external_network(monkeypatch):
    def guarded_getaddrinfo(host, *args, **kwargs):
        if not _is_local(host):
            raise ExternalNetworkBlocked(f"테스트에서 외부 호스트 조회 시도: {host}")
        return _real_getaddrinfo(host, *args, **kwargs)

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and not _is_local(host):
            raise ExternalNetworkBlocked(f"테스트에서 외부 연결 시도: {host}")
        return _real_connect(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield
