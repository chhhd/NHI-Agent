"""공통 테스트 픽스처.

GitHub NHI 인벤토리 입력은 필드가 많아 테스트마다 다시 쓰면 길어지므로
고위험/저위험 두 시나리오를 픽스처로 둔다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

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
