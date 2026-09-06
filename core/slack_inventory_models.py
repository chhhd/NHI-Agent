"""Slack NHI 인벤토리 입력 모델.

`core/inventory_models.py` (GitHub) 와는 별개의 스키마다. Slack 은 GitHub App
처럼 `resource:level` 권한 표기가 없고 평면 OAuth Scope(`channels:history` 등)만
쓰므로 `raw_permissions` 개념이 필요 없다. 또한 GitHub 처럼 "입력유형→공통유형"
매핑 테이블(`GitHubNHIType`/`GITHUB_NHI_TYPE_MAP`)도 필요 없다 —
`connectors/slack_connector.py::SlackConnector.token_kind()` 가 토큰 접두사
(`xoxb-`/`xoxp-`/`xapp-`)로 유형을 이미 명확히 구분해주므로
`core.nhi_models.NHIType` 를 바로 쓴다.

환경 구분 같은 공통 열거형은 `core/nhi_models.py` 것을 그대로 쓴다.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from core.nhi_models import Environment, NHIType


class ChannelInfo(BaseModel):
    """NHI 가 접근할 수 있는 Slack 채널 1건."""

    name: str = Field(..., examples=["general"])
    is_private: bool = False
    #: 민감한 대화가 오가는 채널인가. 선언 값이며 코드로 추정하지 않는다.
    is_sensitive: bool = False


class SlackNHIInput(BaseModel):
    """분석 대상 Slack NHI 1건 (Bot / User / App-level 토큰).

    리스트 기본값은 `default_factory` 로 만든다. 가변 객체를 기본값으로
    공유하면 인스턴스 간에 데이터가 섞인다.
    """

    nhi_id: str = Field(..., examples=["slack-T0000-B0000"])
    nhi_name: str = Field(..., examples=["support-bot"])
    nhi_type: NHIType
    #: 관리 책임자 또는 팀. 없을 수 있으므로 None 을 허용한다.
    owner: Optional[str] = None
    environment: Environment = Environment.UNKNOWN
    #: Credential 이 살아 있는가. `auth.test` 실호출 결과를 그대로 담는다
    #: (GitHub 인벤토리 경로와 달리 선언값이 아니라 실제 검증 결과다).
    active: bool = True
    #: `auth.test` 응답 헤더(`x-oauth-scopes`)에서 얻은 평면 OAuth Scope.
    raw_scopes: List[str] = Field(default_factory=list)
    channels: List[ChannelInfo] = Field(default_factory=list)
    #: 채널 목록 조회 자체가 실패한 사유. `channels` 는 실패해도 빈 리스트로
    #: 남으므로("조회 성공 + 채널 0개"와 모양이 같음), 이 필드가 없으면 둘을
    #: 구분할 수 없다. None = 조회를 시도하지 않았거나 성공함, 문자열 = 실패 사유.
    channels_error: Optional[str] = None
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None

    @property
    def nhi_type_common(self) -> NHIType:
        """GitHub 입력(`GitHubNHIInput.nhi_type_common`)과 인터페이스를 맞추기
        위한 항등 프로퍼티 — Slack 은 별도 매핑이 필요 없다."""
        return self.nhi_type

    @property
    def scopes(self) -> List[str]:
        """Scope Translation 에 넘길 원본 Scope 목록."""
        return [scope.strip() for scope in self.raw_scopes if scope and scope.strip()]
