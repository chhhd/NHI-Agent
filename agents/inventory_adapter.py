"""GitHub NHI 인벤토리 입력 → 분석 파이프라인 입력 변환.

분석 엔진(Discovery ~ Recommendation, Policy, Blast Radius)은 하나뿐이고,
입력 경로만 두 개다.

    저장소 스캔 → SecretFinding ─┐
                                 ├→ EvaluationContext → 위험 점수 / 정책 / 권고
    GitHub NHI 인벤토리 입력 ────┘   (이 모듈이 오른쪽 경로를 만든다)

인벤토리 경로는 NHI 의 신원(id·이름·유형·Owner)을 **이미 알고 있으므로**
Discovery Agent 의 추정을 거치지 않고 `NHIProfile` 을 직접 만든다.
문맥(환경·민감도)도 코드에서 유추하지 않고 선언된 값을 그대로 쓴다.

`SecretFinding` 은 원문 Secret 이 없는 "자격 증명 레코드" 로 대체 생성한다.
`EvaluationContext` 가 요구하는 필드를 채우기 위한 것이며, 코드 노출 사실이
없다는 점은 `AnalysisSource.INVENTORY` 로 구분된다(`policy/rules.py` 참고).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.aws_inventory_models import AWSNHIInput
from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo
from core.models import CredentialStatus, DetectorType, SecretFinding, Severity
from core.nhi_models import (
    AnalysisSignals,
    ContextInsight,
    DataSensitivity,
    Environment,
    NHIProfile,
    NHIType,
)
from core.slack_inventory_models import ChannelInfo, SlackNHIInput

#: 인벤토리 입력의 신뢰도 — 선언된 메타데이터이므로 추정보다 높게 본다.
DECLARED_CONFIDENCE = 0.9

#: Bot 계정으로 취급하는 NHI 유형
_BOT_TYPES = {NHIType.GITHUB_APP}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def build_github_nhi_input(
    user: Dict[str, Any],
    repositories: List[Dict[str, Any]],
    *,
    nhi_type: GitHubNHIType = GitHubNHIType.PERSONAL_ACCESS_TOKEN,
) -> GitHubNHIInput:
    """Assemble connector identity and repository results into inventory input.

    Only stable public identity data is used for the NHI identifier. The token
    is intentionally not accepted by this adapter and is never copied into the
    resulting model.
    """
    if not isinstance(user, dict) or user.get("id") is None:
        raise ValueError("GitHub authenticated user must include id")

    login = user.get("login")
    if not isinstance(login, str) or not login.strip():
        raise ValueError("GitHub authenticated user must include login")

    repository_infos: List[RepositoryInfo] = []
    for repository in repositories or []:
        if not isinstance(repository, dict):
            continue
        full_name = repository.get("full_name") or repository.get("name")
        if not isinstance(full_name, str) or not full_name.strip():
            continue
        is_private = repository.get("private")
        visibility = "private" if is_private is True else "public"
        repository_infos.append(
            RepositoryInfo(name=full_name, visibility=visibility)
        )

    return GitHubNHIInput(
        nhi_id=f"github-user-{user['id']}",
        nhi_name=login.strip(),
        nhi_type=nhi_type,
        owner=None,
        active=True,
        repositories=repository_infos,
    )


def build_github_app_nhi_input(
    installation: Dict[str, Any],
    repositories: List[Dict[str, Any]],
    *,
    credential_verified: Optional[bool] = None,
) -> GitHubNHIInput:
    """Assemble GitHub App installation + repository results into inventory input.

    `installation` is the minimal dict shape returned by
    `GitHubAppConnector.list_installations()` (`installation_id`,
    `account_login`, `account_type`, `repository_selection`, `permissions`,
    `suspended`). `repositories` is the minimal dict shape returned by
    `GitHubAppConnector.list_installation_repositories()` (`full_name`,
    `private`, `owner_login`).

    Unlike `build_github_nhi_input` (PAT path), this fills `raw_permissions`
    instead of `raw_scopes` — GitHub App permissions are already declared as
    resource:level pairs (e.g. ``{"contents": "write"}``), which
    `GitHubNHIInput.scopes` expands into the same ``"contents:write"`` form
    the `SCOPE_TABLE["github"]` mapping already understands. The values are
    passed through as GitHub returned them — never guessed or rewritten here.

    `account_login` names the GitHub org/user the installation belongs to,
    not a responsible person or team, so it is never used as `owner`. Owner
    is intentionally left unset, matching the PAT path's behavior when no
    owner is declared.

    `credential_verified` carries the outcome of an actual live check (the
    caller minting an Installation Token and successfully calling
    `GET /installation/repositories`) — pass `True`/`False` when that was
    attempted, or leave `None` when it wasn't. This is independent from
    `active` (which only reflects whether GitHub reports the installation as
    suspended); `build_credential_record()` combines both.
    """
    if not isinstance(installation, dict) or installation.get("installation_id") is None:
        raise ValueError("GitHub App installation must include installation_id")

    installation_id = installation["installation_id"]
    account_login = installation.get("account_login")
    permissions = installation.get("permissions")

    repository_infos: List[RepositoryInfo] = []
    for repository in repositories or []:
        if not isinstance(repository, dict):
            continue
        full_name = repository.get("full_name")
        if not isinstance(full_name, str) or not full_name.strip():
            continue
        visibility = "private" if repository.get("private") is True else "public"
        repository_infos.append(
            RepositoryInfo(name=full_name, visibility=visibility)
        )

    if isinstance(account_login, str) and account_login.strip():
        nhi_name = account_login.strip()
    else:
        nhi_name = f"installation-{installation_id}"

    repository_selection = installation.get("repository_selection")

    return GitHubNHIInput(
        nhi_id=f"github-app-installation-{installation_id}",
        nhi_name=nhi_name,
        nhi_type=GitHubNHIType.GITHUB_APP,
        owner=None,
        # Installation 이 정지되면 이 Credential 은 실질적으로 쓸 수 없다.
        active=not bool(installation.get("suspended", False)),
        credential_verified=credential_verified,
        installation_id=str(installation_id),
        repositories=repository_infos,
        repository_selection=(
            repository_selection.strip()
            if isinstance(repository_selection, str) and repository_selection.strip()
            else None
        ),
        raw_permissions=dict(permissions) if isinstance(permissions, dict) else {},
    )


def repository_records(nhi: GitHubNHIInput) -> List[Dict[str, Any]]:
    """접근 가능 저장소를 신호·Blast Radius 공통 형식으로 만든다."""
    records: List[Dict[str, Any]] = []
    for repo in nhi.repositories:
        full_name = repo.name
        owner_login = full_name.split("/", 1)[0] if "/" in full_name else None
        records.append(
            {
                "full_name": full_name,
                "name": full_name,
                "owner_login": owner_login,
                "visibility": repo.visibility,
                "is_sensitive": repo.is_sensitive,
            }
        )
    return records


def build_signals(
    nhi: GitHubNHIInput, overrides: Optional[Dict[str, Any]] = None
) -> AnalysisSignals:
    """NHI 인벤토리 값 → `AnalysisSignals`.

    `overrides` 는 코드·인벤토리 어디에도 없는 외부 사실(감사 로그의 관측 행위,
    Agent 종료 여부, 예외 승인 등)을 주입하는 통로다. 명시된 값이 우선한다.
    """
    repositories = repository_records(nhi)
    base: Dict[str, Any] = {
        "owner": nhi.owner,
        "created_at": _iso(nhi.created_at),
        "last_used_at": _iso(nhi.last_used_at),
        "expires_at": _iso(nhi.expires_at),
        "last_rotated_at": _iso(nhi.last_rotated_at),
        # 인벤토리 경로의 "노출 면적" 은 접근 가능 저장소 범위다.
        #
        # 접근 자원 목록은 자격 증명 레코드(`credential_detail.accessible_resources`)에만
        # 담는다. 여기에 또 넣으면 Blast Radius 가 같은 저장소를 두 번 센다.
        "extra": {
            "environment": nhi.environment.value,
            "repositories": repositories,
            "github_account": dict(nhi.account),
            "repository_selection": nhi.repository_selection,
            "repository_inventory_complete": nhi.repository_inventory_complete,
            "inventory_is_complete": nhi.inventory_is_complete,
            "collection_source": nhi.collection_source,
            "collection_evidence": list(nhi.collection_evidence),
            "subscribed_events": list(nhi.subscribed_events),
            "suspended_at": _iso(nhi.suspended_at),
        },
    }

    merged = dict(base)
    extra = dict(base["extra"])
    for key, value in (overrides or {}).items():
        if key == "extra" and isinstance(value, dict):
            extra.update(value)
        elif value is not None:
            merged[key] = value
    merged["extra"] = extra
    return AnalysisSignals.from_dict(merged)


def _resolve_credential_active(nhi: GitHubNHIInput) -> Optional[bool]:
    """`active`(선언된 활성 상태)와 `credential_verified`(실제 라이브 검증 결과)를 합친다.

    * `active` 가 False (예: GitHub App Installation 이 정지됨) → 항상 False.
      관리자가 명시적으로 정지시켰다는 사실이 검증 시도 결과보다 우선한다.
    * `active` 가 True 인데 `credential_verified` 가 False (검증을 시도했지만
      실패) → None(상태 불명)으로 본다. 검증 실패는 "확실히 비활성"이 아니라
      "확인 못 함"이므로, False 로 단정해 위험을 과소평가하지 않는다.
    * 그 외(검증 성공, 또는 검증 자체를 하지 않는 기존 경로 — PAT 등) → True.
      `credential_verified` 를 설정하지 않는 호출부(PAT 의 `build_github_nhi_input`)는
      이전과 동일하게 `active` 값을 그대로 True 로 반영한다.
    """
    if not nhi.active:
        return False
    if nhi.credential_verified is False:
        return None
    return True


def build_credential_record(nhi: GitHubNHIInput) -> SecretFinding:
    """분석 대상 자격 증명 레코드 (원문 Secret 없음).

    `masked_value` 가 비어 있는 것은 의도된 상태다. 인벤토리 입력에는
    Secret 값 자체가 존재하지 않으며, 이 계층은 값이 아니라 메타데이터로 판단한다.
    """
    return SecretFinding(
        secret_type=nhi.nhi_type.value,
        provider="github",
        masked_value="",
        fingerprint=f"nhi:{nhi.nhi_id}",
        file_path="",
        line_number=0,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        credential_active=_resolve_credential_active(nhi),
        # 인벤토리에는 폐기 여부가 따로 없다. active=False 는 "비활성" 으로만 해석하고
        # 폐기로 단정하지 않는다 (폐기 후 사용 판정을 잘못 유발하지 않기 위함).
        credential_revoked=None,
        raw_scopes=nhi.scopes,
        credential_detail={
            "account": {
                **dict(nhi.account),
                "id": nhi.nhi_id,
                "name": nhi.nhi_name,
                "type": "bot" if nhi.nhi_type_common in _BOT_TYPES else "user",
            },
            "accessible_resources": repository_records(nhi),
        },
    )


def build_profile(nhi: GitHubNHIInput, signals: AnalysisSignals) -> NHIProfile:
    """선언된 인벤토리 값으로 NHI 신원을 그대로 구성한다."""
    nhi_type = nhi.nhi_type_common
    evidence = [
        f"GitHub NHI 인벤토리 입력 — 유형 {nhi.nhi_type.value} → {nhi_type.value}",
        f"접근 가능 저장소 {len(nhi.repositories)}개",
    ]
    evidence.extend(nhi.collection_evidence)
    if not nhi.repository_inventory_complete:
        evidence.append(
            f"저장소 이름 인벤토리 불완전 (selection={nhi.repository_selection or 'unknown'})"
        )
    if not nhi.inventory_is_complete:
        evidence.append("조직 installation 인벤토리가 부분 수집됨")

    owner = (signals.owner or "").strip() or None
    if owner:
        evidence.append(f"인벤토리에 지정된 Owner: {owner}")
    else:
        evidence.append("Owner 미지정 — 인벤토리에 책임자 정보가 없다")

    if not nhi.scopes:
        evidence.append("원본 권한 정보가 없어 유형 기준으로 보수적으로 가정한다")
    elif nhi.raw_scopes:
        evidence.append(f"Token Scope {len(nhi.raw_scopes)}건: {', '.join(nhi.raw_scopes[:5])}")

    # 외부 account payload(GitHub API 가 돌려준 설치 대상 계정)를 베이스로 하되
    # canonical NHI id/name 은 그것에 덮어써지지 않게 마지막에 강제한다.
    account: Dict[str, Any] = {**dict(nhi.account), "id": nhi.nhi_id, "name": nhi.nhi_name}
    github_user = signals.extra.get("github_user") if signals.extra else None
    github_login = signals.extra.get("github_login") if signals.extra else None
    if isinstance(github_user, dict):
        github_login = github_login or github_user.get("login")
    if isinstance(github_login, str) and github_login.strip():
        account["login"] = github_login.strip()

    return NHIProfile(
        nhi_id=f"github:{nhi.nhi_id}",
        nhi_name=nhi.nhi_name,
        nhi_type=nhi_type,
        provider="github",
        secret_type=nhi.nhi_type.value,
        secret_name=f"GitHub {nhi.nhi_type.value.replace('_', ' ').title()}",
        is_bot=nhi_type in _BOT_TYPES,
        is_service_account=True,
        linked_ai_agent=signals.agent_name,
        owner=owner,
        owner_candidates=[owner] if owner else [],
        owner_source="external_signal" if owner else None,
        account=account,
        identified=nhi_type is not NHIType.UNKNOWN_NHI,
        confidence=DECLARED_CONFIDENCE,
        evidence=evidence,
        credential_fingerprint=f"nhi:{nhi.nhi_id}",
    )


def build_context(nhi: GitHubNHIInput, signals: AnalysisSignals) -> ContextInsight:
    """선언된 환경·저장소 정보로 문맥을 구성한다 (코드 유추를 하지 않는다)."""
    sensitive = [repo for repo in nhi.repositories if repo.is_sensitive]
    private = [repo for repo in nhi.repositories if repo.is_private]

    if sensitive:
        sensitivity = DataSensitivity.CONFIDENTIAL
    elif private:
        sensitivity = DataSensitivity.INTERNAL
    elif nhi.repositories:
        sensitivity = DataSensitivity.PUBLIC
    else:
        sensitivity = DataSensitivity.UNKNOWN

    notes = ["GitHub NHI 인벤토리 입력 — 선언된 메타데이터 기준 분석"]
    if sensitive:
        notes.append(f"민감 저장소 접근: {', '.join(repo.name for repo in sensitive[:3])}")
    if nhi.environment is Environment.UNKNOWN:
        notes.append("사용 환경 미지정 — 보수적으로 평가")
    if not nhi.repository_inventory_complete:
        notes.append(
            "개별 저장소 이름 미확인 — 접근 범위를 0개로 단정하지 않음"
        )
    if nhi.repository_selection == "all":
        notes.append("GitHub App이 조직의 모든 저장소를 선택 범위로 가짐")

    path_signals = [f"접근 저장소 {len(nhi.repositories)}개"] if nhi.repositories else []

    return ContextInsight(
        environment=nhi.environment,
        is_test_or_example=False,
        in_use=nhi.active,
        data_sensitivity=sensitivity,
        variable_name=None,
        # 코드에 하드코딩된 값이 아니므로 항상 False 다.
        hardcoded_in_source=False,
        project_hint=signals.project,
        path_signals=path_signals,
        code_signals=[],
        confidence=DECLARED_CONFIDENCE,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Slack 인벤토리 입력 → 분석 파이프라인 입력 변환
#
# GitHub 경로(위)와 완전히 분리된 어댑터다. `SlackNHIInput.channels` 는
# `GitHubNHIInput.repositories` 와 이름·의미가 달라 위 4개 함수를 재사용할 수
# 없으므로, 같은 역할을 하는 Slack 전용 버전을 별도로 둔다. GitHub 쪽 함수는
# 이 섹션에서 전혀 참조하지도, 수정하지도 않는다.
# ---------------------------------------------------------------------------

#: Slack 토큰 접두사 기반 유형(`SlackConnector.token_kind()`) → 공통 NHI 유형.
#: GitHub 처럼 별도 입력유형 Enum + 매핑 테이블이 필요 없다 — 토큰 접두사가
#: 이미 유형을 명확히 구분해준다.
_SLACK_TOKEN_KIND_TO_NHI_TYPE: Dict[str, NHIType] = {
    "bot": NHIType.SLACK_BOT,
    "user": NHIType.SLACK_USER_TOKEN,
    "app_level": NHIType.SLACK_APP,
}

#: Bot 계정으로 취급하는 Slack NHI 유형 (GitHub 의 `_BOT_TYPES` 와 별개 상수).
_SLACK_BOT_TYPES = {NHIType.SLACK_BOT, NHIType.SLACK_APP}


def build_slack_nhi_input(
    status: CredentialStatus,
    channels: Optional[List[Dict[str, Any]]] = None,
) -> SlackNHIInput:
    """Assemble a live Slack `auth.test` result into inventory input.

    `status` is the result of `SlackConnector.validate_credential()` — a
    single live call to `/auth.test` that already returns identity, the real
    OAuth scopes (from the `x-oauth-scopes` response header), and whether the
    token is currently active. Unlike the GitHub PAT/App paths, `active` here
    is not a declared/assumed value — it is the outcome of an actual
    verification call, so no `credential_verified` reconciliation is needed.

    `channels` is typically `status.accessible_resources` — the channel list
    `SlackConnector._safe_channels()` already collected during validation.
    `status.accessible_resources_error` is carried through as
    `SlackNHIInput.channels_error` so downstream (`build_slack_signals()` →
    `EvaluationContext` → risk scoring) can tell "confirmed zero channels"
    apart from "channel lookup failed" — both would otherwise look like the
    same empty list.
    """
    if not isinstance(status, CredentialStatus):
        raise ValueError("Slack credential status is required")

    account = status.account or {}
    identity_id = account.get("bot_id") or account.get("user_id")
    if not identity_id:
        raise ValueError("Slack auth.test result must include bot_id or user_id")

    team_id = account.get("team_id") or "unknown-team"
    nhi_type = _SLACK_TOKEN_KIND_TO_NHI_TYPE.get(
        account.get("token_kind"), NHIType.GENERIC_SERVICE_ACCOUNT
    )
    nhi_name = str(account.get("user") or identity_id)

    channel_infos: List[ChannelInfo] = []
    for channel in channels or []:
        if not isinstance(channel, dict):
            continue
        name = channel.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        channel_infos.append(
            ChannelInfo(name=name, is_private=bool(channel.get("is_private", False)))
        )

    return SlackNHIInput(
        nhi_id=f"slack-{team_id}-{identity_id}",
        nhi_name=nhi_name,
        nhi_type=nhi_type,
        owner=None,
        active=status.active is True,
        raw_scopes=list(status.raw_scopes or []),
        channels=channel_infos,
        channels_error=status.accessible_resources_error,
    )


def _slack_channel_records(nhi: SlackNHIInput) -> List[Dict[str, Any]]:
    """접근 가능 채널을 신호·Blast Radius 공통 형식으로 만든다 (`repository_records` 의 Slack 버전)."""
    return [
        {
            "name": channel.name,
            "is_private": channel.is_private,
            "is_sensitive": channel.is_sensitive,
        }
        for channel in nhi.channels
    ]


def build_slack_signals(
    nhi: SlackNHIInput, overrides: Optional[Dict[str, Any]] = None
) -> AnalysisSignals:
    """Slack NHI 인벤토리 값 → `AnalysisSignals` (`build_signals` 의 Slack 버전).

    `accessible_resources_error` 키는 `EvaluationContext`(`policy/rules.py`)가
    "채널 조회 성공 + 0개"와 "채널 조회 실패"를 구분하는 데 쓴다 — provider
    공통 키 이름이며, GitHub 쪽 `build_signals()` 는 이 키를 채우지 않는다.
    """
    base: Dict[str, Any] = {
        "owner": nhi.owner,
        "created_at": _iso(nhi.created_at),
        "last_used_at": _iso(nhi.last_used_at),
        "expires_at": _iso(nhi.expires_at),
        "last_rotated_at": _iso(nhi.last_rotated_at),
        "extra": {
            "environment": nhi.environment.value,
            "channels": _slack_channel_records(nhi),
            "accessible_resources_error": nhi.channels_error,
        },
    }

    merged = dict(base)
    extra = dict(base["extra"])
    for key, value in (overrides or {}).items():
        if key == "extra" and isinstance(value, dict):
            extra.update(value)
        elif value is not None:
            merged[key] = value
    merged["extra"] = extra
    return AnalysisSignals.from_dict(merged)


def build_slack_credential_record(nhi: SlackNHIInput) -> SecretFinding:
    """분석 대상 자격 증명 레코드 (`build_credential_record` 의 Slack 버전).

    `credential_active` 는 `auth.test` 실호출 결과(`nhi.active`)를 그대로
    반영한다 — GitHub 인벤토리 경로와 달리 이미 실제 검증된 값이다.
    `credential_revoked` 연결은 이번 단계에서 하지 않는다(항상 None).
    """
    return SecretFinding(
        secret_type=nhi.nhi_type.value,
        provider="slack",
        masked_value="",
        fingerprint=f"nhi:{nhi.nhi_id}",
        file_path="",
        line_number=0,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        credential_active=nhi.active,
        credential_revoked=None,
        raw_scopes=nhi.scopes,
        credential_detail={
            "account": {
                "id": nhi.nhi_id,
                "name": nhi.nhi_name,
                "type": "bot" if nhi.nhi_type in _SLACK_BOT_TYPES else "user",
            },
            "accessible_resources": _slack_channel_records(nhi),
        },
    )


def build_slack_profile(nhi: SlackNHIInput, signals: AnalysisSignals) -> NHIProfile:
    """선언된 인벤토리 값으로 NHI 신원을 그대로 구성한다 (`build_profile` 의 Slack 버전)."""
    evidence = [
        f"Slack auth.test 로 확인된 신원 — 유형 {nhi.nhi_type.value}",
        f"접근 가능 채널 {len(nhi.channels)}개",
    ]

    owner = (signals.owner or "").strip() or None
    if owner:
        evidence.append(f"인벤토리에 지정된 Owner: {owner}")
    else:
        evidence.append("Owner 미지정 — 인벤토리에 책임자 정보가 없다")

    if not nhi.scopes:
        evidence.append("원본 권한 정보가 없어 유형 기준으로 보수적으로 가정한다")
    else:
        evidence.append(f"OAuth Scope {len(nhi.scopes)}건: {', '.join(nhi.scopes[:5])}")

    account: Dict[str, Any] = {"id": nhi.nhi_id, "name": nhi.nhi_name}

    return NHIProfile(
        nhi_id=f"slack:{nhi.nhi_id}",
        nhi_name=nhi.nhi_name,
        nhi_type=nhi.nhi_type,
        provider="slack",
        secret_type=nhi.nhi_type.value,
        secret_name=f"Slack {nhi.nhi_type.value.replace('_', ' ').title()}",
        is_bot=nhi.nhi_type in _SLACK_BOT_TYPES,
        is_service_account=True,
        linked_ai_agent=signals.agent_name,
        owner=owner,
        owner_candidates=[owner] if owner else [],
        owner_source="external_signal" if owner else None,
        account=account,
        identified=nhi.nhi_type is not NHIType.UNKNOWN_NHI,
        confidence=DECLARED_CONFIDENCE,
        evidence=evidence,
        credential_fingerprint=f"nhi:{nhi.nhi_id}",
    )


def build_slack_context(nhi: SlackNHIInput, signals: AnalysisSignals) -> ContextInsight:
    """선언된 환경·채널 정보로 문맥을 구성한다 (`build_context` 의 Slack 버전)."""
    sensitive = [channel for channel in nhi.channels if channel.is_sensitive]
    private = [channel for channel in nhi.channels if channel.is_private]

    if sensitive:
        sensitivity = DataSensitivity.CONFIDENTIAL
    elif private:
        sensitivity = DataSensitivity.INTERNAL
    elif nhi.channels:
        sensitivity = DataSensitivity.PUBLIC
    else:
        sensitivity = DataSensitivity.UNKNOWN

    notes = ["Slack NHI 인벤토리 입력 — auth.test 로 확인된 값 기준 분석"]
    if sensitive:
        notes.append(f"민감 채널 접근: {', '.join(channel.name for channel in sensitive[:3])}")
    if nhi.environment is Environment.UNKNOWN:
        notes.append("사용 환경 미지정 — 보수적으로 평가")

    path_signals = [f"접근 채널 {len(nhi.channels)}개"] if nhi.channels else []

    return ContextInsight(
        environment=nhi.environment,
        is_test_or_example=False,
        in_use=nhi.active,
        data_sensitivity=sensitivity,
        variable_name=None,
        hardcoded_in_source=False,
        project_hint=signals.project,
        path_signals=path_signals,
        code_signals=[],
        confidence=DECLARED_CONFIDENCE,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# AWS 인벤토리 입력 → 분석 파이프라인 입력 변환
#
# GitHub/Slack 경로(위)와 완전히 분리된 어댑터다. 이 섹션에서 GitHub/Slack
# 쪽 함수·상수는 전혀 참조하지도, 수정하지도 않는다.
#
# `AWSNHIInput` 에는 아직 Policy 수집(`iam:ListAttachedUserPolicies` 등)이
# 반영되지 않아 `raw_scopes` 가 항상 비어 있고, "접근 가능 자원" 개념도 없다
# (GitHub 의 저장소·Slack 의 채널에 대응하는 목록이 없음). 그래서 아래 함수들은
# `repositories`/`channels` 에 해당하는 처리를 하지 않는다 — 다음 단계에서
# Policy 수집을 붙일 때 함께 추가한다.
# ---------------------------------------------------------------------------

#: Bot(자동화) 계정으로 취급하는 AWS NHI 유형 (GitHub/Slack 의 _BOT_TYPES 와 별개 상수).
#: `CLOUD_SERVICE_ACCOUNT` 는 이름 그대로 서비스 계정이므로 bot 으로 취급한다.
_AWS_BOT_TYPES = {NHIType.CLOUD_SERVICE_ACCOUNT}


def build_aws_signals(
    nhi: AWSNHIInput, overrides: Optional[Dict[str, Any]] = None
) -> AnalysisSignals:
    """AWS NHI 인벤토리 값 → `AnalysisSignals` (`build_signals` 의 AWS 버전).

    `created_at` 을 채우면 `EvaluationContext.days_since_rotation`
    (`policy/rules.py` — `last_rotated_at or created_at`)이 자동으로
    "마지막 Access Key 발급 이후 경과일" 로 계산된다 — IAM Access Key 는
    새로 발급하는 것 자체가 회전 행위라 별도 `last_rotated_at` 신호가
    필요 없다. `last_used_at` 을 채우면 `_usage_anomaly` 의 사용 이력
    채점도 실제 값을 받는다. GitHub PAT·Slack Bot Token 은 이 값들을
    API 에서 얻을 방법이 없어 늘 비어 있었지만, AWS 는 `ListAccessKeys`/
    `GetAccessKeyLastUsed` 로 실제 값을 준다.

    `aws_broad_access` 키는 `graph/blast_radius.py::BlastRadiusCalculator`
    가 읽는다 — GitHub 저장소·Slack 채널처럼 "접근 가능 자원 개수"를 세는
    대신, AWS 는 Policy Resource 에 전체/서비스 전체급 wildcard 가
    있는지(`nhi.broad_access`)만 위험 근거로 전달한다.
    """
    base: Dict[str, Any] = {
        "owner": nhi.owner,
        "created_at": _iso(nhi.created_at),
        "last_used_at": _iso(nhi.last_used_at),
        "extra": {
            "environment": nhi.environment.value,
            "aws_broad_access": nhi.broad_access,
        },
    }

    merged = dict(base)
    extra = dict(base["extra"])
    for key, value in (overrides or {}).items():
        if key == "extra" and isinstance(value, dict):
            extra.update(value)
        elif value is not None:
            merged[key] = value
    merged["extra"] = extra
    return AnalysisSignals.from_dict(merged)


def build_aws_credential_record(nhi: AWSNHIInput) -> SecretFinding:
    """분석 대상 자격 증명 레코드 (`build_credential_record` 의 AWS 버전).

    `credential_active` 는 `nhi.active` — IAM `ListAccessKeys` 의 실제
    `Status`(Active/Inactive) 를 그대로 반영한 값이다(Slack 의 `auth.test`
    결과와 같은 성격 — 선언값이 아니라 실제 조회 결과). `credential_revoked`
    연결은 이번 단계에서 하지 않는다(항상 `None`).
    """
    return SecretFinding(
        secret_type=nhi.nhi_type.value,
        provider="aws",
        masked_value="",
        fingerprint=f"nhi:{nhi.nhi_id}",
        file_path="",
        line_number=0,
        detector=DetectorType.REGEX,
        severity=Severity.MEDIUM,
        credential_active=nhi.active,
        credential_revoked=None,
        raw_scopes=list(nhi.raw_scopes),
        credential_detail={
            "account": {
                "id": nhi.nhi_id,
                "name": nhi.nhi_name,
                "type": "bot" if nhi.nhi_type in _AWS_BOT_TYPES else "user",
            },
            # Policy 수집 이전이라 접근 가능 자원 목록이 없다.
            "accessible_resources": [],
        },
    )


def build_aws_profile(nhi: AWSNHIInput, signals: AnalysisSignals) -> NHIProfile:
    """선언된 인벤토리 값으로 NHI 신원을 그대로 구성한다 (`build_profile` 의 AWS 버전)."""
    evidence = [
        f"AWS IAM Access Key 로 확인된 신원 — 유형 {nhi.nhi_type.value}",
        f"Access Key ID: {nhi.access_key_id}",
    ]

    owner = (signals.owner or "").strip() or None
    if owner:
        evidence.append(f"인벤토리에 지정된 Owner: {owner}")
    else:
        evidence.append("Owner 미지정 — 인벤토리에 책임자 정보가 없다")

    if not nhi.raw_scopes:
        evidence.append("원본 권한 정보가 없어 유형 기준으로 보수적으로 가정한다")
    else:
        evidence.append(f"연결된 Policy {len(nhi.raw_scopes)}건: {', '.join(nhi.raw_scopes[:5])}")

    account: Dict[str, Any] = {"id": nhi.nhi_id, "name": nhi.nhi_name}

    return NHIProfile(
        nhi_id=f"aws:{nhi.nhi_id}",
        nhi_name=nhi.nhi_name,
        nhi_type=nhi.nhi_type,
        provider="aws",
        secret_type=nhi.nhi_type.value,
        secret_name=f"AWS {nhi.nhi_type.value.replace('_', ' ').title()}",
        is_bot=nhi.nhi_type in _AWS_BOT_TYPES,
        is_service_account=True,
        linked_ai_agent=signals.agent_name,
        owner=owner,
        owner_candidates=[owner] if owner else [],
        owner_source="external_signal" if owner else None,
        account=account,
        identified=nhi.nhi_type is not NHIType.UNKNOWN_NHI,
        confidence=DECLARED_CONFIDENCE,
        evidence=evidence,
        credential_fingerprint=f"nhi:{nhi.nhi_id}",
    )


def build_aws_context(nhi: AWSNHIInput, signals: AnalysisSignals) -> ContextInsight:
    """선언된 환경 정보로 문맥을 구성한다 (`build_context` 의 AWS 버전).

    Policy 수집을 아직 하지 않아 "접근 가능 자원" 개념이 없다 — GitHub
    저장소·Slack 채널처럼 목록으로 민감도를 추정할 근거가 없으므로
    `data_sensitivity` 는 `UNKNOWN` 으로 둔다(값을 지어내지 않는다).
    """
    notes = ["AWS NHI 인벤토리 입력 — IAM Access Key 조회 값 기준 분석"]
    if nhi.environment is Environment.UNKNOWN:
        notes.append("사용 환경 미지정 — 보수적으로 평가")

    return ContextInsight(
        environment=nhi.environment,
        is_test_or_example=False,
        in_use=nhi.active,
        data_sensitivity=DataSensitivity.UNKNOWN,
        variable_name=None,
        hardcoded_in_source=False,
        project_hint=signals.project,
        path_signals=[],
        code_signals=[],
        confidence=DECLARED_CONFIDENCE,
        notes=notes,
    )
