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

from core.inventory_models import GitHubNHIInput
from core.models import DetectorType, SecretFinding, Severity
from core.nhi_models import (
    AnalysisSignals,
    ContextInsight,
    DataSensitivity,
    Environment,
    NHIProfile,
    NHIType,
)

#: 인벤토리 입력의 신뢰도 — 선언된 메타데이터이므로 추정보다 높게 본다.
DECLARED_CONFIDENCE = 0.9

#: Bot 계정으로 취급하는 NHI 유형
_BOT_TYPES = {NHIType.GITHUB_APP}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def repository_records(nhi: GitHubNHIInput) -> List[Dict[str, Any]]:
    """접근 가능 저장소를 신호·Blast Radius 공통 형식으로 만든다."""
    return [
        {
            "full_name": repo.name,
            "name": repo.name,
            "visibility": repo.visibility,
            "is_sensitive": repo.is_sensitive,
        }
        for repo in nhi.repositories
    ]


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
        credential_active=nhi.active,
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
        # 외부 account payload가 canonical NHI id/name을 덮어쓰지 못하게 한다.
        account={**dict(nhi.account), "id": nhi.nhi_id, "name": nhi.nhi_name},
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
