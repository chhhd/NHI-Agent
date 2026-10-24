"""논문(JDCS 2020.21.3.617) ER·EC·PW·FR·UR 기반 시나리오 평가 결과 모델.

``core/nhi_models.py`` 의 ``RiskAssessment``/``ScenarioMatch`` 와는 완전히 독립된
축이다. 100점 Risk Score 계산(``policy/scoring.py``)이나 강제 Critical 판정
(``policy/rules.py``)에는 어떤 필드도 가산되지 않는다 — 설명·근거 전용 결과물이다.

데이터가 부족하거나 가중치(ER 매핑표 / UR 산정 기준 / FR 세트 판정 알고리즘)가 아직
팀 승인을 받지 않은 경우, 숫자를 추정하지 않고 ``EvaluationStatus`` 로 사유를 명시한다.
의도적으로 등급(심각/위험/경고/주의 등) 필드를 두지 않는다 — 논문의 400/300/200/100
임계값을 NHI-Agent 척도에 어떻게 맞출지 아직 팀이 결정하지 않았기 때문이다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    # core.nhi_models 와 동일한 구현이다 — 이 모듈이 core.nhi_models 를 import하면
    # (nhi_models -> scenario_evaluation_models) 순환 import 가 생겨 별도로 둔다.
    return datetime.now(timezone.utc).isoformat()


class EvaluationStatus(str, Enum):
    """시나리오 평가 구성요소 1건의 산출 가능 여부."""

    #: 필요한 입력이 모두 있어 점수를 실제로 계산했다.
    EVALUATED = "evaluated"
    #: 타임스탬프 이벤트가 부족해 계산할 수 없다 (예: 해당 단계 이벤트 0건).
    INSUFFICIENT_DATA = "insufficient_data"
    #: 계산에 필요한 가중치·매핑표·알고리즘을 아직 팀이 승인하지 않았다.
    UNCONFIGURED_WEIGHT = "unconfigured_weight"
    #: 이 NHI/provider 에는 애초에 이벤트 소스가 연결되어 있지 않다.
    NOT_APPLICABLE = "not_applicable"


@dataclass
class StageEventScore:
    """논문 식 (1) ``Ws_i = ER_Si * EC_Si`` — 단계(S1/S2/S3) 1개의 산출 결과."""

    stage: str  # "S1" | "S2" | "S3"
    status: EvaluationStatus
    er_raw_score: Optional[int] = None
    er_basis: Optional[str] = None
    event_count: Optional[int] = None
    peak_day: Optional[str] = None
    ec_weight: Optional[int] = None
    stage_score: Optional[int] = None
    event_ids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class PeriodWeightResult:
    """논문 표6 — 발생 기간 가중치(PW). S1 최초 ~ S3 최종 이벤트 사이 기간."""

    status: EvaluationStatus
    first_event_at: Optional[str] = None
    last_event_at: Optional[str] = None
    period_days: Optional[int] = None
    pw_weight: Optional[float] = None
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class FrequencyRiskResult:
    """논문 표7 — 발생 빈도 위험도(FR). S1→S2→S3 완결 세트 반복 횟수."""

    status: EvaluationStatus
    completed_cycle_count: Optional[int] = None
    fr_score: Optional[int] = None
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class CycleDetectionResult:
    """``cycle_detector`` 호출 1건의 결과 — FR 계산의 투명성 확보용 구조체.

    ``PaperScenarioEvaluator`` 는 이 결과의 ``completed_cycle_count`` 만 FR 점수
    산정에 쓰고, 나머지 필드는 "왜 이 숫자가 나왔는지"를 설명하는 근거다.
    """

    completed_cycle_count: int
    reasons: List[str] = field(default_factory=list)
    #: 완결되지 못한(S2 또는 S3를 찾지 못한) 이벤트 ID
    unresolved_event_ids: List[str] = field(default_factory=list)
    #: 자산 식별자(project/resource)가 없어 평가 대상에서 제외한 이벤트 ID
    skipped_missing_asset_event_ids: List[str] = field(default_factory=list)
    #: 동일 이벤트 ID가 중복으로 들어와 이후 발생분을 무시한 이벤트 ID
    duplicate_event_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UserRiskResult:
    """논문 표8 — 사용자 가산치(UR). NHI-Agent 에는 인사정보 소스가 없어
    ``user_risk_resolver`` 를 명시적으로 주입하지 않는 한 항상 미확정이다."""

    status: EvaluationStatus
    basis: Optional[str] = None
    ur_score: Optional[int] = None
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ScenarioEvaluationResult:
    """NHI 1건에 대한 논문 모델 평가 결과 — ``RiskAssessment`` 와 독립된 부가 산출물.

    ``raw_score`` (논문 식 (2) ``W = Σ Ws_i + TR + UR``)는 7개 하위 항목이
    전부 ``EVALUATED`` 일 때만 값이 채워진다. 하나라도 미완성이면 ``None`` 이며,
    그 사유는 ``status``/``reasons`` 에 남는다 — 부분합으로 대체하지 않는다.
    """

    nhi_id: str
    status: EvaluationStatus
    stage_scores: Dict[str, StageEventScore] = field(default_factory=dict)
    unmapped_event_ids: List[str] = field(default_factory=list)
    #: ER/EC 계산 전 제거된 중복 event_id. 내용이 다르더라도 입력 순서상 먼저
    #: 나타난 레코드를 채택하고 이후 발생분은 버린다(StageCycleDetector와 동일 기준).
    duplicate_event_ids: List[str] = field(default_factory=list)
    stage_sum: Optional[int] = None
    period_weight: Optional[PeriodWeightResult] = None
    frequency_risk: Optional[FrequencyRiskResult] = None
    threat_addition: Optional[int] = None  # TR = PW * FR
    user_risk: Optional[UserRiskResult] = None
    raw_score: Optional[int] = None  # W = sum(Ws_i) + TR + UR
    evaluated_at: str = field(default_factory=_utcnow)
    paper_reference: str = "JDCS 2020.21.3.617 §3 (ER·EC·PW·FR·UR)"
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nhi_id": self.nhi_id,
            "status": self.status.value,
            "stage_scores": {
                stage: score.to_dict() for stage, score in self.stage_scores.items()
            },
            "unmapped_event_ids": list(self.unmapped_event_ids),
            "duplicate_event_ids": list(self.duplicate_event_ids),
            "stage_sum": self.stage_sum,
            "period_weight": self.period_weight.to_dict() if self.period_weight else None,
            "frequency_risk": self.frequency_risk.to_dict() if self.frequency_risk else None,
            "threat_addition": self.threat_addition,
            "user_risk": self.user_risk.to_dict() if self.user_risk else None,
            "raw_score": self.raw_score,
            "evaluated_at": self.evaluated_at,
            "paper_reference": self.paper_reference,
            "reasons": list(self.reasons),
        }


__all__ = [
    "EvaluationStatus",
    "StageEventScore",
    "PeriodWeightResult",
    "FrequencyRiskResult",
    "CycleDetectionResult",
    "UserRiskResult",
    "ScenarioEvaluationResult",
]
