"""규칙 기반 Risk Scoring — 100점 만점.

| 평가 영역                  | 배점 |
| -------------------------- | ---- |
| 노출 위치                  | 20   |
| API 권한 수준              | 20   |
| 운영 환경 및 데이터 중요도 | 15   |
| Credential 상태            | 15   |
| 사용 및 이상행위           | 15   |
| Owner·정책 관리 상태       | 10   |
| 연결 서비스 영향 범위      |  5   |

등급: Critical 80~100 / High 60~79 / Medium 30~59 / Low 0~29
강제 Critical 규칙에 걸리면 점수와 무관하게 CRITICAL 로 승격한다
(이때 `base_score` 에 원래 점수를 남긴다).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.nhi_models import (
    DataSensitivity,
    Environment,
    PermissionLevel,
    PolicyViolation,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    parse_dt,
)
from policy.rules import EvaluationContext, evaluate_forced_critical

#: 평가 영역별 배점
AREA_MAX: Dict[str, int] = {
    "exposure_location": 20,
    "api_permission": 20,
    "environment_data": 15,
    "credential_state": 15,
    "usage_anomaly": 15,
    "ownership_policy": 10,
    "connected_service_impact": 5,
}

AREA_LABEL: Dict[str, str] = {
    "exposure_location": "노출 위치",
    "api_permission": "API 권한 수준",
    "environment_data": "운영 환경 및 데이터 중요도",
    "credential_state": "Credential 상태",
    "usage_anomaly": "사용 및 이상행위",
    "ownership_policy": "Owner·정책 관리 상태",
    "connected_service_impact": "연결 서비스 영향 범위",
}

#: 위험 등급 하한선
LEVEL_THRESHOLDS = (
    (80, RiskLevel.CRITICAL),
    (60, RiskLevel.HIGH),
    (30, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
)

#: 강제 Critical 승격 시 보장하는 최소 점수
FORCED_CRITICAL_MIN_SCORE = 80


def risk_level_for(score: int) -> RiskLevel:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


class RiskScorer:
    """평가 영역별 점수를 합산해 위험 등급을 만든다."""

    def score(
        self,
        ctx: EvaluationContext,
        violations: Optional[List[PolicyViolation]] = None,
    ) -> RiskAssessment:
        violations = violations or []
        factors = [
            self._exposure_location(ctx),
            self._api_permission(ctx),
            self._environment_data(ctx),
            self._credential_state(ctx),
            self._usage_anomaly(ctx),
            self._ownership_policy(ctx, violations),
            self._connected_service_impact(ctx),
        ]

        base_score = min(100, sum(f.score for f in factors))
        forced = evaluate_forced_critical(ctx)

        if forced:
            score = max(base_score, FORCED_CRITICAL_MIN_SCORE)
            level = RiskLevel.CRITICAL
        else:
            score = base_score
            level = risk_level_for(score)

        return RiskAssessment(
            score=score,
            level=level,
            base_score=base_score,
            factors=factors,
            reasons=self._collect_reasons(factors, forced),
            forced_critical=bool(forced),
            forced_rules=forced,
        )

    # ------------------------------------------------------------------
    # 1) 노출 위치 (20)
    # ------------------------------------------------------------------
    def _exposure_location(self, ctx: EvaluationContext) -> RiskFactor:
        """노출 면적.

        코드 스캔 건은 "Secret 이 어디에 노출됐는가", 인벤토리 입력 건은
        "이 NHI 가 어디까지 접근할 수 있는가" 가 노출 면적이다.
        """
        if not ctx.from_code_scan:
            return self._exposure_access_scope(ctx)

        reasons: List[str] = []
        public = ctx.signals.repository_public

        if public is True:
            score = 16
            reasons.append("공개 Repository 노출")
        elif public is False:
            score = 9
            reasons.append("비공개 Repository 노출")
        else:
            score = 11
            reasons.append("Repository 공개 여부 미확인 — 보수적으로 평가")

        occurrences = ctx.finding.occurrence_count
        if occurrences >= 3:
            score += 3
            reasons.append(f"{occurrences}개 위치에 중복 노출")
        elif occurrences == 2:
            score += 2
            reasons.append("2개 위치에 중복 노출")

        if ctx.context.hardcoded_in_source:
            score += 2
            reasons.append("소스 코드에 직접 하드코딩")

        if len(ctx.shared_projects) >= 2:
            score += 1
            reasons.append("여러 프로젝트에 걸쳐 노출")

        if ctx.context.is_test_or_example:
            score = min(score, 5)
            reasons.append("테스트·예제 값으로 판단되어 노출 위험 하향")

        return self._factor("exposure_location", score, reasons)

    def _exposure_access_scope(self, ctx: EvaluationContext) -> RiskFactor:
        """인벤토리 입력 — 접근 가능한 저장소 범위로 노출 면적을 평가한다."""
        reasons: List[str] = []
        repositories = ctx.accessible_repositories
        total = len(repositories)
        threshold = ctx.config.broad_repository_access_threshold

        private = sum(
            1
            for repo in repositories
            if str(repo.get("visibility", "private")).strip().lower() != "public"
        )
        sensitive = sum(1 for repo in repositories if repo.get("is_sensitive") is True)

        if total == 0:
            score = 8
            reasons.append("접근 가능한 저장소 목록 미확인 — 보수적으로 평가")
        elif total >= threshold:
            score = 14
            reasons.append(f"{total}개 저장소에 광범위하게 접근 가능 (기준 {threshold}개)")
        elif total >= 2:
            score = 8
            reasons.append(f"{total}개 저장소에 접근 가능")
        else:
            score = 4
            reasons.append("단일 저장소에만 접근 가능")

        if private:
            score += 3
            reasons.append(f"비공개 저장소 {private}개 접근 가능")
        if sensitive:
            score += 3
            reasons.append(f"민감 저장소 {sensitive}개 접근 가능")

        return self._factor("exposure_location", score, reasons)

    # ------------------------------------------------------------------
    # 2) API 권한 수준 (20)
    # ------------------------------------------------------------------
    def _api_permission(self, ctx: EvaluationContext) -> RiskFactor:
        reasons: List[str] = []
        by_level = {
            PermissionLevel.ADMIN: 20,
            PermissionLevel.DELETE: 16,
            PermissionLevel.WRITE: 12,
            PermissionLevel.READ: 6,
        }
        highest = ctx.permissions.highest
        if highest is None:
            score = 8
            reasons.append("권한 범위 확인 불가 — 중간값 적용")
        else:
            score = by_level[highest]
            reasons.append(f"최고 권한 {highest.value}")

        if len(ctx.permissions.permissions) >= 3:
            score += 2
            reasons.append("읽기·쓰기·삭제 등 광범위한 권한 조합")

        if ctx.permissions.assumed:
            reasons.append("Scope 를 확인하지 못해 Secret 유형 기준으로 가정")

        return self._factor("api_permission", score, reasons)

    # ------------------------------------------------------------------
    # 3) 운영 환경 및 데이터 중요도 (15)
    # ------------------------------------------------------------------
    def _environment_data(self, ctx: EvaluationContext) -> RiskFactor:
        reasons: List[str] = []
        env_score = {
            Environment.PRODUCTION: 9,
            Environment.STAGING: 6,
            Environment.DEVELOPMENT: 3,
            Environment.TEST: 1,
            Environment.UNKNOWN: 5,
        }[ctx.context.environment]
        if ctx.context.environment is Environment.PRODUCTION:
            reasons.append("운영 환경에서 사용 중")
        elif ctx.context.environment is Environment.UNKNOWN:
            reasons.append("환경 식별 불가 — 보수적으로 평가")
        else:
            reasons.append(f"{ctx.context.environment.value} 환경")

        sensitivity_score = {
            DataSensitivity.RESTRICTED: 6,
            DataSensitivity.CONFIDENTIAL: 4,
            DataSensitivity.INTERNAL: 2,
            DataSensitivity.PUBLIC: 0,
            DataSensitivity.UNKNOWN: 2,
        }[ctx.context.data_sensitivity]
        if sensitivity_score >= 4:
            reasons.append(f"{ctx.context.data_sensitivity.value} 등급 데이터 접근 가능")

        return self._factor("environment_data", env_score + sensitivity_score, reasons)

    # ------------------------------------------------------------------
    # 4) Credential 상태 (15)
    # ------------------------------------------------------------------
    def _credential_state(self, ctx: EvaluationContext) -> RiskFactor:
        reasons: List[str] = []
        finding = ctx.finding

        if finding.credential_revoked is True:
            score = 2
            reasons.append("폐기된 자격 증명")
        elif finding.credential_active is True:
            score = 8
            reasons.append("외부 검증 결과 활성 Token")
        elif finding.credential_active is False:
            score = 1
            reasons.append("비활성 자격 증명")
        else:
            score = 5
            reasons.append("자격 증명 상태 미확인 — 보수적으로 평가")

        if finding.credential_active is True and not ctx.signals.expires_at:
            score += 3
            reasons.append("만료일 없는 활성 Token")

        expires_at = parse_dt(ctx.signals.expires_at)
        if expires_at is not None and expires_at < datetime.now(timezone.utc):
            score += 2
            reasons.append(f"만료일이 이미 지난 자격 증명 ({ctx.signals.expires_at})")

        age = ctx.token_age_days
        if age is not None and age > ctx.config.max_token_age_days:
            score += 2
            reasons.append(f"Token 수명 초과 ({age}일)")

        rotation = ctx.days_since_rotation
        if rotation is not None and rotation > ctx.config.rotation_period_days:
            score += 2
            reasons.append(f"Rotation 주기 초과 ({rotation}일 경과)")
        elif rotation is None and finding.credential_active is True:
            score += 1
            reasons.append("Rotation 이력 없음")

        return self._factor("credential_state", score, reasons)

    # ------------------------------------------------------------------
    # 5) 사용 및 이상행위 (15)
    # ------------------------------------------------------------------
    def _usage_anomaly(self, ctx: EvaluationContext) -> RiskFactor:
        reasons: List[str] = []
        score = 0

        if ctx.context.in_use is True:
            score += 5
            reasons.append("실제 사용 중인 Secret")
        elif ctx.context.in_use is None:
            score += 3
            reasons.append("사용 여부 미확인 — 보수적으로 평가")

        days = ctx.days_since_use
        if days is not None:
            # 노출된 Secret 이 최근까지 쓰였다는 것은 침해 시 즉시 악용 가능하다는 신호다.
            # 인벤토리 NHI 의 "최근 사용" 은 정상 운영 상태이므로 가산하지 않는다.
            if days <= 7 and ctx.from_code_scan:
                score += 3
                reasons.append(f"최근 {days}일 이내 사용됨")
            elif days > ctx.config.inactive_days:
                score += 2
                reasons.append(f"{days}일간 미사용 상태로 방치")

        if ctx.signals.token_used_after_revocation is True:
            score += 7
            reasons.append("폐기 이후에도 호출 기록 존재")

        declared = set(ctx.declared_permissions)
        observed = set(ctx.observed_permissions)
        if declared and observed - declared:
            over = ", ".join(sorted(p.value for p in observed - declared))
            score += 5
            reasons.append(f"승인 범위를 넘는 행위 관측: {over}")

        anomalies = ctx.signals.extra.get("anomalies") if ctx.signals.extra else None
        if isinstance(anomalies, (list, tuple)):
            for anomaly in list(anomalies)[:3]:
                score += 2
                reasons.append(f"이상행위: {anomaly}")

        return self._factor("usage_anomaly", score, reasons)

    # ------------------------------------------------------------------
    # 6) Owner·정책 관리 상태 (10)
    # ------------------------------------------------------------------
    def _ownership_policy(
        self, ctx: EvaluationContext, violations: List[PolicyViolation]
    ) -> RiskFactor:
        reasons: List[str] = []
        score = 0

        if ctx.profile.owner is None:
            score += 5
            reasons.append("Owner 미지정 NHI")
        elif ctx.profile.owner_source not in ("external_signal", "credential_account"):
            score += 2
            reasons.append(f"Owner 추정값({ctx.profile.owner}) — 공식 확인 필요")

        others = [v for v in violations if v.policy_id != "OWNER_REQUIRED"]
        if others:
            added = min(5, 2 * len(others))
            score += added
            reasons.append(f"정책 위반 {len(others)}건: {', '.join(v.policy_id for v in others[:3])}")

        return self._factor("ownership_policy", score, reasons)

    # ------------------------------------------------------------------
    # 7) 연결 서비스 영향 범위 (5)
    # ------------------------------------------------------------------
    def _connected_service_impact(self, ctx: EvaluationContext) -> RiskFactor:
        reasons: List[str] = []
        blast = ctx.blast_radius
        count = len(blast.connected_services)

        if count >= 3:
            score = 3
            reasons.append(f"{count}개 서비스와 연결")
        elif count == 2:
            score = 2
            reasons.append("2개 서비스와 연결")
        else:
            score = 1
            reasons.append("단일 서비스 연결")

        if blast.cross_project_impact:
            score += 1
            reasons.append("다른 프로젝트까지 영향")
        if blast.external_transfer_possible:
            score += 1
            reasons.append("외부 전송 가능")

        return self._factor("connected_service_impact", score, reasons)

    # ------------------------------------------------------------------
    @staticmethod
    def _factor(area: str, score: int, reasons: List[str]) -> RiskFactor:
        max_score = AREA_MAX[area]
        return RiskFactor(
            area=area,
            label=AREA_LABEL[area],
            score=max(0, min(score, max_score)),
            max_score=max_score,
            reasons=reasons,
        )

    @staticmethod
    def _collect_reasons(factors: List[RiskFactor], forced: List[Dict[str, str]]) -> List[str]:
        """강제 Critical 근거를 앞에 두고, 점수가 큰 영역 순으로 근거를 모은다."""
        reasons = [f["reason"] for f in forced]
        ordered = sorted(factors, key=lambda f: f.score / f.max_score, reverse=True)
        for factor in ordered:
            for reason in factor.reasons:
                if reason not in reasons:
                    reasons.append(reason)
        return reasons
