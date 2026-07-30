"""Recommendation Agent — 위험도·정책 판정을 실제 조치 권고로 바꾼다.

권고 종류
  Token 폐기 / Token Rotation / API Scope 축소 / Owner 지정 /
  프로젝트별 Token 분리 / 환경변수 이전 / 비활성 NHI 중지 / 재승인 요청

여러 권고가 동시에 나올 수 있으며, `priority` 가 가장 낮은(=시급한) 항목이
`NHIAnalysis.recommended_action` 이 된다.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Set

from core.nhi_models import (
    NHIType,
    PermissionLevel,
    PolicyEvaluation,
    PolicyOutcome,
    RecommendedAction,
    Recommendation,
    RiskAssessment,
    RiskLevel,
    parse_dt,
)
from policy.rules import EvaluationContext, is_inactive_nhi

logger = logging.getLogger(__name__)

#: 즉시 폐기가 필요한 강제 Critical 규칙
_REVOCATION_RULES = {
    "REVOKED_TOKEN_STILL_USED",
    "TERMINATED_AGENT_ACTIVE_TOKEN",
    "READ_ONLY_NHI_PERFORMS_MUTATION",
}


class RecommendationAgent:
    """조치 권고 생성."""

    def recommend(
        self,
        ctx: EvaluationContext,
        risk: RiskAssessment,
        policy: PolicyEvaluation,
    ) -> List[Recommendation]:
        target = f"{ctx.profile.nhi_name} ({ctx.profile.credential_fingerprint[:23]})"
        rules: Set[str] = {r["rule_id"] for r in risk.forced_rules}
        auto = policy.auto_remediable
        recommendations: List[Recommendation] = []

        def _add(
            action: RecommendedAction,
            priority: int,
            rationale: str,
            *,
            automatable: bool = False,
        ) -> None:
            recommendations.append(
                Recommendation(
                    action=action,
                    priority=priority,
                    rationale=rationale,
                    target=target,
                    automatable=automatable and auto,
                )
            )

        # 1) Token 폐기 — 정상 사용으로 되돌릴 수 없는 상태
        revocation_reason = self._revocation_reason(ctx, rules)
        if revocation_reason:
            _add(RecommendedAction.TOKEN_REVOCATION, 1, revocation_reason, automatable=True)

        # 2) Token Rotation — 노출된 활성(또는 상태 미상) 자격 증명
        rotation_reason = self._rotation_reason(ctx)
        if rotation_reason:
            _add(RecommendedAction.TOKEN_ROTATION, 2, rotation_reason, automatable=True)

        # 3) API Scope 축소
        scope_reason = self._scope_reduction_reason(ctx)
        if scope_reason:
            _add(RecommendedAction.SCOPE_REDUCTION, 3, scope_reason)

        # 4) Owner 지정
        if ctx.profile.owner is None:
            candidates = ", ".join(ctx.profile.owner_candidates[:3]) or "후보 없음"
            _add(
                RecommendedAction.ASSIGN_OWNER,
                4,
                f"책임자가 없는 NHI 다. 소유자를 지정해야 한다. (후보: {candidates})",
            )

        # 5) 프로젝트별 Token 분리
        projects = ctx.shared_projects
        if len(projects) >= 2:
            _add(
                RecommendedAction.SPLIT_TOKEN_PER_PROJECT,
                5,
                f"{len(projects)}개 프로젝트가 같은 Token 을 공유한다"
                f"({', '.join(projects[:3])}). 프로젝트별로 분리 발급해야 한다.",
            )

        # 6) 환경변수·시크릿 매니저 이전
        if self._needs_env_migration(ctx):
            _add(
                RecommendedAction.MOVE_TO_ENV_VAR,
                6,
                f"{ctx.finding.file_path} 에 평문으로 저장되어 있다. "
                "환경변수 또는 시크릿 매니저로 옮겨야 한다.",
            )

        # 7) 비활성 NHI 중지
        if is_inactive_nhi(ctx) and ctx.is_active is not False:
            days = ctx.days_since_use
            detail = f"{days}일간 미사용" if days is not None else "Agent 종료 상태"
            _add(
                RecommendedAction.DISABLE_INACTIVE_NHI,
                7,
                f"사용되지 않는 NHI 다({detail}). 계정을 비활성화해야 한다.",
                automatable=True,
            )

        # 8) 재승인 요청
        reapproval_reason = self._reapproval_reason(ctx, risk, policy)
        if reapproval_reason:
            _add(RecommendedAction.REQUEST_REAPPROVAL, 8, reapproval_reason)

        if not recommendations:
            _add(
                RecommendedAction.MONITOR,
                9,
                "정책 위반이 없고 위험도가 낮다. 정기 점검 대상으로만 관리한다.",
            )

        return sorted(recommendations, key=lambda r: r.priority)

    # ------------------------------------------------------------------
    @staticmethod
    def _revocation_reason(ctx: EvaluationContext, rules: Set[str]) -> Optional[str]:
        hit = rules & _REVOCATION_RULES
        if "REVOKED_TOKEN_STILL_USED" in hit:
            return "폐기 처리된 Token 이 계속 호출되고 있다. 즉시 완전 폐기하고 사용처를 추적해야 한다."
        if "TERMINATED_AGENT_ACTIVE_TOKEN" in hit:
            return "종료된 AI Agent 의 Token 이 살아있다. 즉시 폐기해야 한다."
        if "READ_ONLY_NHI_PERFORMS_MUTATION" in hit:
            return "조회 전용 NHI 가 변경 행위를 수행했다. Token 을 폐기하고 침해 여부를 조사해야 한다."
        if ctx.signals.token_used_after_revocation is True:
            return "폐기 이후 사용 기록이 있다. 즉시 완전 폐기가 필요하다."

        expires_at = parse_dt(ctx.signals.expires_at)
        if expires_at is not None and expires_at < datetime.now(timezone.utc) and ctx.is_active is not False:
            return (
                f"만료일({ctx.signals.expires_at})이 지난 자격 증명이 남아 있다. "
                "사용 여부를 확인하고 폐기하거나 재발급해야 한다."
            )
        return None

    @staticmethod
    def _rotation_reason(ctx: EvaluationContext) -> Optional[str]:
        """Rotation 권고 사유. 근거가 없으면 권고하지 않는다."""
        if ctx.context.is_test_or_example and ctx.finding.credential_active is not True:
            return None
        if ctx.finding.credential_revoked is True or ctx.is_active is False:
            return None

        uncertain = "" if ctx.finding.credential_active is True else " (상태 미확인이므로 보수적으로 권고)"

        if ctx.from_code_scan:
            return (
                "저장소에 노출된 자격 증명이다. 기존 Token 을 폐기하고 재발급해야 한다." + uncertain
            )

        # 인벤토리 입력 — 노출 사실이 없으므로 수명 관리 관점에서만 권고한다.
        rotation = ctx.days_since_rotation
        if rotation is not None and rotation > ctx.config.rotation_period_days:
            return (
                f"마지막 회전 후 {rotation}일 경과했다(주기 {ctx.config.rotation_period_days}일). "
                "Token 을 재발급해야 한다."
            )
        if not ctx.signals.expires_at:
            return (
                "만료일 없이 유지되는 자격 증명이다. 만료일을 설정하고 정기적으로 재발급해야 한다."
                + uncertain
            )
        return None

    @staticmethod
    def _scope_reduction_reason(ctx: EvaluationContext) -> Optional[str]:
        permissions = set(ctx.permissions.permissions)
        if PermissionLevel.ADMIN in permissions:
            return (
                f"{ctx.profile.nhi_type.value} 에 관리자 권한이 부여되어 있다. "
                "필요한 최소 Scope 로 축소해야 한다."
            )
        if PermissionLevel.DELETE in permissions:
            return "삭제 권한이 포함되어 있다. 실제 필요 여부를 확인하고 제거해야 한다."

        observed = set(ctx.observed_permissions)
        if observed and permissions - observed:
            unused = ", ".join(sorted(p.value for p in permissions - observed))
            return f"부여됐지만 실제로 사용되지 않는 권한이 있다: {unused}"
        return None

    @staticmethod
    def _needs_env_migration(ctx: EvaluationContext) -> bool:
        # 코드에서 평문으로 발견된 경우에만 "환경변수로 옮기라" 는 권고가 성립한다.
        if not ctx.from_code_scan:
            return False
        if ctx.context.is_test_or_example and ctx.finding.credential_active is not True:
            return False
        return True

    @staticmethod
    def _reapproval_reason(
        ctx: EvaluationContext, risk: RiskAssessment, policy: PolicyEvaluation
    ) -> Optional[str]:
        if policy.outcome is PolicyOutcome.HUMAN_REVIEW:
            if ctx.profile.nhi_type is NHIType.UNKNOWN_NHI:
                return "NHI 를 특정하지 못했다. 담당 팀 확인 후 사용 목적을 재승인받아야 한다."
            return (
                f"위험 등급 {risk.level.value} — 계속 사용하려면 보안 담당자의 재승인이 필요하다."
            )
        if ctx.signals.exception_id and policy.exception_applied is None:
            return f"예외 승인 {ctx.signals.exception_id} 이 만료됐다. 재승인이 필요하다."
        if risk.level is RiskLevel.CRITICAL:
            return "Critical 등급 자산이다. 사용 목적과 권한을 재승인받아야 한다."
        return None
