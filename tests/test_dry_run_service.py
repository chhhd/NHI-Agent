"""agents/dry_run_service.py::build_dry_run_result() — Dry-run 기본 구조 검증.

실제 조치를 수행하지 않고(레코드를 읽기만 함), recommended_action 기준으로
예상 변경 사항과 위험도 추정치만 계산하는지 확인한다. 실행/승인 엔진 연결은
이 단계 범위 밖이다.
"""

from __future__ import annotations

from agents.dry_run_service import build_dry_run_result
from core.nhi_models import RecommendedAction


def _record(**overrides):
    base = {
        "nhi_id": "aws:aws-123-AKIAEXAMPLE",
        "nhi_name": "ci-deploy-user",
        "provider": "aws",
        "risk_score": 80,
        "risk_level": "HIGH",
        "recommended_action": RecommendedAction.TOKEN_REVOCATION.value,
    }
    base.update(overrides)
    return base


def test_response_contains_exactly_the_requested_fields():
    result = build_dry_run_result("aws:x", _record())
    assert set(result.keys()) == {
        "target_nhi_id",
        "recommended_action",
        "expected_changes",
        "risk_before",
        "risk_after_estimate",
    }


def test_target_nhi_id_matches_argument_not_record():
    """target_nhi_id 는 호출부가 넘긴 nhi_id 를 그대로 반영한다."""
    result = build_dry_run_result("aws:explicit-id", _record(nhi_id="other-id"))
    assert result["target_nhi_id"] == "aws:explicit-id"


def test_recommended_action_is_read_from_record():
    result = build_dry_run_result("x", _record(recommended_action="SCOPE_REDUCTION"))
    assert result["recommended_action"] == "SCOPE_REDUCTION"


def test_risk_before_matches_stored_risk_score():
    result = build_dry_run_result("x", _record(risk_score=42))
    assert result["risk_before"] == 42


def test_token_revocation_reduces_risk_to_zero():
    """폐기는 위험을 사실상 제거하는 조치이므로 감소율 100%."""
    result = build_dry_run_result("x", _record(risk_score=90, recommended_action="TOKEN_REVOCATION"))
    assert result["risk_after_estimate"] == 0
    assert result["expected_changes"]


def test_monitor_does_not_reduce_risk():
    result = build_dry_run_result("x", _record(risk_score=55, recommended_action="MONITOR"))
    assert result["risk_after_estimate"] == 55


def test_token_rotation_reduces_risk_partially():
    result = build_dry_run_result("x", _record(risk_score=80, recommended_action="TOKEN_ROTATION"))
    assert 0 < result["risk_after_estimate"] < 80


def test_risk_after_estimate_never_negative():
    result = build_dry_run_result("x", _record(risk_score=0, recommended_action="TOKEN_REVOCATION"))
    assert result["risk_after_estimate"] == 0


def test_missing_risk_score_defaults_to_zero():
    record = _record()
    del record["risk_score"]
    result = build_dry_run_result("x", record)
    assert result["risk_before"] == 0
    assert result["risk_after_estimate"] == 0


def test_missing_recommended_action_defaults_to_monitor():
    record = _record()
    del record["recommended_action"]
    result = build_dry_run_result("x", record)
    assert result["recommended_action"] == RecommendedAction.MONITOR.value


def test_unknown_action_falls_back_to_safe_defaults_without_raising():
    """향후 추가될 수 있는 미지의 조치 유형이 와도 예외 없이 안전하게 처리한다."""
    result = build_dry_run_result("x", _record(risk_score=50, recommended_action="SOME_FUTURE_ACTION"))
    assert result["recommended_action"] == "SOME_FUTURE_ACTION"
    assert result["risk_after_estimate"] == 50  # 감소율 0 (정의되지 않음)
    assert result["expected_changes"] == ["정의된 예상 변경 사항이 없습니다."]


def test_every_recommended_action_has_expected_changes_defined():
    """열거형에 정의된 모든 조치는 실제로 안내 문구가 준비돼 있어야 한다."""
    for action in RecommendedAction:
        result = build_dry_run_result("x", _record(recommended_action=action.value))
        assert result["expected_changes"] != ["정의된 예상 변경 사항이 없습니다."], action
