"""NHI 단위 질의(`authorize`)와 Agent 호출(`authorize_call`)이 같은 규칙 카탈로그를 쓰는지 고정한다."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from backend.services.agent_access_evaluator import AGENT_ACCESS_RULE_CATALOG
from core.governance_models import ControlEventType

from tests.test_agent_access_control import call, control, make_nhi, make_profile
from tests.test_governance import store  # noqa: F401  (fixture 재사용)


def ids(result):
    return {rule["rule_id"] for rule in result["rules"]}


@pytest.mark.parametrize(
    "nhi_overrides, expected",
    [
        ({"lifecycle_stage": "DEACTIVATED"}, "NHI_LIFECYCLE_ENDED"),
        ({"credential_state": "REVOKED"}, "NHI_LIFECYCLE_ENDED"),
        ({"control_state": "QUARANTINED"}, "NHI_QUARANTINED"),
        ({"known_sources": ["10.0.0.1"]}, "UNREGISTERED_SOURCE"),
        ({"last_used_at": "2020-01-01T00:00:00+00:00"}, "DORMANT_CREDENTIAL_REACTIVATED"),
    ],
)
def test_same_condition_yields_same_rule_on_both_paths(store, nhi_overrides, expected):
    make_nhi(store, **nhi_overrides)
    make_profile(store)
    svc = control(store)

    legacy = svc.authorize("nhi-1", "WRITE", source_ip="203.0.113.9")
    agent = svc.authorize_call(call(source_ip="203.0.113.9"))

    assert expected in ids(legacy)
    assert expected in ids(agent)
    legacy_rule = next(r for r in legacy["rules"] if r["rule_id"] == expected)
    agent_rule = next(r for r in agent["rules"] if r["rule_id"] == expected)
    assert legacy_rule["verdict"] == agent_rule["verdict"]
    assert legacy_rule["severity"] == agent_rule["severity"]


def test_permission_overreach_uses_one_rule_and_one_escalation_counter(store):
    make_nhi(store, permissions=["READ"])
    make_profile(store)
    svc = control(store)
    # 레거시 질의와 Agent 호출의 위반이 같은 창에서 합산되어 격리로 올라간다
    assert svc.authorize("nhi-1", "DELETE")["verdict"] == "DENY"
    assert svc.authorize("nhi-1", "DELETE")["verdict"] == "DENY"
    third = svc.authorize("nhi-1", "DELETE")
    assert third["verdict"] == "DENY"
    assert "PERMISSION_SCOPE_EXCEEDED" in ids(third)


def test_legacy_permission_rules(store):
    make_nhi(store, permissions=["READ"])
    svc = control(store)
    assert "UNKNOWN_PERMISSION" in ids(svc.authorize("nhi-1", "SUPERUSER"))
    make_nhi(store, "nhi-2", permissions=[])
    unknown = svc.authorize("nhi-2", "WRITE")
    assert ids(unknown) == {"PERMISSION_BASELINE_INCOMPLETE"} and unknown["allowed"] is False


def test_event_rules_are_in_the_shared_catalog(store):
    make_nhi(store, permissions=["READ", "WRITE"])
    svc = control(store)
    spike = svc.evaluate(
        "nhi-1", ControlEventType.USAGE_SPIKE, {"requests_per_min": 2000, "baseline_per_min": 100}
    )
    exposed = svc.evaluate("nhi-1", ControlEventType.EXPOSURE_DETECTED, {})
    assert ids(spike) == {"USAGE_SPIKE"}
    assert ids(exposed) == {"CREDENTIAL_EXPOSED"}
    assert {"USAGE_SPIKE", "CREDENTIAL_EXPOSED"} <= set(AGENT_ACCESS_RULE_CATALOG)


def test_every_rule_emitted_by_control_service_is_in_the_catalog():
    """control_service.py 안에 카탈로그에 없는 규칙 ID 리터럴이 남아 있지 않아야 한다."""
    source = Path("backend/services/control_service.py").read_text(encoding="utf-8")
    literals = set(re.findall(r'_rule\(\s*"([A-Z0-9_]+)"', source))
    assert literals, "규칙 리터럴을 찾지 못했습니다(패턴 점검 필요)"
    assert literals <= set(AGENT_ACCESS_RULE_CATALOG)
    # 옛 R-번호 ID는 과거 이벤트 이력을 반복 횟수에 합산하기 위한 호환 상수 한 곳에만 남는다.
    legacy = re.findall(r'"(R[1-7]_[A-Z_]+)"', source)
    assert legacy == []  # 신규 판정은 과거 R-번호 기반의 자동 격리를 사용하지 않는다.
