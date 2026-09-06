"""AWS Managed Policy Document 정규화.

`connectors/aws_connector.py::get_policy_document()` 가 반환하는 원문 IAM
Policy Document(`Version`/`Statement`)의 각 Statement 를 다루기 쉬운 공통
구조로 정규화한다. 아직 권한 해석(Read/Write/Delete/Admin 변환)이나 위험도
계산은 하지 않는다 — 그건 다음 단계(Scope Translation)의 몫이다.
"""

from __future__ import annotations

from typing import Any, Dict, List


def normalize_policy_statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """IAM Policy Document 의 Statement 를 정규화된 목록으로 변환한다.

    각 항목은 다음 4개 필드만 가진다:
      * `effect`    — `Effect` 원문("Allow"/"Deny")을 그대로 보존한다.
      * `actions`   — `Action` 을 항상 `List[str]` 로(단일 문자열이면 리스트로 감싼다).
      * `resources` — `Resource` 를 항상 `List[str]` 로(단일 문자열이면 리스트로 감싼다).
      * `condition` — `Condition` 원문을 그대로 보존한다(없으면 `None`).

    IAM 은 Statement 가 하나뿐이면 배열로 감싸지 않고 단일 객체로 줄 수도
    있다 — 이 함수는 그 경우도 처리한다.

    `NotAction`/`NotResource`(Action/Resource 의 여집합 표기)는 아직
    지원하지 않는다 — 해당 Statement 의 `actions`/`resources` 는 빈
    리스트로 남는다. `Action`/`NotAction` 이 둘 다 있는 것은 IAM 문법상
    불가능하므로, 이 값을 지어내서 채우지 않는 편이 실제 정책보다 권한을
    과소평가하는 방향이라 더 안전하다.
    """
    if not isinstance(document, dict):
        return []

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        normalized.append(
            {
                "effect": statement.get("Effect"),
                "actions": _as_string_list(statement.get("Action")),
                "resources": _as_string_list(statement.get("Resource")),
                "condition": statement.get("Condition"),
            }
        )
    return normalized


def _as_string_list(value: Any) -> List[str]:
    """단일 문자열이면 리스트로 감싸고, 이미 리스트면 문자열 항목만 남기고,
    그 외(없음·잘못된 타입)는 빈 리스트로 만든다 — 값을 지어내지 않는다."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
