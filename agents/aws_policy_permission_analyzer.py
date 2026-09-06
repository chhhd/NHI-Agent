"""AWS Policy 의 Allow Action 을 공통 권한별로 집계한다.

`agents/aws_policy_normalizer.py::normalize_policy_statements()` 가 만든
정규화된 Statement 목록을 받아, `Effect=Allow` 인 Statement 의 `actions` 만
`agents/aws_permission_mapper.py::map_action()` 으로 변환해 READ/WRITE/
DELETE/ADMIN/UNKNOWN 개수를 센다.

이 분석은 "정책에 Allow 로 어떤 권한이 나열돼 있는가" 만 답한다 — "실제로
이 자격 증명이 무엇을 할 수 있는가" 를 답하려면 Resource 범위·Condition
제약·Deny 가 Allow 를 부분적으로 무효화하는 IAM 평가 순서까지 반영해야
하고, 이는 아직 하지 않는다. `Effect=Deny` 인 Statement 는 개수를 세고
원문을 그대로 보존만 할 뿐, Allow 집계에서 상쇄하는 계산은 하지 않는다.

Resource 는 딱 한 가지만 최소로 본다 — Allow Statement 의 Resource 에
전체(`"*"`) 또는 서비스 전체(`"arn:...:*"`) 급 wildcard 가 있는지
(`broad_access`). GitHub/Slack 처럼 "접근 가능 자원이 몇 개인가"를 세는
것과 달리, AWS 정책은 Resource 가 ARN 패턴/와일드카드라 "몇 개"라는 개수
자체가 의미가 없다 — 그래서 개수 대신 "광범위한가"라는 이진값만 본다.
`"arn:...:my-bucket/*"` 처럼 특정 리소스 하나 아래의 wildcard 는 좁은
범위라 broad_access 로 치지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from agents.aws_permission_mapper import map_action
from core.nhi_models import PermissionLevel


@dataclass
class AWSPolicyPermissionCounts:
    """Allow Statement 의 Action 을 공통 권한별로 집계한 개수."""

    read: int = 0
    write: int = 0
    delete: int = 0
    admin: int = 0
    #: `map_action()` 이 `None` 을 반환한(모호하거나 알려지지 않은) Action 개수.
    unknown: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "READ": self.read,
            "WRITE": self.write,
            "DELETE": self.delete,
            "ADMIN": self.admin,
            "UNKNOWN": self.unknown,
        }


@dataclass
class AWSPolicyPermissionAnalysis:
    """`normalize_policy_statements()` 결과 전체에 대한 권한 집계 결과."""

    counts: AWSPolicyPermissionCounts = field(default_factory=AWSPolicyPermissionCounts)
    #: 집계에 반영된 Allow Statement 개수(Action 개수가 아니라 Statement 개수).
    allow_statement_count: int = 0
    #: Deny Statement 개수 — 아직 실제 상쇄 계산에는 쓰이지 않는다.
    deny_statement_count: int = 0
    #: Deny Statement 원문(정규화된 형태)을 그대로 보존한다 — 다음 단계에서
    #: 실제 권한 상쇄 계산을 할 때 다시 계산하지 않고 여기서 가져다 쓸 수 있게.
    deny_statements: List[Dict[str, Any]] = field(default_factory=list)
    #: Allow Statement 에 나열된 Action 문자열(중복 제거, 첫 등장 순서 유지).
    #: `map_action()` 이 알아보지 못한(UNKNOWN) Action 도 포함한다 — 이 목록은
    #: "무엇이 허용됐다고 선언돼 있는가" 를 그대로 보존하는 목적이라, 해석
    #: 가능 여부와 무관하게 실제 부여된 Action 을 전부 담아야 한다.
    allowed_actions: List[str] = field(default_factory=list)
    #: Allow Statement 의 Resource 중 전체/서비스 전체급 wildcard(`"*"`,
    #: `"arn:...:*"`)가 하나라도 있으면 True. 정확한 리소스 개수 대신 이
    #: 이진값만 위험 근거로 쓴다 — `graph/blast_radius.py` 참고.
    broad_access: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts.to_dict(),
            "allow_statement_count": self.allow_statement_count,
            "deny_statement_count": self.deny_statement_count,
            "deny_statements": list(self.deny_statements),
            "allowed_actions": list(self.allowed_actions),
            "broad_access": self.broad_access,
        }


def analyze_policy_permissions(
    statements: List[Dict[str, Any]],
) -> AWSPolicyPermissionAnalysis:
    """정규화된 Statement 목록에서 `Effect=Allow` 인 Action 만 집계한다.

    `Effect=Deny` 인 Statement 는 집계에서 제외하고 별도로 보존한다(개수 +
    원문). `Effect` 가 "Allow"/"Deny" 어느 쪽도 아니면(정규화 단계가 값을
    못 채운 경우 등) 어느 쪽에도 포함하지 않는다 — 추측하지 않는다.
    Resource·Condition 은 이 함수가 읽지 않는다.
    """
    counts = AWSPolicyPermissionCounts()
    allow_statement_count = 0
    deny_statements: List[Dict[str, Any]] = []
    allowed_actions: List[str] = []
    seen_actions = set()
    broad_access = False

    for statement in statements or []:
        if not isinstance(statement, dict):
            continue

        effect = statement.get("effect")
        if effect == "Deny":
            deny_statements.append(statement)
            continue
        if effect != "Allow":
            continue

        allow_statement_count += 1
        for action in statement.get("actions") or []:
            if isinstance(action, str) and action not in seen_actions:
                seen_actions.add(action)
                allowed_actions.append(action)

            level = map_action(action)
            if level is PermissionLevel.READ:
                counts.read += 1
            elif level is PermissionLevel.WRITE:
                counts.write += 1
            elif level is PermissionLevel.DELETE:
                counts.delete += 1
            elif level is PermissionLevel.ADMIN:
                counts.admin += 1
            else:
                counts.unknown += 1

        if not broad_access:
            broad_access = any(
                _is_broad_resource(resource) for resource in statement.get("resources") or []
            )

    return AWSPolicyPermissionAnalysis(
        counts=counts,
        allow_statement_count=allow_statement_count,
        deny_statement_count=len(deny_statements),
        deny_statements=deny_statements,
        allowed_actions=allowed_actions,
        broad_access=broad_access,
    )


def _is_broad_resource(resource: Any) -> bool:
    """Resource 값이 전체(또는 서비스 전체)를 가리키는 광범위한 wildcard 인지 판정한다.

    `"*"` 자체이거나 ARN 의 마지막 구간이 통째로 `"*"` 인 경우
    (`"arn:aws:s3:::*"` 처럼 서비스 전체를 가리킴)만 광범위로 본다.
    `"arn:aws:s3:::my-bucket/*"` 처럼 특정 리소스 하나 아래의 wildcard(버킷
    하나 안의 객체 전체 등)는 좁은 범위이므로 포함하지 않는다 — 이 구분이
    없으면 흔한 버킷 단위 정책까지 전부 광범위로 오탐하게 된다.
    """
    if not isinstance(resource, str):
        return False
    value = resource.strip()
    if not value:
        return False
    return value == "*" or value.endswith(":*")
