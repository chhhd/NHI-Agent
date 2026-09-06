"""AWS Action 문자열 → 공통 권한(Read/Write/Delete/Admin) 변환.

AWS Action 은 `{service}:{ActionName}` 형태이고, AWS 자신이 정한 명명
관례상 `ActionName` 의 동사 접두어가 접근 수준을 드러낸다 — `Get`/`List`/
`Describe` 는 항상 읽기 전용, `Delete`/`Remove`/`Terminate` 는 항상
파괴적이다(AWS Policy Generator·IAM Access Analyzer 같은 AWS 공식 도구도
이 관례에 기반해 동작한다). 이 모듈은 그 명명 관례와, 관례만으로는 부족한
소수의 잘 알려진 Action 만을 규칙으로 삼는다 — 규칙에 없거나 동사를
알아볼 수 없는 Action 은 추측하지 않고 `None`("UNKNOWN")으로 남긴다.

IAM(신원·접근 관리) 서비스는 예외적으로 취급한다. IAM 상태를 바꾸는 행위는
단순한 "쓰기"가 아니라 "누가 무엇에 접근할 수 있는지 자체를 바꾸는 행위"라
`ADMIN` 으로 분류한다 — `agents/scope_translation_agent.py` 의 GitHub 테이블이
`members:write`/`secrets:write` 를 ADMIN 으로 보는 것과 같은 원칙이다.

Deny/Resource/Condition 해석, 위험도 계산은 다루지 않는다 — Effect 가
Allow 든 Deny 든 이 모듈은 "그 Action 이 허용하는 접근 수준"만 판단한다.
그 값을 실제로 적용할지(Deny 라면 무시해야 한다)는 상위 계층의 몫이다.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.nhi_models import PermissionLevel

R, W, D, A = (
    PermissionLevel.READ,
    PermissionLevel.WRITE,
    PermissionLevel.DELETE,
    PermissionLevel.ADMIN,
)

#: 정확히 일치하는 Action 문자열에 대한 명시적 매핑 — 동사 규칙보다 항상 먼저 확인한다.
#: `s3:*`/`iam:CreateUser` 처럼 규칙만으로도 같은 결과가 나오는 것들도, 예시로
#: 요구된 값이라 규칙 변경에 흔들리지 않도록 명시적으로 고정해 둔다.
_EXACT_ACTION_TABLE: Dict[str, PermissionLevel] = {
    "s3:GetObject": R,
    "s3:PutObject": W,
    "s3:DeleteObject": D,
    "iam:CreateUser": A,
    # 다른 역할의 권한을 넘겨받을 수 있어("Pass" 는 동사 규칙에 없음) 그
    # 자체로 관리자급 위험이다 — AWS 권한 상승 경로로 잘 알려져 있다.
    "iam:PassRole": A,
}

#: IAM 서비스 전용 동사 규칙.
_IAM_READ_PREFIXES = ("Get", "List", "Describe")
_IAM_MUTATING_PREFIXES = (
    "Create",
    "Delete",
    "Put",
    "Update",
    "Attach",
    "Detach",
    "Add",
    "Remove",
    "Tag",
    "Untag",
    "Enable",
    "Disable",
    "Set",
    "Upload",
    "Activate",
    "Deactivate",
)

#: 서비스 무관 일반 동사 규칙(IAM 이외의 서비스에 적용) — AWS 명명 관례 기반.
_GENERIC_READ_PREFIXES = ("Get", "List", "Describe", "Head", "Lookup")
_GENERIC_WRITE_PREFIXES = (
    "Put",
    "Create",
    "Update",
    "Tag",
    "Untag",
    "Enable",
    "Attach",
    "Add",
    "Associate",
    "Copy",
    "Import",
    "Publish",
    "Start",
    "Restore",
    "Modify",
    "Register",
    "Grant",
    "Upload",
    "Invoke",
    "Run",
    "Send",
)
_GENERIC_DELETE_PREFIXES = (
    "Delete",
    "Remove",
    "Terminate",
    "Detach",
    "Disable",
    "Deregister",
    "Revoke",
    "Purge",
    "Destroy",
)


def map_action(action: str) -> Optional[PermissionLevel]:
    """AWS Action 문자열 1개를 공통 권한으로 변환한다.

    모호하거나 알려지지 않은 Action 은 `None` 을 반환한다("UNKNOWN") —
    잘못 추측해서 실제보다 낮거나 높게 평가하지 않는다.
    """
    if not isinstance(action, str):
        return None
    action = action.strip()
    if not action:
        return None

    # 전체 와일드카드("*") 또는 서비스 전체 와일드카드("service:*")는 그
    # 서비스(혹은 계정 전체) 안에서 가능한 가장 강한 권한을 의미한다.
    if action == "*" or action.endswith(":*"):
        return A

    exact = _EXACT_ACTION_TABLE.get(action)
    if exact is not None:
        return exact

    if ":" not in action:
        return None
    service, _, action_name = action.partition(":")
    service = service.strip().lower()
    action_name = action_name.strip()
    if not service or not action_name:
        return None

    if service == "iam":
        if action_name.startswith(_IAM_READ_PREFIXES):
            return R
        if action_name.startswith(_IAM_MUTATING_PREFIXES):
            return A
        return None

    if action_name.startswith(_GENERIC_DELETE_PREFIXES):
        return D
    if action_name.startswith(_GENERIC_WRITE_PREFIXES):
        return W
    if action_name.startswith(_GENERIC_READ_PREFIXES):
        return R
    return None


def map_actions(actions: List[str]) -> Dict[str, Optional[PermissionLevel]]:
    """여러 Action 문자열을 한 번에 변환한다.

    각 Action 문자열을 키로, `map_action()` 결과(또는 알 수 없으면 `None`)를
    값으로 담은 dict 를 반환한다. `agents/aws_policy_normalizer.py` 가 만든
    `actions: List[str]` 를 그대로 넣을 수 있다.
    """
    return {action: map_action(action) for action in (actions or [])}
