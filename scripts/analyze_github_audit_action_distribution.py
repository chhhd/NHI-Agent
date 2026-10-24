"""GitHub 조직 Audit Log 샘플의 action 값 분포를 읽기 전용으로 분석한다.

ER 매핑표(행위 -> S1/S2/S3 + 점수)를 팀이 확정하기 전, 실제 조직에서 어떤
`action` 값이 얼마나 나오는지 확인하기 위한 도구다. **실제 GitHub API를 호출하지
않는다** — 사용자가 로컬에 준비한 JSON 샘플 파일만 읽는다.

Git Bash::

    PYTHONUTF8=1 PYTHONPATH=. python scripts/analyze_github_audit_action_distribution.py \\
        --audit-sample path/to/raw_audit_events.json \\
        [--inventory-sample path/to/github_nhi_inventory.json] \\
        [--known-actions path/to/known_github_actions.json]

PowerShell::

    $env:PYTHONUTF8 = '1'; $env:PYTHONPATH = '.'
    python scripts/analyze_github_audit_action_distribution.py `
        --audit-sample path/to/raw_audit_events.json `
        --inventory-sample path/to/github_nhi_inventory.json

    (PowerShell에서도 --xxx 플래그를 그대로 쓴다. 줄바꿈만 백틱(`)을 쓴다. 이 두
    명령은 이번 작업에서 실제로 실행해 동일한 결과를 확인했다.)

입력 파일 형식
--------------
`--audit-sample`: GitHub `/orgs/{org}/audit-log` 응답과 같은 형태의 JSON 배열
    (`GitHubConnector.collect_organization_audit_log()` 가 반환하는
    `GitHubAuditLogResult.events` 원문과 동일한 레코드 리스트).
`--inventory-sample` (선택): `core.inventory_models.GitHubNHIInput` 이 받는
    필드로 구성된 JSON 배열. 생략하면 NHI 매칭 통계는 계산하지 않는다.
`--known-actions` (선택): 사용자가 준비한 action 문자열 참조 목록(JSON 배열
    또는 한 줄에 하나씩). 이 목록과 정확히 일치하는 값만
    `user_provided_reference_match_distribution`으로 분류한다. **이 스크립트는
    그 목록의 출처를 검증하지 않는다** — 목록이 실제로 GitHub 공식 문서에서
    옮겨 적은 것인지, 사용자의 착오나 추측이 섞인 것인지 코드로는 구분할 수
    없다. "GitHub 공식 문서와 대조해 확인됨"이 아니라 "사용자가 제공한 목록과
    문자열이 정확히 일치함"이라는 뜻일 뿐이다.

action 이름 분류 — 마스킹 문제 해결
------------------------------------
이전 버전은 모든 문자열에 `security.redaction.sanitize_security_text()`를
그대로 적용했는데, 그 안의 `redact_unknown_tokens(min_length=20)`이 20자
이상의 영문/숫자/점/밑줄/하이픈 연속을 전부 토큰으로 간주해 가려버려서,
정상적인 긴 GitHub action 이름(예: `protected_branch.policy_override`)까지
마스킹됐다. 이 스크립트는 `security/redaction.py`를 수정하지 않고(전역 동작
불변), 대신 action 필드 전용의 **더 엄격한 형식 검증**을 직접 적용한다.

세 범주로 나눈다:
    1) `user_provided_reference_match_distribution` — `--known-actions` 목록과
       정확히 일치. 원문 그대로 노출. **"GitHub 공식 검증됨"이 아니다** —
       사용자가 제공한 목록과 문자열이 일치했다는 사실만 의미한다. 이 스크립트는
       그 목록이 실제로 GitHub 공식 문서에서 온 것인지 확인하지 않는다(아래
       "민감정보 처리"/`action_name_summary.known_actions_disclaimer` 참고).
    2) `format_valid_action_distribution` — GitHub의 `category.action` 명명
       규칙(소문자/숫자/밑줄 세그먼트를 점으로 연결)과 일치하고, 추가로
       `sanitize_security_text()`를 통과해도 값이 바뀌지 않는 문자열. 원문
       노출. **이 범주는 "형식만 맞다"는 뜻이지 "GitHub 공식 문서에 있다"는
       뜻이 아니다** — `user_provided_reference_match`와 절대 혼동 표시하지 않는다.
    3) `unvalidated_action_distribution` — 위 둘 다 아닌 값. **원문을 출력하지
       않는다.** 서로 다른 미검증 값은 서로 다른 opaque 식별자
       (`UNVALIDATED_ACTION_<n>`)로 집계하며, 이 식별자는 이번 실행에서 처음
       등장한 순서로 부여되는 순차 번호일 뿐 원문을 복원할 수 있는 어떤 정보도
       담지 않는다(해시가 아니다 — 실행마다, 심지어 같은 입력이라도 재실행하면
       같은 숫자가 나온다는 보장도 하지 않는다. 이번 실행 "안에서만" 서로 다른
       값을 구분하는 용도다).

민감정보 처리
--------------
* 원문 감사로그 레코드, actor 식별자, IP, User-Agent, 토큰 등은 **출력에 전혀
  포함하지 않는다.**
* `unvalidated_action_distribution`은 원문을 담지 않는다 — opaque 식별자와
  대략적인 길이 구간(`approx_length_bucket`)만 담는다.
* `--inventory-sample`의 `nhi_name`/`owner` 등은 보고서에 포함하지 않는다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.inventory_models import GitHubNHIInput
from normalization.github_audit import GitHubAuditNormalizer, _audit_timestamp
from security.redaction import (
    _AUTH_SCHEME_RE,
    _KNOWN_SECRET_RE,
    _SENSITIVE_ASSIGNMENT_RE,
    sanitize_security_text,
)

#: GitHub Audit Log 공개 문서가 설명하는 "category.action" 명명 규칙에 대한
#: *형식* 검증 규칙이다. 이 리포지토리가 실제 GitHub 응답으로 검증한 패턴이
#: 아니라, 세그먼트가 소문자 영문자로 시작하고 소문자/숫자/밑줄로 이어지며
#: 점(.)으로 1개 이상 연결된다는 일반 규칙만 본다. 공식 action 이름 목록이
#: 아니므로 이 정규식 통과 여부만으로 "GitHub 공식 문서에 있다"고 표시하지
#: 않는다(아래 officially_confirmed와 분리).
_GITHUB_ACTION_FORMAT_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")

#: 이보다 길면 정규식 평가 없이 바로 미검증으로 처리한다 — 정상적인 GitHub
#: action 이름이 이 길이를 넘는 사례는 알려져 있지 않고, 비정상적으로 긴
#: 입력에 정규식을 돌리지 않기 위한 상식적 상한이다(평가 비용 억제 목적도 겸함).
_MAX_FORMAT_CHECK_LENGTH = 150

#: security.redaction.redact_unknown_tokens()는 20자부터 "장문 토큰"으로 간주한다
#: (security/redaction.py: sanitize_security_text()가 min_length=20으로 호출).
#: 그 아래 길이는 이 전역 길이 휴리스틱이 아예 작동하지 않으므로, 기존
#: sanitize_security_text()를 그대로 적용해도 안전하게 통과시킬 수 있다.
_SAFE_FOR_GLOBAL_SANITIZER_MAX_LENGTH = 19


def _length_bucket(length: int) -> str:
    if length <= 20:
        return "1-20"
    if length <= 50:
        return "21-50"
    if length <= 150:
        return "51-150"
    return ">150"


def _classify_action(value: str) -> str:
    """반환값: "format_valid" 또는 "format_invalid".

    "format_valid"이어도 공식 확인된 것은 아니다 — 호출부가 `known_actions`와
    별도로 대조한다.

    자격증명 모양 이중 방어는 길이에 따라 다른 경로를 쓴다:
        * 20자 미만: `redact_unknown_tokens`(길이 기반 휴리스틱)가 애초에
          작동하지 않는 구간이라, 기존 `sanitize_security_text()`를 그대로
          호출해도 정상적인 짧은 action 이름을 가리지 않는다. 결과가 원문과
          다르면(= 다른 3가지 자격증명 패턴 중 하나에 걸리면) 미검증 처리한다.
        * 20자 이상: `sanitize_security_text()`를 그대로 쓰면 그 안의
          `redact_unknown_tokens(min_length=20)`이 길이만 보고 모든 긴
          action 이름을 가린다(이번에 고치려는 문제 그 자체). 대신 같은
          함수가 내부적으로 쓰는 자격증명 패턴 탐지기 3종
          (`_SENSITIVE_ASSIGNMENT_RE`/`_AUTH_SCHEME_RE`/`_KNOWN_SECRET_RE`)을
          그대로(재구현하지 않고) 재사용해 길이와 무관하게 자격증명 모양만
          따로 검사한다. `security/redaction.py` 자체는 수정하지 않는다.
    """
    if not _GITHUB_ACTION_FORMAT_RE.fullmatch(value):
        return "format_invalid"
    if len(value) <= _SAFE_FOR_GLOBAL_SANITIZER_MAX_LENGTH:
        if sanitize_security_text(value) != value:
            return "format_invalid"
        return "format_valid"
    if (
        _SENSITIVE_ASSIGNMENT_RE.search(value)
        or _AUTH_SCHEME_RE.search(value)
        or _KNOWN_SECRET_RE.search(value)
    ):
        return "format_invalid"
    return "format_valid"


def _action_distribution(
    records: List[Dict[str, Any]], *, known_actions: Optional[Set[str]]
) -> Dict[str, Any]:
    """레코드 전체(매칭 여부 무관) 기준 action 분포를 3개 범주로 나눈다.

    원문은 "user_provided_reference_match"/"format_valid" 범주에서만 노출된다.
    "format_invalid" 값은 opaque 식별자로만 집계되고 원문은 반환값 어디에도
    담기지 않는다.
    """
    known_actions = known_actions or set()
    reference_match: Counter[str] = Counter()
    format_valid: Counter[str] = Counter()
    unvalidated: Counter[str] = Counter()
    unvalidated_length_buckets: Dict[str, str] = {}
    opaque_id_by_value: Dict[str, str] = {}
    next_opaque_index = 1
    no_action_field_count = 0

    for record in records:
        raw_action = record.get("action")
        if raw_action is None or not str(raw_action).strip():
            no_action_field_count += 1
            continue

        value = str(raw_action)
        if len(value) > _MAX_FORMAT_CHECK_LENGTH:
            category = "format_invalid"
        else:
            category = _classify_action(value)

        if category == "format_invalid":
            opaque = opaque_id_by_value.get(value)
            if opaque is None:
                opaque = f"UNVALIDATED_ACTION_{next_opaque_index}"
                opaque_id_by_value[value] = opaque
                next_opaque_index += 1
                unvalidated_length_buckets[opaque] = _length_bucket(len(value))
            unvalidated[opaque] += 1
            continue

        if value in known_actions:
            reference_match[value] += 1
        else:
            format_valid[value] += 1

    return {
        # "GitHub 공식 검증됨"이 아니다 — 사용자가 --known-actions로 제공한 목록과
        # 문자열이 정확히 일치했다는 뜻뿐이다(이 스크립트는 그 목록의 출처를
        # 검증하지 않는다). action_name_summary.known_actions_disclaimer 참고.
        "user_provided_reference_match_distribution": dict(
            sorted(reference_match.items(), key=lambda item: item[1], reverse=True)
        ),
        "format_valid_action_distribution": dict(
            sorted(format_valid.items(), key=lambda item: item[1], reverse=True)
        ),
        "unvalidated_action_distribution": {
            opaque: {"count": count, "approx_length_bucket": unvalidated_length_buckets[opaque]}
            for opaque, count in sorted(unvalidated.items(), key=lambda item: item[1], reverse=True)
        },
        "no_action_field_count": no_action_field_count,
        "action_name_summary": {
            "user_provided_reference_match_distinct_count": len(reference_match),
            "format_valid_distinct_count": len(format_valid),
            "unvalidated_distinct_count": len(unvalidated),
            "known_actions_reference_count": len(known_actions),
            "known_actions_disclaimer": (
                "known_actions_reference_count는 --known-actions로 제공된 목록의 "
                "항목 수일 뿐이다. 이 도구는 그 목록이 실제 GitHub 공식 문서에서 "
                "온 것인지 검증하지 않는다 — user_provided_reference_match_* 값은 "
                "'사용자가 제공한 목록과 문자열이 일치함'을 뜻하지 'GitHub가 공식"
                "확인함'을 뜻하지 않는다."
            ),
        },
    }


def _timestamp_missing_count(records: List[Dict[str, Any]]) -> int:
    missing = 0
    for record in records:
        value = record.get("created_at")
        if value is None:
            value = record.get("@timestamp")
        if _audit_timestamp(value) is None:
            missing += 1
    return missing


def _load_json_array(path: Path, *, label: str) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"{label} 파일을 찾을 수 없습니다: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} 파일이 올바른 JSON이 아닙니다: {exc}")
    if not isinstance(raw, list):
        raise SystemExit(f"{label} 파일은 JSON 배열(list)이어야 합니다.")
    return [item for item in raw if isinstance(item, dict)]


def _load_inventory(path: Optional[Path]) -> Optional[List[GitHubNHIInput]]:
    if path is None:
        return None
    items = _load_json_array(path, label="--inventory-sample")
    identities: List[GitHubNHIInput] = []
    skipped = 0
    for item in items:
        try:
            identities.append(GitHubNHIInput(**item))
        except Exception:
            skipped += 1
    if skipped:
        print(
            f"[경고] --inventory-sample 중 {skipped}건은 GitHubNHIInput 형식이 아니라 건너뜀",
            file=sys.stderr,
        )
    return identities


def _load_known_actions(path: Optional[Path]) -> Optional[Set[str]]:
    """팀이 GitHub 공식 문서에서 직접 옮겨 적은 action 참조 목록만 받는다.

    이 스크립트는 GitHub의 실제 action 이름을 스스로 추정해 등록하지 않는다 —
    이 집합과 정확히 일치하는 값만 "officially_confirmed"로 분류된다.
    """
    if path is None:
        return None
    if not path.exists():
        raise SystemExit(f"--known-actions 파일을 찾을 수 없습니다: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return {str(item).strip() for item in parsed if str(item).strip()}
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def analyze(
    *,
    audit_records: List[Dict[str, Any]],
    identities: Optional[List[GitHubNHIInput]],
    known_actions: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    total = len(audit_records)
    timestamp_missing = _timestamp_missing_count(audit_records)

    report: Dict[str, Any] = {
        "input_summary": {
            "raw_record_count": total,
            "timestamp_missing_count": timestamp_missing,
            "timestamp_missing_ratio": round(timestamp_missing / total, 4) if total else None,
        },
        **_action_distribution(audit_records, known_actions=known_actions),
    }
    if not known_actions:
        report["action_name_summary"]["note"] = (
            "--known-actions 미제공 — user_provided_reference_match_distribution은 "
            "항상 비어 있고 형식 검증(format_valid)만 수행됨"
        )

    if identities is None:
        report["identity_matching"] = {
            "performed": False,
            "note": "--inventory-sample이 주어지지 않아 NHI 매칭을 수행하지 않음",
        }
        report["asset_identifier_coverage"] = {
            "note": "NHI 매칭 없이는 provider가 인정하는 UsageEvent를 만들 수 없어 측정 불가",
        }
        return report

    normalized = GitHubAuditNormalizer().normalize(audit_records, identities=identities)
    matched_distinct_nhi = len({event.principal_id for event in normalized.events})
    missing_asset = sum(
        1 for event in normalized.events if not event.project and not event.resource
    )
    normalized_count = len(normalized.events)

    report["identity_matching"] = {
        "performed": True,
        "matched_event_count": normalized.matched_nhi_event_count,
        "matched_distinct_nhi_count": matched_distinct_nhi,
        "unmatched_actor_event_count": normalized.unmatched_actor_event_count,
        "unmatched_programmatic_event_count": normalized.unmatched_programmatic_event_count,
        "invalid_event_count": normalized.invalid_event_count,
        "inventory_identity_count": len(identities),
    }
    report["asset_identifier_coverage"] = {
        "normalized_event_count": normalized_count,
        "missing_asset_identifier_count": missing_asset,
        "missing_asset_identifier_ratio": (
            round(missing_asset / normalized_count, 4) if normalized_count else None
        ),
    }
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--audit-sample",
        required=True,
        type=Path,
        help="GitHub 조직 Audit Log 원문 레코드 JSON 배열 파일 (로컬 파일만, API 호출 없음)",
    )
    parser.add_argument(
        "--inventory-sample",
        type=Path,
        default=None,
        help="GitHubNHIInput 형식 JSON 배열 파일 (선택 — 없으면 NHI 매칭 통계는 생략)",
    )
    parser.add_argument(
        "--known-actions",
        type=Path,
        default=None,
        help="팀이 GitHub 공식 문서에서 직접 확인한 action 문자열 목록 "
        "(JSON 배열 또는 줄바꿈 구분 텍스트, 선택)",
    )
    args = parser.parse_args(argv)

    audit_records = _load_json_array(args.audit_sample, label="--audit-sample")
    identities = _load_inventory(args.inventory_sample)
    known_actions = _load_known_actions(args.known_actions)

    report = analyze(audit_records=audit_records, identities=identities, known_actions=known_actions)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
