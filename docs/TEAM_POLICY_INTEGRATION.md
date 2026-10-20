# 팀 논의 결과의 파이프라인 반영

2026-10-21 기준 로컬 구현. 제공 문서의 브랜치·커밋·1,052개 테스트·원격 push 수치는
이 작업의 결과로 사용하지 않았다. 이번 작업의 최종 변경은
`feat/nhi-pipeline-integration` 브랜치로 관리한다.

## Lifecycle

표준 상태는 `REGISTERED → ACTIVE → DEACTIVATED → DECOMMISSIONED`이다.
권한 변경은 별도 상태가 아닌 `PERMISSION_CHANGE` 이벤트로 남긴다.
승인된 권한 변경과 재분석으로 관측한 변경 모두 활성 상태를 유지하며 변경 전후 권한을 기록한다.

`DECOMMISSIONED` 전환에는 파기 증적이 필수다. 변경 승인 API와 내부 Lifecycle 서비스 양쪽에서
검증하며, 수행자와 검증자가 같거나 검증 결과가 유효하지 않으면 전환을 거부한다.
증적·직전 이벤트 ID·SHA-256을 타임라인에, 이벤트 ID·증적 해시를 감사 로그에 남긴다.
저장된 이전 파기 요청도 실행기 호출 전에 증적을 검증한다.

기존 SQLite 인벤토리는 DB를 열 때 다음과 같이 변환한다. 과거 타임라인 원문은 보존하고
조회에서는 표준 상태와 `legacy_stage`를 반환한다. 이전 변경 요청의 전후 스냅샷도 표준 상태로 읽는다.

| 기존 상태 | 표준 상태 |
| --- | --- |
| CREATION | REGISTERED |
| PERMISSION_CHANGE | ACTIVE |
| TERMINATION | DEACTIVATED |
| DISPOSED | DECOMMISSIONED |

기존 폐기 완료 레코드의 증적을 만들어내거나 실제 외부 토큰을 자동 폐기하지는 않는다.
새로운 폐기 완료 전환부터 증적을 강제한다.

## 접근 통제

추가 답변에 따라 `ALERT`를 네 번째 판정으로 채택했다.

| 판정 | enforce | monitor | human_in_the_loop |
| --- | --- | --- | --- |
| ALLOW | 허용 | 허용 | 허용 |
| ALERT | 허용·경고 | 허용·경고 | 허용·경고 |
| REVIEW | 차단 | 허용·관찰 | 승인 대기·차단 |
| DENY | 차단 | 차단 | 차단 |

신원·권한·자원 기준선 불완전은 REVIEW, 미등록 IP·휴면 재사용 단독은 ALERT다.
NHI 질의와 Agent 호출이 같은 운영 모드 정책을 사용한다.
`enforced`는 해당 요청을 실제 차단하거나 승인 대기로 보류했음을 뜻한다.
재시도는 현재 상태와 정책을 다시 확인하며, 과거 승인 허가가 새 DENY를 우회할 수 없다.

호출률은 서버의 `UsageRateTracker`로 측정한다. 최근 1분을 직전 29분 평균과 비교하고,
기준선 호출이 10개 미만이면 급증 여부를 확정하지 않는다.

- 5배 이상 급증 단독: `AGENT_CALL_RATE_SPIKE`, REVIEW.
- 위 급증 + 미등록 출처·휴면 재사용·token/proof 재사용·미승인 Credential·권한/자원 초과 중 하나:
  `AGENT_CALL_RATE_SPIKE_CORRELATED`, DENY.
- 호출자가 보고한 급증: 미검증 `USAGE_SPIKE`, REVIEW. 이 값으로 DENY를 만들지 않는다.

삭제된 논의 항목은 새 요구사항으로 확장하지 않았다. 자동 QUARANTINE은 신규 판정에서 제거했다.
기존 수동 격리 관리 API·저장 이벤트는 호환성을 위해 유지한다.
기존 Agent 승인 허가 기능은 보존했으며, 별도 요청 재실행 워커는 추가하지 않았다.
NHI 단위 REVIEW도 승인 대기 레코드를 남기지만 이 경로의 승인 후 재시도 처리는 추가하지 않았다.

## 검증과 실행 범위

전체 테스트 **405개 통과**. 모드×판정×두 진입점 24개 조합, 증적 검증,
DB 상태 변환의 반복 실행, 호출률과 이상행위 결합, 승인 이후 상태 변경,
재분석에서 권한 변경 이벤트 기록을 검증했다.
기존 Starlette TestClient deprecation warning 1개가 있다.

SQLite 저장 데이터 변환은 자동이다. PostgreSQL DDL도 갱신했으며 기존 서버용 변환 SQL은
`backend/database/migrations/20261021_team_policy.sql`에 제공한다. 실제 PostgreSQL 서버에는 실행하지 않았다.
외부 SaaS 토큰 폐기·교체는 이번 검증에서 실행하지 않았다.

대시보드는 4단계 상태, REVIEW 카운터, monitor의 DENY 차단을 표시한다.
호출률과 거버넌스 잠금은 단일 프로세스 기준이다.
