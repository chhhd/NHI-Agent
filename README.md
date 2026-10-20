# NHI Risk Analysis Agent

`hanium.zip`에서 보완한 기능과 검증 결과는 [압축본 통합 보고서](docs/ARCHIVE_INTEGRATION.md)를 참고하세요.
현재 Lifecycle·접근 통제 기준과 검증 결과는 [팀 정책 반영 내역](docs/TEAM_POLICY_INTEGRATION.md)을 참고하세요.

GitHub·Slack 등에서 사용되는 **NHI(Non-Human Identity)** 의 보안 위험을 자동으로 분석하는
규칙 기반 시스템이다. 저장소에서 Secret 을 탐지하고, 그 자격 증명이 어떤 NHI 에 연결되는지
식별하고, 권한·환경·사용 상태를 근거로 위험 점수와 조치 권고를 만든다. 그리고 분석 결과에
따라 추가 검사를 실행할지 스스로 정하는 Agent 실행 계층을 얹었다.

한 문장으로: **NHI 의 권한·환경·접근 범위·소유자·수명·사용 상태를 분석해 설명 가능한
위험 점수와 조치 권고를 만들고, 결과에 따라 추가 보안 도구를 조건부로 실행하는 시스템.**

---

## 1. 전체 흐름

입력은 두 경로로 들어오고, 채점부터는 완전히 같은 엔진을 쓴다.

```
(A) 저장소 스캔 경로                        (B) NHI 인벤토리 경로
 GitHub Webhook / POST /scans                POST /nhi/inventory/analyze
        ↓                                    POST /agent/nhi/run
 Connector → 파일 목록/내용                          ↓
        ↓                                    GitHubNHIInput
 Scanner (Regex + Entropy)                   (GitHub App / PAT / Actions Credential)
        ↓                                           ↓
 SecretFinding (마스킹·Fingerprint)          inventory_adapter
        ↓                                    (신원·문맥을 선언값으로 확정)
 Discovery Agent → Context Analysis Agent           │
        └───────────────────┬────────────────────────┘
                            ▼
             Scope Translation   서비스별 Scope → READ/WRITE/DELETE/ADMIN
                            ▼
             Blast Radius        연결 서비스·자원·외부 전송·교차 프로젝트
                            ▼
             Policy Engine       정책 8종 위반 판정
                            ▼
             Risk Scoring        100점 만점 7영역 + 강제 Critical 7종
                            ▼
             Decision Engine     자동 조치 / 사람 검토 / 예외 승인
                            ▼
             Recommendation      조치 권고 9종
                            ▼
             NHIAnalysis         요약 9필드 + 판단 근거 전체
```

정책 위반 판정이 위험 점수보다 **먼저** 실행된다("Owner·정책 관리 상태" 배점에 위반 건수가
들어간다). 반대로 조치 결정은 점수가 나온 **뒤에** 한다.

Agent 실행 계층은 이 파이프라인을 하나의 도구로 감싼 다음, 결과를 보고 다음 도구를 고른다.

```
사용자 목표 + NHI 입력 → State 생성 → 초기 계획(ANALYZE_NHI)
   → NHI 분석 실행 → 결과 관찰 → 조건부 재계획
   → (위험 등급 HIGH 이상 + 허용 시) SCAN_SECRETS
   → (허용 시) EVALUATE_POLICY → COMPLETE
```

---

## 2. 디렉터리

```
core/
├─ config.py             환경 설정 (.env)
├─ models.py             SecretFinding / ScanResult / CredentialStatus  ← 탐지 계층 스키마
├─ nhi_models.py         NHIProfile / ContextInsight / PermissionProfile / RiskAssessment /
│                        PolicyEvaluation / BlastRadiusReport / NHIAnalysis / AnalysisSignals
└─ inventory_models.py   GitHubNHIInput / RepositoryInfo  ← 인벤토리 입력 스키마 (Pydantic)

connectors/              외부 서비스 연동 (HTTP 재시도·Rate Limit·인증 예외 공통 처리)
├─ base_connector.py     공통 기반
├─ github_connector.py   Repo 등록/조회, 브랜치·파일 목록, Commit/PR 변경 파일
├─ github_webhook.py     HMAC 서명 검증, push/PR 이벤트 파싱, 자동 검사 트리거
├─ slack_connector.py    Workspace/Bot/App 정보, Scope, 토큰 유효성·폐기 확인
└─ gitlab_ / notion_ / huggingface_connector.py

scanner/
├─ pattern_registry.py   Secret 패턴 정의 (유형 분류의 단일 진실 공급원)
├─ regex_scanner.py      Regex 탐지 + 파일 유형 필터 + 오탐 억제
├─ entropy_scanner.py    Shannon Entropy 기반 무작위 문자열 탐지
├─ masking.py            Secret 원문 마스킹
├─ fingerprint.py        SHA-256 Fingerprint (중복/재발 판정 키)
└─ scan_service.py       탐지 파이프라인 오케스트레이션

agents/                  NHI 분석 Agent
├─ discovery_agent.py          Credential → NHI 식별 (유형·Bot·AI Agent·Owner)
├─ context_analysis_agent.py   경로/변수명/주변 코드 → 환경·민감도·사용 여부
├─ scope_translation_agent.py  서비스별 Scope → Read/Write/Delete/Admin
├─ risk_scoring_agent.py       100점 위험 점수 (policy/scoring 위임)
├─ policy_evidence_agent.py    정책 위반 판정 + 판단 근거(Evidence) 수집
├─ recommendation_agent.py     조치 권고 9종 생성
├─ inventory_adapter.py        GitHubNHIInput → 분석 입력 변환 (인벤토리 경로)
├─ pipeline.py                 두 입력 경로를 하나로 묶는 단일 분석 엔진
└─ heuristics.py               경로·변수명·주석 신호 추출 공용 유틸

policy/
├─ rules.py              정책 8종 + 강제 Critical 8종 + EvaluationContext + PolicyConfig
├─ scoring.py            평가 영역 7개 배점 및 등급 산정
└─ decision_engine.py    자동 조치 / 사람 검토 / 예외 승인 판단

graph/
├─ relationship_graph.py AI Agent → NHI → Credential → Permission → Service → Resource
└─ blast_radius.py       영향 범위 계산 및 합산

agent_runtime/           Agent 실행 계층
├─ models.py             AgentAction / AgentStatus / NHIAgentRequest / NHIAgentState
├─ planner.py            초기 계획 (기본 분석 1단계)
├─ tools.py              AgentTool 인터페이스 + 실제 도구 3종 + Registry
├─ replanner.py          분석 결과 관찰 후 조건부 도구 추가
└─ orchestrator.py       계획 실행 / 상태 관리 / 오류 기록

rescan/
├─ credential_verifier.py 탐지된 토큰의 외부 API 재검증 (읽기 전용 호출만)
└─ revalidator.py         재스캔 + 해결/미해결/재발/신규 판정

storage/
├─ base.py               저장소 인터페이스 (Storage) — DB 교체 시 이 계약만 맞추면 된다
└─ sqlite_store.py       SQLite 구현 (기본)

api/app.py               FastAPI 단일 진입점 (Webhook 수신 포함)
tests/                   단위·통합 테스트 159개 (네트워크·DB 파일 없음)
```

---

## 3. 설치 및 실행

```bash
pip install -r requirements.txt
cp .env.example .env          # 토큰/시크릿 입력
uvicorn api.app:app --reload --port 8000
pytest                        # 외부 네트워크·실제 .env 토큰·프로젝트 DB 없이 실행된다 (tests/conftest.py)
```

### 운영 데이터 파이프라인과 암호화 Secret material

스캔·인벤토리 입력은 공통 `CredentialObservation` 으로 정규화되고, NHI 관계와
분석 스냅샷(점수/정책 버전 포함), 추천 조치 `ActionRequest` 가 SQLite 에 저장된다.
원문 Secret 은 기존처럼 일반 finding JSON 에 저장하지 않는다.

검증·폐기 같은 후속 작업을 위해 원문을 잠시 보관해야 할 때만 AES-256-GCM 분리
저장소를 사용할 수 있다. 로컬 개발 키는 다음처럼 생성해 `.env` 에 넣는다.

```bash
python -c "from security.secret_store import AESGCMSecretMaterialStore as S; print(S.generate_key())"
```

```dotenv
NHI_MASTER_KEY=<위 명령의 출력>
NHI_MASTER_KEY_ID=local-v1
NHI_SECRET_TTL_SECONDS=3600
NHI_ADMIN_API_KEY=<충분히 긴 관리자 API 키>
```

운영 환경에서는 로컬 master key 대신 KMS/Vault 기반 구현으로 교체하는 것을
권장한다. `persist_secret_material=true` 스캔, 저장된 Credential 재검증, 조치
승인·취소 API 는 `X-NHI-Admin-Key` 헤더가 필요하며, 관리자 키가 설정되지 않으면
비활성화된다.

추가된 주요 API:

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/analyses` | 버전이 포함된 분석 스냅샷 이력 |
| GET | `/actions` · `/actions/{action_id}` | 추천에서 생성된 조치 요청 |
| POST | `/actions/{action_id}/approve` · `/cancel` | 관리자 승인·취소 |
| POST | `/credentials/verify` | 암호화 참조를 이용한 읽기 전용 재검증 |

### Backend 운영 API와 Dashboard

FastAPI 서버가 별도 빌드 없이 운영 Dashboard를 함께 제공한다.

- Dashboard: <http://127.0.0.1:8000/dashboard/>
- Executive KPI: `GET /dashboard/summary`
- Project Coverage: `POST/GET /projects`, `POST /projects/{id}/scan`
- Connector: `POST /connectors/github`, `POST /connectors/slack`,
  `GET /connectors/status`
- Finding Lifecycle: `GET /findings`, `GET /findings/{id}`,
  `PATCH /findings/{id}/status`, `POST /findings/{id}/rescan`
- NHI Inventory: `GET /nhi`, `GET /nhi/{id}`
- Relationship Graph: `GET /graph`
- Review Queue: `POST /reviews/{id}/approve`, `POST /reviews/{id}/reject`
- Audit/Report: `GET /audit`, `GET /reports/summary?format=markdown`

검사할 GitHub 저장소가 없어도 Dashboard 상단의 **데모 데이터 생성** 버튼으로
전체 흐름을 확인할 수 있다. 이 기능은 실제 Secret이나 외부 API 호출 없이 합성
Project, Finding, NHI, 관계 그래프, Review Queue를 생성한다.

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/demo/workspace` | 안전한 합성 workspace 생성 또는 새로고침 |
| DELETE | `/demo/workspace` | 합성 데이터만 삭제하고 사용자 데이터는 유지 |
| POST | `/demo/reviews/{id}/approve` · `/reject` | 합성 조치 승인·거부 체험 |

합성 레코드는 `nhi-sentinel-demo-v1` 표식으로 격리되며 원문 Credential을 저장하지
않는다. 데모 Project의 `Refresh demo`는 GitHub를 호출하지 않고 동일한 안전한
시나리오를 다시 생성한다.

Finding 운영 상태는 Scanner의 단기 재스캔 상태와 분리되어 다음 lifecycle을
따른다.

```text
NEW → TRIAGED → ASSIGNED → REMEDIATION_IN_PROGRESS
    → CREDENTIAL_REVOKED → RESCAN_PENDING → RESOLVED
```

`REOPENED`, `RECURRENCE`, `FALSE_POSITIVE`, `EXCEPTION`, `NEEDS_REVIEW`,
`SLA_OVERDUE`, `ACCEPTED_RISK`도 지원하며 허용되지 않은 전이는 HTTP 409로
거부한다.

### NHI 거버넌스: 실시간 통제 · 변경 승인 · 생명주기

탐지·분석에서 끝나지 않고, NHI를 **통제하고(실시간), 안전하게 바꾸고(승인·롤백), 끝까지 추적하는(생명주기)** 세 축이다.
세 축은 `nhi_identities` 레코드 하나를 공유한다 (`backend/services/`).

#### 1. 실시간 통제 (`control_service.py`)

사용 이벤트를 받아 **ALLOW / ALERT / REVIEW / DENY**로 판정한다. 판정과 실제 허용 여부는 별도 필드로 반환한다.

| 판정 | enforce | monitor | human_in_the_loop |
| --- | --- | --- | --- |
| ALLOW | 허용 | 허용 | 허용 |
| ALERT | 허용·경고 | 허용·경고 | 허용·경고 |
| REVIEW | 차단 | 허용·관찰 | 승인 대기·차단 |
| DENY | 차단 | 차단 | 차단 |

| 규칙 ID | 조건 | 판정 |
| --- | --- | --- |
| `NHI_LIFECYCLE_ENDED` (R1) | 종료·폐기된 Credential 사용 (탈취 신호) | DENY |
| `NHI_QUARANTINED` (R2) | 격리 중인 NHI 사용 | DENY |
| `PERMISSION_SCOPE_EXCEEDED` (R3) | 승인 범위를 넘는 권한 요청 | DENY |
| `AGENT_CALL_RATE_SPIKE` | 서버 측정 호출률이 기준선의 5배 이상 | REVIEW |
| `AGENT_CALL_RATE_SPIKE_CORRELATED` | 서버 측정 급증 + 미등록 출처·휴면 재사용·권한 초과 등 독립 이상행위 | DENY |
| `USAGE_SPIKE` (R4) | 호출자 보고 사용량 급증(미검증) | REVIEW |
| `UNREGISTERED_SOURCE` (R5) | 등록되지 않은 출처 (IP 는 인증 근거가 아니므로 차단하지 않음) | ALERT |
| `CREDENTIAL_EXPOSED` (R6) | 활성 Credential 외부 노출 | 위험 요청 DENY + 폐기 승인 요청; 비운영 읽기 전용은 ALERT |
| `DORMANT_CREDENTIAL_REACTIVATED` (R7) | 90일 이상 휴면 Credential 재사용 | ALERT |

규칙은 `backend/services/agent_access_evaluator.py` 의 **하나의 카탈로그**(`GET /agent-access/rules`)에 있고,
NHI 단위 질의(`/control/authorize`)와 Agent 호출(`/control/agent-calls`)이 같은 평가기를 호출한다.
괄호의 R번호는 이전 문서·로그와의 대응용이다. 신규 접근 판정은 자동 격리를 생성하지 않는다.
기존 격리 데이터·수동 관리 API는 호환성을 위해 유지한다. `monitor`도 DENY 요청은 차단한다.

`POST /control/authorize` (게이트웨이용 동기 인가 질의) · `POST /control/events` · `GET /control/events?after_seq=`
· `GET /control/status` · `POST /control/nhi/{id}/quarantine|release`

#### 2. 변경 승인 — 영향도 미리보기 · 중요도별 승인 · 롤백 (`change_control_service.py`)

Token **폐기 / 교체 / 권한 변경 / 파기**는 적용 전에 변경 전·후 형상과 영향을 보여 주고, 관리자가 승인한 뒤에만 적용한다.

- 미리보기: permissions·scopes·실효 접근·Credential 상태·생명주기 단계·버전의 전/후 diff, 영향 범위(서비스·리소스·AI Agent),
  서비스 연속성 위험과 완화 방안, 보안 효과, 롤백 계획 (`POST /changes/preview`, 저장하지 않음)
- 권한 중요도 → 승인 등급: **LOW** 자동 승인 / **MEDIUM** 관리자 승인 / **HIGH** 요청자와 다른 관리자(직무 분리) /
  **CRITICAL** 직무 분리 + 영향도 확인(`acknowledge_impact`). 권한 상향 변경은 한 등급 올려 심사한다.
- 롤백: 적용 후 변경 전 형상으로 복원. 이후 다른 변경이 있으면 덮어쓰지 않도록 409 로 거부하고, 제안 이후 대상 상태가
  달라졌다면 승인도 거부한다. 교체는 유예 시간 안에서만, **파기는 롤백 불가**(승인 화면에 명시).

`POST /changes` · `GET /changes` · `POST /changes/{id}/approve|reject|rollback`

> 기본 실행기(`InventoryStateExecutor`)는 NHI 인벤토리 상태만 바꾸고 **외부 Provider(GitHub/Slack)를 호출하지 않는다.**
> 실제 Token 폐기·교체는 `ChangeExecutor` 공급자 어댑터를 연결해야 일어난다.
> 개인 관리자 키 사용 시 서버가 승인자 신원을 확정한다.

#### 3. 생명주기 — DAS (`lifecycle_service.py`)

```
REGISTERED → ACTIVE → DEACTIVATED → DECOMMISSIONED
```

- 모든 전이는 검증되고 타임라인과 감사 로그에 남는다. 수동 활성화는 `REGISTERED→ACTIVE`(Owner 필수)이다.
- 권한 변경은 활성 상태를 유지하고 `PERMISSION_CHANGE` 이벤트로 기록한다. 재분석에서 관측한 변경도 기록한다.
- `DECOMMISSIONED` 전환은 수행자와 다른 검증자·방법·검증 결과가 담긴 파기 증적이 필수다. 증적 해시를 타임라인에 남긴다.
- Owner 지정·신원 확정 NHI는 사용 단계로 자동 진입하고, 아니면 등록 단계에 머문다.
- 노후화 신호: 미사용(90일) · 교체 지연(90일) · 만료 임박/경과 · Owner 없음 · 등록 정체 ·
  **종료 후 보존 기간(30일) 경과 → 파기 필요** · 격리 중. 기준은 `NHI_*_DAYS` 로 조정한다.
- 파기는 암호화된 Secret material 까지 제거하고, 파기·종료된 NHI의 Credential이 다시 탐지되면 잔존 사용처 신호로 기록한다.
- 재분석(`persist_analysis`)이 생명주기·통제 상태를 초기화하지 않도록 보존한다. (권한은 재분석의 관측값이 우선)

`GET /lifecycle` · `GET /lifecycle/{id}` · `POST /lifecycle/{id}/advance`

Dashboard에는 **Lifecycle / Change Control / Live Control** 화면이 있다. 데모 데이터에는 4단계 NHI, 승인 대기 변경,
롤백 가능한 적용 건과 통제 이벤트가 포함되며, 관리자 키 없이 체험할 수 있다 (합성 NHI 한정).
민감 API(제안·승인·통제 이벤트)는 실제 NHI에 대해 `X-NHI-Admin-Key` 가 필요하다.

#### 4. Agent 접근 기준선 · 위장 호출 판정 (`agent_access_evaluator.py`)

위 실시간 통제는 NHI 단위라 "누가 호출했는가"를 보지 못한다. 이 경로는 업무 주체(AI Agent)와
인증 주체(NHI/Credential)를 분리해, 주장 Agent·인증 Agent·Credential fingerprint·권한·자원을
회사가 승인한 기준선(`AgentAccessProfile`)과 비교한다.

`PUT /agent-access/profiles/{agent_id}` (기준선 등록, 관리자 키) · `GET /agent-access/profiles[/{id}[/scope]]`
· `GET /agent-access/rules` · `POST /control/agent-calls` (Gateway 동기 질의)

기존 규칙과의 대응:

| 기존 | 평가기 규칙 | 판정 |
| --- | --- | --- |
| R1 종료·폐기 Credential 사용 | `NHI_LIFECYCLE_ENDED` | DENY |
| R2 격리 중 사용 | `NHI_QUARANTINED` | DENY |
| R3 승인 권한 초과 | `PERMISSION_SCOPE_EXCEEDED` | DENY |
| R5 미등록 출처 | `UNREGISTERED_SOURCE` | ALERT (IP 는 인증 근거가 아니므로 차단하지 않음) |
| R7 휴면 재사용 | `DORMANT_CREDENTIAL_REACTIVATED` | ALERT |
| R4 사용량 급증 · R6 노출 | `USAGE_SPIKE` · `CREDENTIAL_EXPOSED` (`POST /control/events`) | REVIEW / 위험 요청 DENY |
| (신규) | `CLAIMED_IDENTITY_MISMATCH`, `UNREGISTERED_AGENT`, `UNAPPROVED_NHI`, `UNAPPROVED_CREDENTIAL`, `RESOURCE_SCOPE_EXCEEDED` 등 | DENY |

기준선·관측이 불완전하면(`*_inventory_complete=false`) 공격으로 확정하지 않고 `*_BASELINE_INCOMPLETE`
(REVIEW)로 남긴다. 같은 요청의 재전송도 현재 상태와 운영 모드를 재평가한다.
**승인 보류 · 1회용 허가** (`NHI_CONTROL_MODE=human_in_the_loop`)

`POST /control/agent-calls` 는 `directive` 로 `PASS · ALERT_ONLY · REQUIRE_APPROVAL · BLOCK` 을 돌려준다.
확정 불가(REVIEW)인 호출은 `enforce`에서는 차단하고 `monitor`에서 허용·관찰하며 `human_in_the_loop`에서 보류한다.

1. 보류: `approval.status=PENDING` (결정 없이 `NHI_CONTROL_APPROVAL_TTL_SECONDS`=900초가 지나면 `EXPIRED`)
2. 관리자 `POST /control/approvals/{decision_id}/approve` → 1회용 `grant` 를 **응답에서 한 번만** 반환
   (저장소에는 SHA-256 digest 만 남는다). `GET /control/approvals` 로 목록, `/reject` 로 거부.
3. Gateway 가 같은 요청을 `X-NHI-Approval-Grant: <grant>` 와 함께 재시도 → `PASS`.
   허가는 Agent·인증 Agent·provider·NHI·Credential·행위·권한·자원에 묶이고 `compare_and_set` 으로
   한 번만 쓰인다. 허가 유효 시간 `NHI_CONTROL_GRANT_TTL_SECONDS`=300초.

확정된 위반(DENY)은 보류하지 않고 즉시 `BLOCK` 한다. Credential 탈취·위장이 의심되는 차단
(`CLAIMED_IDENTITY_MISMATCH`, `UNAPPROVED_CREDENTIAL`, `TOKEN_REPLAY_SUSPECTED`, `SENDER_PROOF_INVALID`)은
`TOKEN_ROTATE` 승인 요청을 자동 제안한다. 차단만으로는 탈취된 Credential 이 계속 유효하기 때문이며,
실행은 사람의 승인 이후다.

**기존 규칙 보정**
- R5: IP 만으로는 차단하지 않는다(관리자급이면 심각도만 HIGH). IP 는 NAT·프록시·위조로 인증 근거가 될 수 없다.
- R3: NHI 의 승인 권한 목록이 비어 있으면 "초과"로 단정하지 않고 `PERMISSION_BASELINE_INCOMPLETE`(REVIEW).
- R4: `/control/agent-calls` 는 호출자가 보고한 수치가 아니라 **서버가 측정한** 호출률을 쓴다
  (최근 1분 vs 직전 29분 평균, 기준선 호출 10회 미만이면 판정하지 않음). `/control/events` 의 수치는
  호출자 보고값이라고 메시지에 표시한다.

**한계**: 호출률 측정과 `GOVERNANCE_LOCK` 은 단일 프로세스 메모리 기준이다(다중 워커 시 공유 저장소 필요).
승인자 신원은 개인 관리자 키로 확정한다(아래 "승인자 신원 · 역할").

#### 승인자 신원 · 역할 (`security/admin_identity.py`)

공유 관리자 키 하나와 본문 `actor` 문자열만으로는 "요청자와 다른 관리자만 승인" 같은 직무 분리가
이름만 바꿔 쓰면 우회된다. 관리자별 개인 키로 신원을 확정하고 역할로 승인 권한을 제한한다.

| 구분 | 내용 |
| --- | --- |
| 개인 키 | `nhik.<admin_id>.<secret>`. 서버가 생성해 **한 번만** 보여 주고 SHA-256 digest 만 저장. 회전·비활성 가능 |
| 역할 | `ADMIN`: 일반 승인·거부·롤백·격리 해제 / `SECURITY`: 추가로 **CRITICAL 변경 승인** |
| actor | 개인 키를 쓰면 `actor` 는 키의 관리자 ID. 본문에 다른 이름을 적으면 403, 생략하면 키의 ID |
| bootstrap | 기존 `NHI_ADMIN_API_KEY` 는 관리자 계정 관리 전용(break-glass). 개인 계정이 하나라도 있으면 승인 등 actor 가 필요한 작업에는 쓸 수 없다 |
| 기록 | `ChangeRequest.requested_by_verified` · `approved_by_verified`, 실시간 보류 `decided_by_verified`, 감사 로그 `actor_verified` |

```bash
# 1) 공유 키로 관리자 계정 생성 (api_key 는 이 응답에서만 볼 수 있다)
curl -X POST localhost:8000/admin/principals -H "X-NHI-Admin-Key: $NHI_ADMIN_API_KEY" \
  -H "Content-Type: application/json" -d '{"admin_id":"alice","roles":["ADMIN"]}'
curl -X POST localhost:8000/admin/principals -H "X-NHI-Admin-Key: $NHI_ADMIN_API_KEY" \
  -H "Content-Type: application/json" -d '{"admin_id":"sam","roles":["SECURITY"]}'
# 2) 이후 승인은 개인 키로 (actor 생략 가능)
curl -X POST localhost:8000/changes/<id>/approve -H "X-NHI-Admin-Key: nhik.sam.<secret>" \
  -H "Content-Type: application/json" -d '{"acknowledge_impact":true,"reason":"확인"}'
```

`GET /admin/whoami` · `GET/POST /admin/principals` · `POST /admin/principals/{id}/rotate-key|disable|enable`
(관리 API 는 공유 키 전용 — 계정이 스스로 권한을 올릴 수 없다).
합성 데모 NHI 는 이전처럼 키 없이 체험할 수 있다(`via=demo`, `verified=false`).

**한계**: 개인 키는 IdP 가 아니라 자체 발급 비밀이다(분실·유출 시 회전). 모든 계정을 비활성화하면 공유 키 방식으로
되돌아가므로, 되돌림을 막으려면 `NHI_REQUIRE_VERIFIED_ADMIN=true` 를 설정한다. CRITICAL 변경의 **2인 승인**
(OWNER+SECURITY)과 IdP(OIDC) 연동은 아직 없다 — `AdminDirectory.authenticate` 만 교체하면 된다.

#### 5. 사용 분석 → 보안 이벤트 → 시나리오 (`usage_analysis_agent.py`)

감사 로그를 공통 `UsageEvent` 로 정규화하고(`POST /nhi/usage/normalize`, 또는 `/nhi/inventory/analyze` 의
`usage_events`·`usage_data_complete`), 승인 권한과 관측 행위를 비교해 `security_events` 를 만든다.
`scenario_matches` 는 강제 Critical 규칙과 같은 판정에서 나오므로 `risk_detail.forced_rules` 와 어긋나지 않는다.

- 로그가 없거나 불완전하면 "이상 없음"으로 보지 않는다. `unused_permissions` 는 승인 기준과 사용 이력이
  **모두 완전할 때만** 계산하고, 파싱 실패가 한 건이라도 있으면 `data_complete=true` 요청도 `false` 로 낮춘다.
- 중복 이벤트는 제거하고, 다른 principal 의 이벤트는 무시하며, 로그 안의 토큰 형태 문자열은 저장 전에 지운다.
- 이 프로젝트 고유 규칙(`IAM_PRIVILEGE_SELF_ESCALATION`, `BROAD_OAUTH_SCOPE`, `EXCESSIVE_DATA_EXPOSURE`)은
  유지되며 시나리오에도 매핑된다. `TOKEN_REPLAY_SUSPECTED` 강제 Critical 규칙이 추가됐다(총 8종).
- 한계: 인벤토리 경로는 `credential_revoked` 를 알 수 없어 시각 순서만으로 "폐기 후 사용"을 추론하지 않는다
  (`token_used_after_revocation` 명시 신호 또는 스캔 경로에서만 판정).

#### 보안 위생 점검

```bash
python scripts/check_security.py     # HIGH 가 있으면 종료 코드 1, 값은 출력하지 않는다
```

약한 `NHI_ADMIN_API_KEY`(32자 미만), 비어 있는 `FINGERPRINT_SALT`, 클라우드 동기화 폴더 안의 프로젝트,
프로젝트 근처의 개인키(`*.pem`), `.gitignore` 누락, 공유 시 빠뜨려야 할 `*.db` 를 보고한다.
키 생성 예: `python -c "import secrets; print(secrets.token_urlsafe(48))"`

#### 6. SaaS · 조직 Discovery와 이력 (읽기 전용)

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/integrations/github/discover` | 조직 GitHub App installation 을 페이지 순회로 수집 → 전건 분석 → 실행 요약 감사 (`GITHUB_INVENTORY_TOKEN` 전용) |
| POST | `/integrations/microsoft/discover` | Entra service principal · Owner · delegated grant · app role |
| POST | `/integrations/google/discover` | Admin Reports OAuth 이벤트를 Client ID 별로 집계 |
| POST | `/nhi/inventory/saas/analyze` | 이미 수집한 공급자 중립 SaaS NHI 1건 분석 |
| GET | `/nhi/{nhi_id}/history` · `/history/compare` | 분석 스냅샷 이력, 직전(또는 지정) 대비 위험·정책·권한·시나리오·권고 변화 |

- Discovery 는 모두 `X-NHI-Admin-Key` 가 필요하고 Credential 값은 응답·DB 에 저장하지 않는다.
- **수집 한계를 숨기지 않는다.** 페이지 상한·권한 부족·파싱 실패는 `inventory_complete=false` / `retrieval_truncated`
  로 남고, 개별 저장소 이름을 알 수 없으면 0개가 아니라 `UNKNOWN` 으로 취급한다(Google 은 감사 로그 보존
  기간 안의 관측분이라 전체 현재 토큰 목록으로 단정하지 않는다).
- 이력 비교는 재채점 없이 **저장 당시 결과끼리** 비교한다. `nhi_id` 는 `GET /nhi` 의 정규화된 ID
  (예: `github:app-1`)를 쓴다.
- Slack 검증(`/integrations/slack/verify`·`/channels`)은 이제 관리자 키가 필요하고, 서버의
  `SLACK_BOT_TOKEN` 만 쓴다. 토큰을 본문·query 로 받으면 access log 에 복제되므로 거부한다.

#### 7. aging 승인 요청과 파기 증적

```bash
curl localhost:8000/lifecycle/aging                      # 대상만 계산 (장기 미사용 · 보존 기간 경과)
curl -X POST localhost:8000/lifecycle/aging/run -H "X-NHI-Admin-Key: nhik.alice.<secret>" \
  -H "Content-Type: application/json" -d '{}'            # 승인 요청 생성 (create_changes=false 면 dry-run)
```

- `STALE_UNUSED`(기본 90일) → **Token 폐기** 요청, `DISPOSAL_DUE`(종료 후 기본 30일) → **Token 파기** 요청.
- **자동으로 종료·파기하지 않는다.** 요청은 `force_approval` 로 만들어 승인 등급이 LOW 여도 사람이 승인해야 하고,
  이미 승인 대기 중이면 중복 생성하지 않는다. 실행은 감사 로그(`AGING_RUN`)에 건수만 남는다.
- **파기는 증적이 있어야만 승인된다** (`destruction_evidence`): 방법 · 수행자(생략 시 승인자) · **수행자와 다른 검증자** ·
  검증 방법 · 결과(`AUTH_REJECTED_401/403` · `NOT_FOUND_404` · `MATERIAL_ABSENT`). 개인 계정 모드에서는 검증자가
  등록된 활성 관리자여야 한다. 증적과 직전 수명주기 이벤트 ID 로 계산한 `evidence_digest` 가
  `TOKEN_DISPOSED` 이벤트에 남아 타임라인 변조를 탐지할 수 있다. 대시보드의 파기 승인 창에 증적 입력란이 있다.
- 한계: 실제 공급자에 대한 인증 시도는 아직 운영자가 수행하고 결과를 기록하는 방식이다.

#### 8. AI Agent API token 탈취·재사용 방어 연구 (DPoP)

| 방식 | 장점 | 한계 | 적용 |
| --- | --- | --- | --- |
| IP·User-Agent 비교 | 구현이 쉽다 | NAT·프록시에서 변하고 위조 가능 | 보조 증거로만 저장 |
| 짧은 TTL·audience | 탈취 영향 시간 축소 | 유효 시간 안의 재사용 가능 | DPoP 와 함께 적용 |
| [mTLS(RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705.html) | TLS 계층의 강한 바인딩 | PKI·proxy·배포 자동화 필요 | 운영 고보안 후보 |
| [DPoP(RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449.html) | 요청 단위 key 보유 증명 | key 보관·replay 저장소 필요 | **연구 경로로 구현** |
| SPIFFE/SPIRE · Workload Identity | secret 없는 단기 identity | 별도 인프라 | 장기 운영 후보 |

Agent 의 EC P-256 공개키 thumbprint 를 access token 의 `cnf.jkt` 에 바인딩한다. 탈취한 token 만으로는 호출할 수 없고,
token 과 정상 proof 를 함께 복사해도 proof `jti` 단일 사용으로 막힌다.

| 단계 | 검증 | 실패 예 |
| --- | --- | --- |
| 발급 `POST /runtime/tokens/issue` | 관리자 승인 + ES256 proof 의 공개키 보유 증명 | 서명 오류 · 오래된 proof · 재전송 |
| 호출 `GET·POST /runtime/protected` | `Authorization: DPoP` + 요청별 새 `DPoP` proof | Bearer 사용 · token hash 불일치 |
| Sender | token `cnf.jkt` ↔ proof JWK thumbprint | 탈취 token + 공격자 key |
| Replay | `htm` · `htu` · `iat` · `ath` · 단일 사용 `jti` | token 과 proof 동시 복사 |

- **발급자 신원**: 개인 관리자 모드에서는 공유 키로 발급할 수 없고, 발급자 ID 가 감사 로그(`issued_by`)에 남는다.
- **replay 캐시는 저장소 기반**(`StorageReplayCache`): 프로세스 재시작·다중 워커(같은 DB) 사이에서도 proof 재전송을 막고,
  저장 한도 초과 시 fail-closed 한다. 호스트가 여러 대면 `Storage.consume_replay_key` 를 Redis 등으로 구현한다.
- **위험 엔진 연동**: 키 불일치·재전송 거부는 `token_replay_suspected` 신호로 NHI 분석에 입력되어
  `TOKEN_REPLAY_SUSPECTED` 강제 Critical 과 즉시 폐기 권고로 이어진다.
- **Gateway 연동** — `POST /control/agent-calls` 의 `sender_evidence`(`authorization`, `dpop_proof`, 원래 요청의
  `http_method`·`http_url`)를 보내면 서버가 직접 검증해 `authenticated_agent_id`·`sender_proof_valid` 를 채운다.
  호출자가 거짓으로 "인증됨·proof 유효"라고 적어도 덮어쓰며, 실패하면 `SENDER_PROOF_INVALID`(+재전송이면
  `TOKEN_REPLAY_SUSPECTED`)로 차단하고 Credential 교체 승인 요청을 만든다.
  - 주의: Gateway 가 **같은 proof 를 `/runtime/protected` 와 `/control/agent-calls` 양쪽에 보내면** 두 번째가 재전송으로 거부된다.
    둘 중 하나만 검증 지점으로 쓴다.
  - 한계: `sender_evidence` 없이 호출자가 `sender_proof_valid=true` 를 주장하는 기존 방식은 여전히 Gateway 를 신뢰한다.
    Agent 정책에서 `require_sender_constraint=true` 로 두고 Gateway 가 증거를 전달하게 하는 구성을 권장한다.

```bash
python scripts/demo_dpop_replay.py   # 정상 key ALLOW → 탈취 token+공격자 key 차단 → token+proof 복사 차단 (비밀은 출력·저장 안 함)
```

한계: 연구 경로이며 회사 Agent Registry 나 사내 Gateway 연동을 대체하지 않는다. 장기 운영에는 mTLS 또는 SPIFFE/클라우드
Workload Identity, 키의 TPM/HSM/KMS 보관, DPoP nonce 가 필요하다.

### PostgreSQL 운영 스키마

전체 운영 엔티티와 외래키는 `backend/database/postgres_schema.sql`에 정의되어
있다. 로컬 PostgreSQL은 다음 명령으로 기동한다.

```bash
docker compose -f compose.postgres.yml up -d
```

직접 초기화할 경우:

```bash
export DATABASE_URL=postgresql://nhi_agent:change-me@localhost:5432/nhi_agent
python scripts/init_postgres.py
```

현재 FastAPI 기본 저장소는 기존 호환성을 위해 SQLite이고, PostgreSQL 스키마와
초기화 포트가 병행 제공된다. 운영 전환 시 `Storage`의 PostgreSQL 구현을 연결한다.

Swagger 문서: <http://127.0.0.1:8000/docs>

```python
# 저장소 스캔 결과 분석
from agents import NHIAnalysisPipeline
from core.nhi_models import AnalysisSignals

report = NHIAnalysisPipeline().analyze_scan_result(
    scan_result,                                   # ScanResult 또는 to_dict() 결과
    default_signals=AnalysisSignals(repository_public=True),
)
print(report.summary())

# NHI 인벤토리 1건 분석
from core.inventory_models import GitHubNHIInput

analysis = NHIAnalysisPipeline().analyze_github_nhi(GitHubNHIInput(**payload))
print(analysis.to_dict()["risk_score"], analysis.recommended_action.value)

# Agent 실행
from agent_runtime import NHIAgentRequest, run_nhi_agent

state = run_nhi_agent(NHIAgentRequest(nhi=GitHubNHIInput(**payload), allow_secret_scan=True))
print(state.status.value, [a.action_type.value for a in state.plan])
```

### 전 과정 실행 스크립트

서버를 띄우지 않고 GitHub API 연동부터 위험 점수화까지 한 번에 실행해 볼 수 있다.

```bash
python scripts/demo_github_analysis.py --repo psf/requests --max-files 5 --run-agent
```

```
1. GitHub API 연동      repository 메타데이터 / 파일 목록 / 파일 내용 (실제 REST API)
2. Secret 탐지          Regex + Entropy → 마스킹 · Fingerprint · 중복 병합
3. NHI 분석 및 위험 점수화  탐지 건별 점수 구성 · 정책 판정 · 조치 권고 · 영향 범위
4. Agent 실행           초기 계획 → 조건부 재계획 → 도구 실행 → 최종 상태
```

`GITHUB_TOKEN` 이 없으면 공개 저장소에 대해 비인증(시간당 60회)으로 동작하므로
`--max-files` 로 검사 파일 수를 제한한다. 토큰이 있으면 저장소 전체를 검사한다.
`--verify-credentials` 를 주면 탐지된 토큰을 해당 서비스 API 로 재검증한다(읽기 전용, 기본 꺼짐).

---

## 4. 엔드포인트

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/` · `/health` | 서비스 개요 / 상태 |
| POST | `/repositories` | GitHub Repository 등록 |
| GET | `/repositories/{owner}/{repo}/branches` · `/files` | 브랜치·파일 목록 |
| POST | `/scans` | 수동 스캔 (전체 / commit / PR). `analyze_nhi=true` 로 NHI 분석 포함 |
| GET | `/scans/{owner}/{repo}` | 스캔 이력 |
| POST | `/rescans` | 조치 후 재스캔 + 해결/재발 판정 |
| POST | `/findings/{fingerprint}/resolve` | 해결 처리 (이후 재탐지 시 '재발') |
| POST | `/nhi/analyze` | 탐지 결과 → NHI 분석 (findings 직접 전달 또는 저장소 조회) |
| GET | `/nhi/{owner}/{repo}` | 저장된 탐지 결과 기준 분석 |
| GET | `/nhi/{owner}/{repo}/graph` | 관계 그래프 |
| GET | `/nhi/{owner}/{repo}/blast-radius` | 영향 범위 (합산 + NHI 별) |
| **POST** | **`/nhi/inventory/analyze`** | **NHI 정보 직접 입력 → 분석 (스캔 결과 불필요)** |
| POST | `/nhi/scopes/translate` | Scope → 공통 권한 변환 |
| **POST** | **`/agent/nhi/run`** | **Agent 실행 (계획 → 도구 실행 → 재계획)** |
| **POST** | **`/integrations/github/continuous-assessment`** | **GitHub App 인벤토리 + Audit Log 수집 → 사용 분석 → 위험 재평가 → 조치 요청 생성** |
| POST | `/privacy/retention/run` | 보존 기간이 지난 최소화 UsageEvent 즉시 삭제 |
| POST | `/integrations/slack/verify` · GET `/integrations/slack/channels` | Slack Token 검증·채널 |
| POST | `/webhooks/github` | Webhook 수신 → Push/PR 자동 검사 |

### GitHub 지속평가와 개인정보 최소화

`GITHUB_INVENTORY_TOKEN`과 `GITHUB_AUDIT_TOKEN`을 서로 다른 읽기 전용 자격 증명으로
설정한 뒤 다음 API를 호출하면 조직의 GitHub App과 실제 사용 로그를 함께 평가한다.

```bash
curl -X POST http://localhost:8000/integrations/github/continuous-assessment \
  -H "X-NHI-Admin-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"organization":"acme","inventory_limit":100,"audit_limit":1000}'
```

처리 흐름은 `App installation 수집 → Audit Log 수집 → NHI 연결 → UsageEvent 최소화 저장
→ 기존 정책·위험 분석 → ActionRequest 생성`이다. 첫 실행은 최근 24시간부터 시작하고,
이후에는 저장된 checkpoint 기준으로 5분을 겹쳐 증분 수집한다. 중복 이벤트는 event ID로
제거한다. `since`를 명시하면 과거 구간 backfill도 가능하다.

개인정보 보호 원칙:

- GitHub 원본 Audit Log JSON은 DB·응답·감사 이벤트에 저장하지 않는다.
- 알려진 NHI에 연결되지 않은 사람·앱 이벤트는 건수만 집계하고 폐기한다.
- actor login은 저장하지 않고, 이벤트 ID와 IP 네트워크는 별도 키로 HMAC 가명처리한다.
- User-Agent는 `browser`, `github-actions`, `api-client` 같은 제품군만 남긴다.
- 최소화된 UsageEvent도 `NHI_USAGE_EVENT_RETENTION_DAYS` 이후 다음 수집 시 삭제하며,
  운영 Scheduler는 `POST /privacy/retention/run`을 호출해 즉시 물리 삭제할 수 있다.
- 연속 수집 기간이 `NHI_USAGE_MIN_COVERAGE_DAYS`보다 짧거나 수집이 잘렸으면
  “미사용 권한”처럼 로그 부재에 의존하는 판정을 금지한다.
- 재시작 후에도 동일한 가명으로 상관분석하려면 운영 Secret Manager에서
  `NHI_PRIVACY_PSEUDONYMIZATION_KEY`를 주입한다. 미설정 시 프로세스 임시 키를 쓴다.

### GitHub Webhook 설정

Repository → Settings → Webhooks → Add webhook

- Payload URL: `https://<host>/webhooks/github`
- Content type: `application/json`
- Secret: `.env` 의 `GITHUB_WEBHOOK_SECRET` 과 동일한 값
- Events: `Pushes`, `Pull requests`

서명은 `X-Hub-Signature-256` 헤더로 HMAC-SHA256 검증하며, 시크릿이 없으면 요청을 거부한다.
GitHub 은 10초 내 응답을 기대하므로 서명 검증만 동기로 처리하고 스캔은 백그라운드로 넘긴다.

---

## 5. 탐지 계층 (Scanner)

Regex 탐지 → 유형 분류 → 문맥 추출 → 마스킹 → Fingerprint → 중복 병합 순으로 처리하고,
Regex 로 잡히지 않은 고엔트로피 문자열은 Entropy 탐지가 보완한다.

```json
{
  "secret_type": "SLACK_BOT_TOKEN",
  "provider": "slack",
  "masked_value": "xoxb-****-nW7pQ3d",
  "fingerprint": "sha256:9f2c...",
  "file_path": "config/slack.env",
  "line_number": 12,
  "detector": "regex",
  "severity": "critical",
  "entropy": 4.61,
  "context": { "before": ["# slack settings"], "line": "SLACK_BOT_TOKEN=xoxb-****", "after": [] },
  "credential_active": true,
  "credential_revoked": false,
  "raw_scopes": ["chat:write", "channels:history"],
  "credential_detail": { "account": {}, "accessible_resources": [] },
  "occurrence_count": 2,
  "duplicate_locations": [{ "file_path": "b.env", "line_number": 3 }],
  "status": "new"
}
```

**지켜야 할 규칙**

1. **원문은 절대 직렬화하지 않는다.** `SecretFinding._raw_value` 는 프로세스 메모리에서
   외부 API 재검증에만 쓰이고 `to_dict()` 에서 제거된다. 문맥 라인도 마스킹을 거친다.
2. **Fingerprint 는 값 기반**이라 파일이 옮겨져도 동일 Secret 임을 추적할 수 있다.
   `FINGERPRINT_SALT` 를 중간에 바꾸면 과거 결과와 대조가 불가능해진다.
3. **"코드에서 제거됨" ≠ "토큰 폐기됨".** `Revalidator.summarize()` 의
   `removed_from_code_but_still_active` 가 코드만 지우고 토큰을 살려둔 경우를 잡아낸다.
4. **검증 호출은 읽기 전용 메서드만 사용한다** (`auth.test`, `GET /user`).

새 Secret 유형은 `scanner/pattern_registry.py` 에 `SecretPattern` 을 추가하고,
새 SaaS 연동은 `BaseConnector` 를 상속해 `connectors/__init__.py` 의 `CONNECTOR_REGISTRY` 에
등록하면 `CredentialVerifier` 가 자동으로 그 provider 를 검증한다.

---

## 6. 분석 계층

### 6.1 Discovery Agent

| 항목 | 근거 |
| --- | --- |
| Secret 유형 | `scanner/pattern_registry.py` |
| Provider | 탐지 결과 → 없으면 변수명·경로·문맥 키워드 |
| NHI 유형 | `SECRET_TYPE_TO_NHI` 매핑 (GitHub 은 계정 유형으로 App/Machine User 구분) |
| Bot·서비스 계정 | `bot_id`/계정 타입, `bot`·`ci`·`deploy` 등 문맥 키워드 |
| 연결 AI Agent | 외부 신호 → 경로(`services/support_agent/…`) → 변수명 → provider |
| Owner | 외부 신호 → 자격 증명 응답(team/login) → 코드 주석(`# owner: …`) |

Owner 는 **확정 출처에서만** 결정한다. 경로나 Repository 이름에서 유추한 값은
`owner_candidates` 에만 남겨 "Owner 없음" 판정이 흐려지지 않게 했다. NHI 를 특정하지 못하면
`UNKNOWN_NHI` 로 표시하고 자동 조치 대상에서 제외한다.

인벤토리 경로에서는 신원을 이미 알고 있으므로 이 추정을 거치지 않고
`agents/inventory_adapter.py` 가 선언된 값으로 `NHIProfile` 을 직접 만든다.

### 6.2 Context Analysis Agent

경로·변수명·주변 코드에서 운영/스테이징/개발/테스트 환경, 테스트·예제 값 여부, 실제 사용 여부,
데이터 민감도, 분석 신뢰도를 판정한다. 판정 근거는 `path_signals` / `code_signals` / `notes` 에
남아 위험 점수의 근거로 그대로 쓰인다.

인벤토리 경로에서는 환경·민감도를 코드에서 유추하지 않고 선언된 값(환경, 저장소 공개 범위,
민감 저장소 여부)에서 결정한다.

### 6.3 Scope Translation Agent

```
Read / Write / Delete / Admin
```

| 원본 Scope | 공통 권한 | 설명 |
| --- | --- | --- |
| `channels:history` | Read | Slack 채널 메시지 조회 |
| `chat:write` | Write | Slack 메시지 작성 |
| `contents:write` | Write | GitHub Repository 파일 수정 |
| `administration:write` | Admin | 저장소 설정·관리 기능 접근 |
| `secrets:write` | Admin | Actions·환경 Secret 관리 |
| `delete_repo` | Delete | Repository 삭제 |
| `repo` | Admin | Repository 전반 접근 |

변환 우선순위는 **provider 테이블 → 공통 테이블 → 문자열 휴리스틱(`inferred=true`)
→ Secret 유형 기준 보수적 가정(`assumed=true`)** 이다. Scope 를 확인하지 못했을 때 권한을
비워두면 위험이 과소평가되므로, 유형별 최대 권한을 가정하고 그 사실을 플래그로 남긴다.

GitHub 은 OAuth scope(`repo`, `delete_repo`)와 App 권한(`contents:write`) 표기가 섞여
들어오므로 같은 테이블에서 둘 다 처리한다. 인벤토리 입력의
`{"contents": "write"}` 는 `contents:write` 로 정규화된 뒤 같은 표를 탄다.

### 6.4 위험 점수 (100점)

| 평가 영역 | 배점 | 주요 입력 |
| --- | --- | --- |
| 노출 위치 | 20 | (스캔) Repository 공개 여부·중복 노출·하드코딩 / (인벤토리) 접근 가능 저장소 범위·비공개·민감 저장소 |
| API 권한 수준 | 20 | 최고 권한, 권한 조합 폭 |
| 운영 환경 및 데이터 중요도 | 15 | 환경 분류, 데이터 민감도 |
| Credential 상태 | 15 | active/revoked, 만료일·만료 경과, 수명, Rotation |
| 사용 및 이상행위 | 15 | 사용 중 여부, 최근 사용, 폐기 후 사용, 권한 초과 행위 |
| Owner·정책 관리 상태 | 10 | Owner 지정 여부, 정책 위반 건수 |
| 연결 서비스 영향 범위 | 5 | 연결 서비스 수, 교차 프로젝트, 외부 전송 |

```
Critical: 80~100    High: 60~79    Medium: 30~59    Low: 0~29
```

정보가 없는 항목은 **0점이 아니라 중간값**을 준다(예: Repository 공개 여부 미확인 = 11/20).
미검증을 안전으로 오해하지 않기 위한 설계이며, 근거 문구에 "보수적으로 평가"로 남는다.
테스트·예제 값으로 판정되면 노출 위치 점수를 5점으로 눌러 오탐 소음을 줄인다.

두 입력 경로에서 의미가 갈리는 항목은 두 곳뿐이다.

- **노출 위치** — 코드에서 발견된 Secret 은 "어디에 노출됐는가", 인벤토리 NHI 는
  "어디까지 접근할 수 있는가" 가 노출 면적이다.
- **최근 사용** — 노출된 Secret 이 최근까지 쓰였다면 즉시 악용 가능하다는 신호지만,
  인벤토리 NHI 의 최근 사용은 정상 운영 상태이므로 가산하지 않는다.

### 6.5 강제 Critical 규칙

점수와 관계없이 `CRITICAL` 로 승격한다(원래 점수는 `base_score` 에 보존, 점수는 최소 80).

| 규칙 ID | 조건 |
| --- | --- |
| `PUBLIC_REPO_ACTIVE_ADMIN_TOKEN` | 공개 Repository 에 활성 Admin Token |
| `OWNERLESS_SENSITIVE_DATA_ACCESS` | Owner 없는 NHI 가 민감 데이터 접근 |
| `TERMINATED_AGENT_ACTIVE_TOKEN` | 종료된 AI Agent 에 활성 Token |
| `REVOKED_TOKEN_STILL_USED` | 폐기된 Token 이 계속 사용됨 |
| `TOKEN_SHARED_ACROSS_PROJECTS` | 하나의 Token 이 여러 프로젝트에서 공유 |
| `READ_ONLY_NHI_PERFORMS_MUTATION` | 조회 전용 NHI 가 수정·삭제 수행 |

예제·테스트 값이면서 자격 증명이 활성이 아닌 경우에는 평가하지 않는다(오탐 억제).

### 6.6 Policy Engine

| 정책 ID | 내용 | 자동 조치 |
| --- | --- | --- |
| `OWNER_REQUIRED` | Owner 필수 | ✗ (사람이 지정) |
| `TOKEN_MAX_AGE` | 최대 수명 365일 | ○ |
| `ROTATION_PERIOD` | 회전 주기 90일 | ○ |
| `ADMIN_SCOPE_RESTRICTED` | 관리자 Scope 제한 | ○ |
| `PROJECT_TOKEN_ISOLATION` | 프로젝트별 Token 분리 | ○ |
| `NO_PLAINTEXT_CREDENTIAL` | 저장소 평문 자격 증명 금지 | ○ (스캔 경로 전용) |

임계값은 `PolicyConfig` 로 조정한다. 결정 규칙은 다음과 같다.

- **HUMAN_REVIEW** — 강제 Critical, 점수 ≥ 60, 자동 해소 불가 위반, `UNKNOWN_NHI`,
  운영 환경 고위험 자산
- **AUTO_REMEDIATION** — 위 조건에 없고 점수 ≤ 79, NHI 식별됨, 운영 환경 아님
- **EXCEPTION_APPROVED** — 유효한 예외 승인이 있고 Critical 이 아닌 경우
  (예외는 **강제 Critical 을 덮지 못한다**)
- **MONITOR** — 위반 없음

정책을 외부화해야 하면 `POLICIES` / `FORCED_CRITICAL_RULES` 를 OPA(Rego) 또는 Cerbos 로
옮기고 이 모듈을 어댑터로 남기면 된다.

### 6.7 Recommendation Agent

`priority` 가 가장 낮은 권고가 `recommended_action` 이 된다.

| 우선순위 | 조치 | 조건 |
| --- | --- | --- |
| 1 | `TOKEN_REVOCATION` | 폐기 후 사용 / 종료된 Agent / 조회 전용 NHI 의 변경 행위 / 만료일 경과 |
| 2 | `TOKEN_ROTATION` | 노출된 활성 자격 증명 / (인벤토리) 회전 주기 초과·만료일 없음 |
| 3 | `SCOPE_REDUCTION` | Admin·Delete 보유, 미사용 권한 존재 |
| 4 | `ASSIGN_OWNER` | Owner 미지정 |
| 5 | `SPLIT_TOKEN_PER_PROJECT` | 2개 이상 프로젝트 공유 |
| 6 | `MOVE_TO_ENV_VAR` | 코드에 평문 하드코딩 (스캔 경로 전용) |
| 7 | `DISABLE_INACTIVE_NHI` | 장기 미사용 / Agent 종료 |
| 8 | `REQUEST_REAPPROVAL` | 사람 검토 필요, 예외 만료, Critical 등급 |
| 9 | `MONITOR` | 조치 대상 없음 |

`automatable` 은 정책 엔진이 자동 조치를 허용한 경우에만 `true` 가 된다.

### 6.8 관계 그래프 및 Blast Radius

```
AI Agent → NHI → Credential → Permission → Service → Resource
```

`RelationshipGraph` 는 노드/엣지를 중복 없이 누적하므로 여러 NHI 가 같은 Service 노드를
공유한다. `reachable(node_id)` 로 특정 NHI 에서 도달 가능한 서비스·자원을 뽑을 수 있다.
Blast Radius 산출 항목: 연결 서비스 수, 접근 가능 자원 수, 읽기·쓰기·삭제 권한, 외부 전송
가능 여부, 다른 프로젝트 영향, 민감 데이터 접근, `impact_score`(0~100).
권한은 `ADMIN ⊃ DELETE ⊃ WRITE ⊃ READ` 로 펼쳐서 판단한다.

---

## 7. 입력 스키마

### 7.1 외부 입력 신호 (`AnalysisSignals`)

코드·인벤토리 어디에도 없는 사실은 신호로 주입한다. 없으면 보수적으로 평가된다.

```json
{
  "repository_public": true,
  "owner": "Customer Support Team",
  "agent_status": "terminated",
  "agent_name": "support-agent",
  "declared_permissions": ["READ"],
  "observed_actions": ["chat:write", "delete_repo"],
  "token_used_after_revocation": false,
  "shared_projects": ["acme/payments", "acme/support"],
  "created_at": "2025-01-02T00:00:00Z",
  "last_used_at": "2026-07-20T09:00:00Z",
  "expires_at": null,
  "last_rotated_at": null,
  "exception_id": "EXC-2026-014",
  "exception_expires_at": "2026-12-31T00:00:00Z",
  "exempted_policies": ["ROTATION_PERIOD"],
  "extra": { "anomalies": ["비업무시간 대량 조회"], "connected_services": ["Datadog"] }
}
```

`declared_permissions` / `observed_actions` 는 `READ` 같은 공통 권한 표기와
`chat:write` 같은 원본 Scope 를 모두 받는다(내부에서 정규화).

### 7.2 NHI 인벤토리 입력 (`GitHubNHIInput`)

```json
{
  "nhi_id": "github-app-001",
  "nhi_name": "deployment-automation-app",
  "nhi_type": "GITHUB_APP",
  "owner": null,
  "environment": "production",
  "active": true,
  "repositories": [
    { "name": "acme/backend", "visibility": "private", "is_sensitive": true }
  ],
  "raw_permissions": { "contents": "write", "administration": "write", "metadata": "read" },
  "created_at": null,
  "last_used_at": "2025-01-01T00:00:00Z",
  "expires_at": null,
  "last_rotated_at": null
}
```

`nhi_type` 은 `GITHUB_APP` / `PERSONAL_ACCESS_TOKEN` / `ACTIONS_CREDENTIAL` 만 허용한다.
잘못된 값은 분석 함수까지 내려오지 않고 API 입구에서 422 로 걸러진다.

---

## 8. 출력 스키마 (`NHIAnalysis.to_dict()`)

```json
{
  "nhi_name": "customer-support-bot",
  "nhi_type": "SLACK_BOT",
  "owner": "Customer Support Team",
  "environment": "production",
  "permissions": ["READ", "WRITE"],
  "risk_score": 82,
  "risk_level": "CRITICAL",
  "risk_reasons": ["운영 환경에서 사용 중", "만료일 없는 활성 Token", "공개 Repository 노출"],
  "recommended_action": "TOKEN_ROTATION",

  "source": "code_scan",
  "discovery": { "nhi_id": "slack:B01", "confidence": 0.95, "evidence": ["..."] },
  "context_analysis": { "data_sensitivity": "confidential", "confidence": 0.85 },
  "permission_detail": { "mappings": [{ "raw_scope": "chat:write", "permission": "WRITE" }] },
  "risk_detail": { "base_score": 64, "factors": [{ "label": "노출 위치", "score": 18 }], "forced_rules": [] },
  "policy": { "outcome": "HUMAN_REVIEW", "violations": [], "evidence": ["..."] },
  "recommendations": [{ "action": "TOKEN_ROTATION", "priority": 2, "rationale": "..." }],
  "blast_radius": { "connected_services": ["Slack"], "impact_score": 55 }
}
```

앞의 9개 필드가 요약(대시보드 목록 화면), 뒤가 그 판단의 근거(상세 화면)다.
`risk_detail.factors` 를 보면 어느 영역에서 몇 점이 나왔는지 그대로 추적할 수 있다.
`source` 로 스캔 결과인지 인벤토리 입력인지 구분한다.

---

## 9. Agent 실행 계층

### 9.1 왜 LLM 을 먼저 붙이지 않았는가

보안 판단을 LLM 에 전적으로 맡기면 같은 입력에 결과가 달라지고, 점수 근거가 불명확해지고,
존재하지 않는 정책을 만들어낼 수 있고, 자동 테스트가 어려워진다. 그래서 역할을 나눴다.

- **규칙 기반 엔진** — 권한 분석, 위험 검출, 점수 계산 (재현성·감사 가능성)
- **Agent Runtime** — 어떤 도구를 실행할지 선택하고 실행 상태 관리
- **LLM (예정)** — 목표 해석, 계획 수립, 자연어 보고서

LLM 을 붙일 때는 `agent_runtime/planner.py` 를 교체하고 보고서 생성 단계를 추가한다.
위험 계산은 규칙 기반으로 유지한다.

### 9.2 도구 3종 — 모두 실제 구현

| Action | 도구 | 실제 동작 |
| --- | --- | --- |
| `ANALYZE_NHI` | `AnalyzeNHITool` | `agents/pipeline.py` 통합 분석 |
| `SCAN_SECRETS` | `SecretScanTool` | `connectors` + `scanner` 로 접근 가능 저장소를 실제 스캔하고, 탐지 결과를 같은 엔진으로 채점 |
| `EVALUATE_POLICY` | `PolicyEvaluationTool` | `policy` 판정 결과 + 정책 카탈로그·임계값 정리 |

`SCAN_SECRETS` 는 외부 API 호출이 필요하다. `GITHUB_TOKEN` 이 없거나 연동에 실패하면
`scan_executed: false` 와 이유를 반환한다. **검사하지 않은 것을 "Secret 없음" 으로 보고하지
않는다.** 한 저장소 스캔이 실패해도 이미 끝난 분석 결과는 유지되고, 실패한 저장소만
`repositories_failed` 에 남는다. 한 번에 스캔할 저장소 수는 `scan_repository_limit`(기본 3)로
제한하고 나머지는 `repositories_skipped` 로 남긴다.

새 도구는 `build_tool_registry()` 에 등록하면 Orchestrator 를 수정하지 않아도 된다.

### 9.3 조건부 재계획

```
Secret 스캔  : 사용자가 허용 AND 위험 등급 HIGH 또는 CRITICAL   → SCAN_SECRETS 추가
정책 평가    : 사용자가 허용                                    → EVALUATE_POLICY 추가
마지막                                                          → COMPLETE 추가
```

허용했다고 무조건 실행하지 않는 것이 설정 기반 실행과의 차이다. 저위험 NHI 까지 모두
스캔하면 실행 시간·API 비용·저장소 접근 범위가 불필요하게 늘어난다.
계획이 실행 중에 늘어나므로 Orchestrator 는 `for` 가 아니라 매 반복마다 최신 계획에서
다음 미완료 작업을 다시 찾는 방식으로 돌고, 각 작업에 생성 출처(`INITIAL_PLAN` /
`REPLANNER`)와 실패 사유를 남긴다.

### 9.4 실행 예시

요청 `{ "nhi": { "environment": "production", "owner": null, "raw_permissions": { "administration": "write" } }, "allow_secret_scan": true, "allow_policy_evaluation": true }`

```
초기 계획   1. ANALYZE_NHI                      (INITIAL_PLAN)
분석 결과   risk_level = CRITICAL
재계획      2. SCAN_SECRETS                     (REPLANNER)
            3. EVALUATE_POLICY                  (REPLANNER)
            4. COMPLETE                         (REPLANNER)
```

같은 요청에서 위험 등급이 `LOW` 였다면 계획은 `ANALYZE_NHI → COMPLETE` 로 끝난다.

---

## 10. 영속화

스캔 결과·Repository·해결 상태는 SQLite(`NHI_DB_PATH`, 기본 `nhi_scanner.db`)에 저장된다.
**원문 토큰은 DB 에 저장하지 않으며**, DB 에서 복원한 finding 은 `_raw_value` 가 비어 있어
외부 API 재검증이 불가능하다(의도된 보안 속성 — 재검증하려면 재스캔해야 한다).

PostgreSQL 등으로 교체하려면 `storage/base.py` 의 `Storage` 인터페이스를 구현하고
`api/app.py` 의 `storage = get_default_storage()` 한 줄만 바꾸면 된다.
스키마는 `storage/sqlite_store.py` 의 `_SCHEMA` 참고.

분석 결과는 현재 요청 시점에 계산하며 **영속화하지 않는다.** 이력 비교가 필요하면
`Storage` 인터페이스에 분석 결과 저장 메서드를 추가하는 것이 다음 단계다.

---

## 11. 설계상 지켜야 할 규칙

1. **원문 Secret 은 분석 계층에 들어오지 않는다.** 마스킹된 값과 메타데이터로만 판단한다.
2. **모르는 값은 안전으로 취급하지 않는다.** 미확인 항목은 중간 점수를 주고 근거에 명시한다.
3. **근거 없는 판정을 만들지 않는다.** 실행하지 않은 검사는 "이상 없음" 이 아니고,
   코드 노출 사실이 없는 입력에 평문 노출 위반을 붙이지 않는다.
4. **강제 Critical 은 예외 승인으로 덮이지 않는다.** 사고성 조건이므로 항상 검토 대상이다.
5. **자동 조치는 운영 환경·미식별 NHI 에 적용하지 않는다.** 서비스 중단 위험이 크다.
6. **모든 판정에 근거를 남긴다.** `evidence` / `reasons` / `factors` 없이 점수만 내지 않는다.
7. **의존 방향을 지킨다.** `core` ← `scanner`/`connectors`/`policy`/`graph` ← `agents`
   ← `agent_runtime` ← `api`. 역방향 import 를 만들지 않는다.

---

## 12. 현재 상태

**구현됨**

- GitHub 조직 App installation 수집(페이지 순회·완전성 표시), Microsoft 365 · Google Workspace 인벤토리 수집
- GitHub/Slack/GitLab/Notion/Hugging Face 연동, Webhook 자동 검사
- Regex + Entropy Secret 탐지, 마스킹, Fingerprint, 중복 병합, 재스캔 판정, 읽기 전용 재검증
- NHI 식별 / 문맥 분석 / Scope 정규화 / Blast Radius / 관계 그래프
- 감사 로그 정규화 → 사용 분석 → 보안 이벤트 → 시나리오, 승인 권한 ↔ 관측 사용 비교
- 규칙 기반 위험 점수(7영역 100점) + 강제 Critical 8종, 정책 엔진 8종, 조치 권고 9종
- Agent 접근 기준선 · 위장 호출 판정(ALLOW/REVIEW/DENY) · 실시간 통제(PASS/REQUIRE_APPROVAL/BLOCK) · 1회용 승인 허가
- 규칙 카탈로그 단일화(NHI 단위 질의와 Agent 호출이 같은 평가기 사용)
- DPoP sender-constrained token 연구 경로(저장소 기반 replay 차단, Gateway 증거 서버 검증)
- 개인 관리자 키 · 역할 · 직무 분리, 변경 승인(영향도 미리보기 · 롤백), 격리/해제
- NHI 생명주기(생성→사용→권한 변경→종료→파기), aging 승인 요청 자동 생성, 파기 증적(수행자≠검증자 · 해시 체인)
- 분석 이력 영속화와 NHI별 스냅샷 비교
- Agent 실행 계층(Planner / Tool Registry / 조건부 Replanner / Orchestrator, 조직 수집 모드)
- SQLite 영속화, PostgreSQL 운영 스키마, FastAPI + Dashboard/Swagger

**부분 구현**

- 공급자 Audit Log · CMDB · IdP 가 연결되지 않아 자동 수집 값은 `UNKNOWN` 이거나 부분 범위일 수 있다.
- 승인 후 revoke/rotate/scope 축소의 **공급자 실행**은 기본 실행기(인벤토리 상태만 변경)뿐이다. 파기 검증도 운영자 수행·기록 방식이다.
- 호출률 측정과 `GOVERNANCE_LOCK` 은 단일 프로세스 기준이다.

**아직 없음**

- 운영용 Agent key enrollment · IdP 연동, 다중 호스트 replay 저장소(Redis 등), DPoP nonce
- CRITICAL 변경의 2인 승인(OWNER + SECURITY), IdP(OIDC) 연동
- 사내 API Gateway 플러그인, 비동기 job · Scheduler(aging 은 현재 API 호출로 실행)
- LLM 기반 Planner / 자연어 보고서

---

## 13. 참여

| 담당 | 범위 |
| --- | --- |
| 팀원 1 | `connectors/` · `scanner/` · `rescan/` · `storage/` · 탐지 계층 스키마 |
| 팀원 2 | `agents/` · `policy/` · `graph/` · 분석 계층 스키마 |
| 팀원 3 (김태희) | `agent_runtime/` · `core/inventory_models.py` · 인벤토리 입력 경로 |

세 계층은 원래 각자 실행되는 별개 프로젝트였고, 지금은 하나의 패키지·하나의 FastAPI 앱·
하나의 테스트 스위트로 합쳐져 있다. 통합 과정에서 중복 구현(별도의 Scope Translation /
Context Analysis / Risk Scoring / Recommendation 모듈)과 Mock 도구는 삭제하고, 그 자리에
실제 엔진을 연결했다.
