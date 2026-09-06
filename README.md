# NHI Risk Analysis Agent

회사가 사용하는 **AI Agent와 NHI(Non-Human Identity)/API 계정의 연결 관계**를 수집해
각 Agent가 어떤 권한으로 어떤 저장소·채널·파일·메일함까지 접근할 수 있는지 설명하고,
실제 API 호출이 승인된 Agent·Credential·권한·자원 범위를 벗어나는지 탐지하는 규칙 기반
시스템이다. 저장소 Secret 탐지와 DPoP 연구 구현은 이 핵심 목표를 보조한다.

이 시스템은 “악의적인 의도”를 추측하지 않는다. 대신 **주장 Agent와 인증 Agent 불일치,
승인되지 않은 NHI/Credential, 권한·자원 범위 초과, 비활성 Agent 사용, Token/proof 재사용**처럼
감사 가능한 사실을 근거로 `ALLOW / REVIEW / DENY`를 만든다.

한 문장으로: **회사 AI Agent의 실제 접근 가능 범위를 인벤토리화하고, 정상 Agent로 위장한
API 호출과 과도한 권한·민감 자원 접근을 근거 기반으로 식별하는 시스템.**

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
             Usage Analysis      승인 권한 ↔ 관측 행위·재사용·폐기 후 사용
                            ▼
             Security Events     관측 사실 / 파생 신호 / 통제 공백
                            ▼
             Scenario Matching   canonical 정책 ID 기반 공격·오용 시나리오
                            ▼
             Blast Radius        연결 서비스·자원·외부 전송·교차 프로젝트
                            ▼
             Policy Engine       정책 6종 위반 판정
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
여기서 Agent 실행 계층은 보안 분석을 수행하는 **Analysis Orchestrator**이며, 감시 대상인
회사 AI Agent와는 다른 개념이다.

```
사용자 목표 + 단건 NHI 또는 GitHub 조직 → State 생성
   → (조직 요청이면) COLLECT_GITHUB_DATA → 수집 결과 기반 재계획
   → ANALYZE_NHI → 결과 관찰 → 조건부 재계획
   → (위험 등급 HIGH 이상 + 허용 시) SCAN_SECRETS
   → 스캔 실행/부분/미실행 결과를 관찰한 2차 재계획
   → (허용 시) EVALUATE_POLICY → COMPLETE
```

실행 시점의 위장·범위 초과 호출은 별도 경로에서 판정한다.

```
회사 Agent Registry                        API Gateway / Audit Log
Agent → 승인 NHI → Credential                    실제 호출
     → 권한 → 허용 자원                          주장 Agent / 인증 Agent
            └──────────────────┬────────────────── NHI / 권한 / 대상 자원
                               ▼
                    Agent Access Evaluator
          신원 불일치 · Token replay · 권한/자원 초과
                               ▼
                    ALLOW / REVIEW / DENY + 이력
```

---

## 2. 디렉터리

```
core/
├─ config.py             환경 설정 (.env)
├─ models.py             SecretFinding / ScanResult / CredentialStatus  ← 탐지 계층 스키마
├─ nhi_models.py         NHIProfile / ContextInsight / PermissionProfile / RiskAssessment /
│                        PolicyEvaluation / BlastRadiusReport / NHIAnalysis / AnalysisSignals
├─ inventory_models.py   GitHubNHIInput / RepositoryInfo  ← 인벤토리 입력 스키마 (Pydantic)
├─ usage_models.py       UsageEvent  ← 공급자별 감사 로그의 최소 공통 스키마
└─ agent_access_models.py 회사 Agent 접근 기준선 / API 관측 / ALLOW·REVIEW·DENY

normalization/
├─ observation_normalizer.py  Connector 입력 → 출처가 명시된 관측 스냅샷
└─ usage_event_adapter.py     감사 로그 필터링·중복 제거 → AnalysisSignals

connectors/              외부 서비스 연동 (HTTP 재시도·Rate Limit·인증 예외 공통 처리)
├─ base_connector.py     공통 기반
├─ github_connector.py   Repo 등록/조회·페이지 순회·완전성 표시, Commit/PR 변경 파일
├─ github_webhook.py     HMAC 서명 검증, push/PR 이벤트 파싱, 자동 검사 트리거
├─ slack_connector.py    Workspace/Bot/App 정보, Scope, 토큰 유효성·폐기 확인
├─ microsoft_graph_connector.py  Entra 서비스 주체·Owner·OAuth/App 권한 Discovery
├─ google_workspace_connector.py OAuth Token 감사 이벤트 기반 Client Discovery
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
├─ usage_analysis_agent.py     승인 권한과 관측 행위 비교 → Event 추출
├─ risk_scoring_agent.py       100점 위험 점수 (policy/scoring 위임)
├─ policy_evidence_agent.py    정책 위반 판정 + 판단 근거(Evidence) 수집
├─ recommendation_agent.py     조치 권고 9종 생성
├─ inventory_adapter.py        GitHubNHIInput → 분석 입력 변환 (인벤토리 경로)
├─ pipeline.py                 두 입력 경로를 하나로 묶는 단일 분석 엔진
└─ heuristics.py               경로·변수명·주석 신호 추출 공용 유틸

policy/
├─ rules.py              정책 6종 + 강제 Critical 7종 + EvaluationContext + PolicyConfig
├─ scoring.py            평가 영역 7개 배점 및 등급 산정
└─ decision_engine.py    자동 조치 / 사람 검토 / 예외 승인 판단

graph/
├─ relationship_graph.py AI Agent → NHI → Credential → Permission → Service → Resource
└─ blast_radius.py       영향 범위 계산 및 합산

agent_runtime/           Agent 실행 계층
├─ models.py             AgentAction / AgentStatus / NHIAgentRequest / NHIAgentState
├─ planner.py            초기 계획 (기본 분석 1단계)
├─ tools.py              AgentTool 인터페이스 + 실제 도구 4종 + Registry
├─ replanner.py          수집·분석·Secret Scan 결과별 조건부 재계획
└─ orchestrator.py       계획 실행 / 상태 관리 / 오류 기록

rescan/
├─ credential_verifier.py 탐지된 토큰의 외부 API 재검증 (읽기 전용 호출만)
└─ revalidator.py         재스캔 + 해결/미해결/재발/신규 판정

storage/
├─ base.py               저장소 인터페이스 (Storage) — DB 교체 시 이 계약만 맞추면 된다
└─ sqlite_store.py       SQLite 구현 (기본)

backend/services/
├─ analysis_history.py        NHI별 분석 스냅샷 변화 비교
└─ agent_access_evaluator.py  Agent 위장·Credential·권한·자원 범위 초과 판정

api/app.py               FastAPI 단일 진입점 (Webhook 수신 포함)
tests/                   단위·통합 테스트 227개 (외부 네트워크 호출 없음)
```

---

## 3. 설치 및 실행

```bash
pip install -r requirements.txt
cp .env.example .env          # 토큰/시크릿 입력
uvicorn api.app:app --reload --port 8000
pytest                        # 227 passed
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
| GET | `/nhi/{nhi_id}/history` | 특정 NHI의 분석 결정 이력 |
| GET | `/nhi/{nhi_id}/history/compare` | 직전 또는 지정 스냅샷 대비 위험·정책·권한·권고 변화 |
| GET | `/actions` · `/actions/{action_id}` | 추천에서 생성된 조치 요청 |
| POST | `/actions/{action_id}/approve` · `/cancel` | 관리자 승인·취소 |
| POST | `/credentials/verify` | 암호화 참조를 이용한 읽기 전용 재검증 |
| POST | `/integrations/github/discover` | 조직 GitHub App installation 수집 → 전건 분석 → 실행 요약 감사 |
| POST | `/nhi/usage/normalize` | 공급자 감사 로그 → 공통 UsageEvent/AnalysisSignals 정규화 |
| PUT·GET | `/agent-access/profiles/{agent_id}` | 회사 Agent별 승인 NHI·Credential·권한·자원 기준선 |
| POST | `/agent-access/evaluate` | Gateway 호출을 기준선과 비교해 ALLOW·REVIEW·DENY |
| GET | `/agent-access/decisions` · `/agent-access/rules` | 위장/범위 초과 판정 이력·확장 규칙 카탈로그 |

### Backend 운영 API와 Dashboard

FastAPI 서버가 별도 빌드 없이 운영 Dashboard를 함께 제공한다.

- 운영 Dashboard: <http://127.0.0.1:8000/dashboard/>
- 공모전 시연 Dashboard: <http://127.0.0.1:8000/competition/>
- Executive KPI: `GET /dashboard/summary`
- Project Coverage: `POST/GET /projects`, `POST /projects/{id}/scan`
- Connector: `POST /connectors/github`, `POST /connectors/slack`,
  `POST /connectors/microsoft`, `POST /connectors/google`,
  `GET /connectors/status`
- Finding Lifecycle: `GET /findings`, `GET /findings/{id}`,
  `PATCH /findings/{id}/status`, `POST /findings/{id}/rescan`
- NHI Inventory: `GET /nhi`, `GET /nhi/{id}`
- Agent Access: `PUT/GET /agent-access/profiles`, `POST /agent-access/evaluate`,
  `GET /agent-access/decisions`
- Decision Flow: Usage → Event → Scenario → Risk/Action과 직전 분석 대비 변화
- Relationship Graph: `GET /graph`
- Review Queue: `POST /reviews/{id}/approve`, `POST /reviews/{id}/reject`
- Audit/Report: `GET /audit`, `GET /reports/summary?format=markdown`

### GitHub 조직 NHI Discovery

`POST /integrations/github/discover`는 조직의 GitHub App installation 목록을 읽기
전용으로 수집한 뒤, 각 installation을 독립 NHI로 분석한다. 조직 인벤토리에는
`GITHUB_INVENTORY_TOKEN`, 저장소 파일 스캔에는 `GITHUB_TOKEN`을 사용하며 두 토큰은
서로 fallback하지 않는다. 전자는 조직 Administration read 범위가 필요할 수 있으므로
일반 코드 스캔 경로와 권한 경계를 분리한다.

조직 installation API는 개별 접근 저장소 이름을 제공하지 않는다. 따라서
`repository_inventory_complete=false`일 때 저장소 수를 0으로 해석하지 않고
`UNKNOWN`으로 표시하며, Secret Scan도 대상 저장소를 확정하지 못한 상태로 남긴다.
응답의 `run_summary`와 `GITHUB_INVENTORY_AGENT_COMPLETED` 감사 이벤트에는 전체 목록
완전성, 실제 plan step, Replanner 출처, Usage/Event/Scenario 수, Secret Scan 범위가
민감 원문 없이 저장된다.

### Microsoft 365 / Google Workspace NHI Discovery

계획서의 1단계인 SaaS 계정·OAuth 권한 수집을 읽기 전용 API로 구현한다. 두
Discovery API는 조직 인벤토리를 반환하므로 `X-NHI-Admin-Key`가 필요하며,
Credential 값은 요청 본문이나 응답/DB에 저장하지 않는다.

| Method | Path | 수집 내용 |
| --- | --- | --- |
| POST | `/integrations/microsoft/discover` | Entra service principal, Owner, delegated grant, app role |
| POST | `/integrations/google/discover` | Admin Reports의 OAuth authorize/activity/revoke 이벤트를 Client ID별 집계 |
| POST | `/nhi/inventory/saas/analyze` | 이미 수집한 공급자 중립 SaaS NHI 1건 분석 |

Microsoft Graph 앱에는 조회 범위에 맞는 최소 권한(일반적으로
`Application.Read.All`과 delegated grant 조회 권한)을 부여한다. Google 쪽은
`admin.reports.audit.readonly` Scope의 단기 access token을 사용한다. Google Reports
결과는 감사 로그 보존 기간 안에서 관측된 이벤트이므로 전체 현재 토큰 목록으로
단정하지 않고 응답의 `coverage_note`와 `inventory_is_complete=false`로 한계를 남긴다.

```bash
curl -X POST http://127.0.0.1:8000/integrations/microsoft/discover \
  -H "Content-Type: application/json" \
  -H "X-NHI-Admin-Key: $NHI_ADMIN_API_KEY" \
  -d '{"limit": 25, "analyze": true}'

curl -X POST http://127.0.0.1:8000/integrations/google/discover \
  -H "Content-Type: application/json" \
  -H "X-NHI-Admin-Key: $NHI_ADMIN_API_KEY" \
  -d '{"max_events": 200, "analyze": true}'
```

### 회사 AI Agent 접근 기준선과 위장 API 판정

`AgentAccessProfile`은 업무 주체인 AI Agent와 인증 주체인 NHI/API 계정을 분리한다.
각 grant에는 provider, NHI ID, Credential fingerprint, 승인 권한, 허용 자원을 함께 둔다.
`GET /agent-access/profiles/{agent_id}/scope`는 이 관계를 합쳐 실제 접근 가능 범위와
Admin/Delete·wildcard 자원, Owner/인벤토리 공백을 보여준다.

API Gateway 또는 감사 로그 수집기는 `POST /agent-access/evaluate`에 주장 Agent,
인증 계층이 확인한 Agent, NHI, Credential fingerprint, 공통 권한, 대상 자원,
sender proof 결과를 보낸다. IP·User-Agent는 보조 증거일 뿐 인증 근거로 사용하지 않는다.
완전한 기준선에서 범위를 벗어나면 `DENY`, 기준선이나 관측 정보가 불완전하면 정상으로
오인하지 않고 `REVIEW`, 모든 증거가 일치할 때만 `ALLOW`한다. 동일 event 재전송은 같은
decision ID로 멱등 저장된다.

규칙은 `backend/services/agent_access_evaluator.py`의 카탈로그에 모여 있다. 이후 팀원이
조사한 정보유출·과도 권한 사례는 새 rule ID와 검증 조건으로 추가하고, GitHub/Microsoft/
Slack Connector 결과는 원문 응답 대신 `GitHubNHIInput` 또는 `SaaSNHIInput`, 활동 로그는
`UsageEvent`로 넘긴다. 수집 상한·권한 부족·페이지 중단은 반드시 `*_complete=false`로 남긴다.

Slack 검증은 원문 Token을 body/query로 받지 않는다. 서버의 `SLACK_BOT_TOKEN`과
`X-NHI-Admin-Key`만 사용하므로 Token이 access log나 APM에 복제되는 경로를 막는다.

### AI Agent API token 탈취·재사용 방어 연구 (DPoP)

검토한 방식과 이 연구에 대한 적합성은 다음과 같다.

| 방식 | 장점 | 한계 | 적용 판단 |
| --- | --- | --- | --- |
| IP·User-Agent 비교 | 구현이 쉽고 이상행동 탐지에 유용 | NAT·프록시·모바일 환경에서 변하고 위조 가능 | 보조 증거만 사용 |
| 자체 디바이스 fingerprint | 데모가 단순함 | 표준 proof가 아니면 값 복제·헤더 위조 가능 | 인증 근거로 사용하지 않음 |
| 짧은 TTL·audience 제한 | 탈취 영향 시간과 사용처 축소 | 유효 시간 안의 token 재사용은 가능 | DPoP와 함께 적용 |
| [OAuth mTLS(RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705.html) | TLS 계층의 강한 client 인증·key 바인딩 | 인증서 PKI, proxy, 배포 자동화 필요 | 운영 고보안 경로 후보 |
| [DPoP(RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449.html) | HTTP 요청 단위 key 보유 증명, 앱에서 실험 가능 | key 보관과 분산 replay cache가 필요 | 연구용 보호 경로로 구현 |
| [SPIFFE/SPIRE](https://spiffe.io/docs/latest/spiffe-specs/)·Cloud Workload Identity | secret 없는 단기 workload identity와 자동 회전 | 별도 인프라·플랫폼 연동 범위가 큼 | 장기 운영 아키텍처 후보 |

현재 `/runtime/*`에는 **DPoP + 짧은 TTL + proof replay cache + IP/UA 감사 증거**를
연구용으로 적용했다. 이 경로는 회사 Agent Registry나 실제 사내 Gateway 연동을 대체하지
않으며, 다중 클러스터 운영 단계에서는 mTLS 또는 SPIFFE/클라우드 Workload Identity와
공유 replay 저장소로 발급 경계를 강화해야 한다.

계획서의 NHI 위험 분석을 실행 시점의 API 보호까지 확장하기 위해 RFC 9449 DPoP
sender-constrained token을 적용한다. 단순 IP/User-Agent 또는 자체 문자열
fingerprint가 아니라 Agent의 EC P-256 공개키 thumbprint를 access token의
`cnf.jkt`에 바인딩한다.

| 단계 | 검증 내용 | 실패 예시 |
| --- | --- | --- |
| Token 발급 | 관리자 승인 + ES256 DPoP proof의 공개키 보유 증명 | 서명 오류, 오래된 proof, proof 재전송 |
| API 호출 | `Authorization: DPoP <token>` + 요청별 새 `DPoP` proof | Bearer 사용, token hash 불일치 |
| Sender 확인 | token의 `cnf.jkt`와 proof JWK thumbprint 비교 | 탈취 token + 공격자 key |
| Replay 확인 | `htm`, `htu`, `iat`, `ath`, 단일 사용 `jti` 검증 | token과 proof를 함께 복사해 재전송 |

| Method | Path | 설명 |
| --- | --- | --- |
| POST | `/runtime/tokens/issue` | 연구 경로에서 관리자 지정 Agent ID에 5분 DPoP-bound token 발급 |
| GET·POST | `/runtime/protected` | Agent private key 보유까지 검증하는 보호 리소스 |

발급 API는 현재 연구용 계정 bootstrap 경계이므로 `X-NHI-Admin-Key`가 필요하다.
운영에서는 이 경계를 조직 IdP 또는 SPIFFE/클라우드 Workload Identity로 교체한다.
요청 IP와 User-Agent는 `ALLOW`/`DENY`의 근거가 아니라 상관분석용 증거로만 저장한다.
보안 이벤트는 token·proof 원문 없이 감사 로그와 `CredentialObservation`에 저장되며,
`token_replay_suspected` 신호는 강제 Critical 규칙과 즉시 폐기 권고로 연결된다.

필수 설정:

```dotenv
NHI_RUNTIME_TOKEN_SIGNING_KEY=<관리자-key와 다른 32-byte 이상 random 값>
NHI_RUNTIME_TOKEN_TTL_SECONDS=300
NHI_DPOP_PROOF_MAX_AGE_SECONDS=120
NHI_RUNTIME_PUBLIC_BASE_URL=https://nhi.example.com
```

API 실행 후 `python scripts/demo_dpop_replay.py`를 호출하면 정상 key의 `ALLOW`,
탈취 token과 공격자 key의 `sender_key_mismatch`, token과 정상 proof를 함께 복사한
경우의 `dpop_proof_replay`를 순서대로 재현한다. Token과 private key는 출력하거나
파일에 저장하지 않는다.

현재 replay cache는 단일 프로세스 메모리 구현이다. 다중 인스턴스 운영에서는 Redis
같은 공유 TTL 저장소로 교체하고, 장기 token이 필요하면 DPoP nonce 또는 조직 IdP의
정식 sender-constrained token 발급 기능을 사용한다. Agent private key도 가능하면
TPM/HSM/KMS처럼 내보낼 수 없는 저장소에 둔다.

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
| POST | `/nhi/inventory/saas/analyze` | Microsoft/Google 등 공급자 중립 NHI 입력 → 분석 |
| POST | `/nhi/usage/normalize` | 원본 감사 이벤트 필터링·중복 제거 → 분석 신호 |
| POST | `/nhi/scopes/translate` | Scope → 공통 권한 변환 |
| PUT·GET | `/agent-access/profiles/{agent_id}` | 회사 Agent의 승인 NHI·권한·자원 기준선 |
| POST | `/agent-access/evaluate` | 실제 API 호출의 위장·범위 초과 판정 |
| GET | `/agent-access/decisions` · `/agent-access/rules` | 판정 이력·규칙 카탈로그 |
| **POST** | **`/agent/nhi/run`** | **분석 Orchestrator 실행 (계획 → 도구 실행 → 재계획)** |
| **POST** | **`/integrations/github/discover`** | **GitHub 조직 App installation 수집·전건 분석** |
| POST | `/integrations/slack/verify` · GET `/integrations/slack/channels` | 서버 설정 Slack Connector 검증·채널 |
| POST | `/webhooks/github` | Webhook 수신 → Push/PR 자동 검사 |

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
  "credential_detail": {
    "account": {},
    "accessible_resources": [],
    "resource_inventory_complete": false,
    "resource_inventory_note": "GitHub Repository 조회가 1페이지에서 중단됨"
  },
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

### 7.2 감사 로그 입력 (`UsageEvent`)

공급자별 Audit Log는 `POST /nhi/usage/normalize`에서 `principal_id`, `action`,
`occurred_at` 중심의 최소 공통 모델로 바뀐다. NHI와 일치하는 이벤트만 모아 실제 사용 권한,
최근 사용 시각, 공유 프로젝트를 계산하며 원본 Token과 불필요한 응답 필드는 보관하지 않는다.
중복 이벤트는 제거하고 파싱 실패가 하나라도 있으면 요청의 `data_complete=true`를 그대로
신뢰하지 않는다. 따라서 부분 수집을 근거로 미사용 권한을 확정하지 않는다.

`POST /nhi/inventory/analyze`와 `/nhi/inventory/saas/analyze`에도 `usage_events`,
`usage_data_complete`, `usage_principal_aliases`를 함께 전달하면 정규화 결과가 해당 NHI 분석에
즉시 병합되고, 처리 건수와 실패는 응답의 `usage_ingestion`에 표시된다.

### 7.3 NHI 인벤토리 입력 (`GitHubNHIInput`)

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
  "usage_analysis": { "data_complete": true, "permission_comparison_complete": true, "observed_permissions": ["READ", "WRITE"] },
  "security_events": [{ "event_type": "CROSS_PROJECT_CREDENTIAL_USE", "origin": "control_gap", "severity": "CRITICAL" }],
  "scenario_matches": [{ "scenario_id": "TOKEN_SHARED_ACROSS_PROJECTS", "forced_critical": true }],
  "risk_detail": { "base_score": 64, "factors": [{ "label": "노출 위치", "score": 18 }], "forced_rules": [] },
  "policy": { "outcome": "HUMAN_REVIEW", "violations": [], "evidence": ["..."] },
  "recommendations": [{ "action": "TOKEN_ROTATION", "priority": 2, "rationale": "..." }],
  "blast_radius": { "connected_services": ["Slack"], "impact_score": 55 }
}
```

앞의 9개 필드가 요약(대시보드 목록 화면), 뒤가 그 판단의 근거(상세 화면)다.
`risk_detail.factors` 를 보면 어느 영역에서 몇 점이 나왔는지 그대로 추적할 수 있다.
`source` 로 스캔 결과인지 인벤토리 입력인지 구분한다. `usage_analysis.data_complete=false`와
`permission_comparison_complete=false`는 각각 미사용·권한 초과 없음이 아니라 **판정에 필요한
근거가 불완전함**을 뜻한다. `unused_permissions`는 두 값이 모두 완전한 경우에만 생성되며,
`activity_status`는 `active / inactive_warning / stale / orphaned_candidate / unknown`으로 수명
상태를 구분한다. Scenario의 강제 규칙 ID는 `risk_detail.forced_rules`와 동일하다.

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

### 9.2 도구 4종 — 모두 실제 구현

| Action | 도구 | 실제 동작 |
| --- | --- | --- |
| `COLLECT_GITHUB_DATA` | `CollectGitHubDataTool` | 조직 App installation 페이지 순회, 중복 제거, 수집 완전성 기록 |
| `ANALYZE_NHI` | `AnalyzeNHITool` | `agents/pipeline.py` 통합 분석 |
| `SCAN_SECRETS` | `SecretScanTool` | `connectors` + `scanner` 로 접근 가능 저장소를 실제 스캔하고, 탐지 결과를 같은 엔진으로 채점 |
| `EVALUATE_POLICY` | `PolicyEvaluationTool` | `policy` 판정 결과 + 정책 카탈로그·임계값 정리 |

`SCAN_SECRETS` 는 외부 API 호출이 필요하다. `GITHUB_TOKEN` 이 없거나 연동에 실패하면
`scan_executed: false` 와 이유를 반환한다. **검사하지 않은 것을 "Secret 없음" 으로 보고하지
않는다.** 한 저장소 스캔이 실패해도 이미 끝난 분석 결과는 유지되고, 실패한 저장소만
`repositories_failed` 에 남는다. 한 번에 스캔할 저장소 수는 `scan_repository_limit`(기본 3)로
제한하고 나머지는 `repositories_skipped` 로 남긴다.

`COLLECT_GITHUB_DATA`는 별도 `GITHUB_INVENTORY_TOKEN`만 사용한다. 조직 수집용 고권한
Credential이 저장소 파일 스캔 경로로 흘러가지 않으며, 토큰이 없으면 네트워크 호출 전에
명시적으로 실패한다.

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

조직 요청은 `COLLECT_GITHUB_DATA` 결과를 본 뒤 전건 분석 여부를 정하고, Secret Scan을
실행한 경우에는 **미실행 / 성공 0건 / 부분 실패 / 발견 있음**을 구분한 두 번째 재계획으로
정책 평가와 종료 이유를 확정한다.

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

분석 결과는 `analysis_runs`에 입력·점수·정책 버전과 함께 저장하고 `/analyses`와
`/nhi/{nhi_id}/history`에서 이력을 조회한다. `/nhi/{nhi_id}/history/compare`는 재채점 없이
저장 당시 결과끼리 위험 점수, 정책/강제 규칙, 권한, 시나리오, 권고의 증감을 비교한다.
GitHub 조직 수집 실행은 원문 inventory나 token을 감사 로그에 복제하지
않고 compact `run_summary`만 남긴다. 다건 저장 실패는 item 단위로 보고해 부분 성공을
전체 성공처럼 표시하지 않는다.

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

- GitHub 조직 App installation 수집, Microsoft 365·Google Workspace 인벤토리 수집,
  GitHub Webhook 자동 검사
- Slack/GitLab/Notion/Hugging Face Credential 탐지·읽기 전용 검증 Connector
- Regex + Entropy Secret 탐지, 마스킹, Fingerprint, 중복 병합, 재스캔 판정
- 탐지된 토큰의 외부 API 재검증 (읽기 전용)
- NHI 식별 / 문맥 분석 / Scope 정규화 / Blast Radius / 관계 그래프
- 규칙 기반 위험 점수(7영역 100점) + 강제 Critical 7종
- 정책 엔진 6종 + 조치 결정(자동/검토/예외) + 조치 권고 9종
- NHI 인벤토리 직접 입력 경로 (스캔 결과 없이 분석)
- Agent 실행 계층 (Planner / Tool Registry / 조건부 Replanner / Orchestrator)
- GitHub 조직 App installation 자동 수집, 전건 분석, 수집·저장소·Secret Scan 완전성 구분
- 감사 로그 공통 UsageEvent 정규화·직접 입력, 승인 권한 ↔ 관측 사용 비교, Security Event,
  canonical Scenario Match, Secret Scan 2차 재계획
- GitHub 자격 증명 접근 저장소 전체 페이지 순회와 수집 실패/상한 완전성 표시
- 회사 Agent ↔ NHI ↔ Credential ↔ 권한·자원 승인 기준선과 접근 범위 요약
- 위장 Agent, Token replay, 미승인 Credential, 권한·자원 초과 `ALLOW/REVIEW/DENY` 판정·이력
- DPoP key-bound 단기 token 발급·API 검증·proof replay 차단 연구 경로
- SQLite 분석 이력/감사 영속화와 NHI별 스냅샷 비교, PostgreSQL 운영 스키마, FastAPI + Dashboard/Swagger
- Decision Flow·분석 변화·Agent Run 시각화와 반응형 Dashboard, 테스트 227개

**부분 구현 — 판정 모델은 있으나 실제 수집 근거가 제한됨**

- 권한·환경·Owner·수명·사용·접근 범위 모델과 정책 판정은 구현되어 있다. 다만 공급자별
  Audit Log·CMDB·IdP 연결이 완전하지 않아 자동 수집 값은 `UNKNOWN` 또는 부분 범위일 수 있다.
- GitHub 조직 수집은 App installation과 권한을 수집하지만, 타사 App installation의 개별
  저장소 이름은 조직 API 응답만으로 확정할 수 없어 불완전 범위로 표시한다.
- Microsoft 365·Google Workspace Connector는 일부 계정·Credential·활동 근거를 수집하지만
  전 조직의 모든 Resource·행위를 완전한 snapshot으로 보장하지 않는다.
- Agent 접근 기준선과 판정 API는 구현됐지만 실제 사내 API Gateway가 호출·차단을 적용하는
  연동, 조직 IdP 기반 authenticated_agent_id, 자동 profile reconciliation은 아직 없다.
- DPoP는 탈취 Bearer Token 재사용을 막는 연구 데모와 API 검증까지 구현됐다. 운영용 key
  enrollment·IdP 연동·분산 replay 저장소는 아직 없다.
- Project의 schedule 필드는 저장되지만 실행 Scheduler는 아직 없다. 오해를 막기 위해
  Dashboard의 `정기 검사` 입력은 노출하지 않는다.

**아직 없음**

- 주 공급자 Audit Log·CMDB·IdP를 결합한 authoritative Owner/환경/사용/수명 데이터 수집
- 실제 사내 API Gateway의 동기 enforcement 또는 비동기 로그 스트리밍 연동
- GitHub/Microsoft/Slack 인벤토리에서 AgentAccessProfile을 자동 조립·정합하는 reconciler
- 대규모 조직용 비동기·페이지형 분석 job, Scheduler, 완전 snapshot reconciliation
- 최종 사용자 로그인/RBAC, 운영용 Agent key enrollment, 분산 DPoP replay 저장소·KMS
- 승인 후 revoke/rotate/scope 축소 실행, Dry-run·rollback·사후 검증
- 신규 OAuth 동의 시점의 과도한 Scope 예방 경고·차단
- LLM 기반 목표 해석과 자연어 보고서(위험 판정은 규칙 기반 유지)

---

## 13. 참여

| 담당 | 범위 |
| --- | --- |
| 팀원 1 | `connectors/` · `scanner/` · `rescan/` · `storage/` · 탐지 계층 스키마 |
| 팀원 2 | `agents/` · `policy/` · `graph/` · 분석 계층 스키마 |
| 팀원 3 | `agent_runtime/` · `core/inventory_models.py` · 인벤토리 입력 경로 |

세 계층은 원래 각자 실행되는 별개 프로젝트였고, 지금은 하나의 패키지·하나의 FastAPI 앱·
하나의 테스트 스위트로 합쳐져 있다. 통합 과정에서 중복 구현(별도의 Scope Translation /
Context Analysis / Risk Scoring / Recommendation 모듈)과 Mock 도구는 삭제하고, 그 자리에
실제 엔진을 연결했다.
