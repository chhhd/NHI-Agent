# hanium.zip 비교 및 기능 통합 결과

이 문서는 최초 압축본 통합 당시의 기록이다. 이후 적용한 Lifecycle·접근 통제 기준은
[팀 정책 반영 내역](TEAM_POLICY_INTEGRATION.md)이 현재 기준이다.

작업일: 2026-10-21 (Asia/Seoul)

비교 기준은 GitHub에서 클론한 `be08df4` 커밋이다. `hanium.zip`은
`.archive-review/`에 경로 이탈 여부를 검증한 후 풀었으며, 원본 ZIP을 보존했다.
압축본 내부 Git 이력은 현재 저장소의 `.git`에 복사하지 않았다.

## 확인한 소스

- 주 소스: `.archive-review/hanium/hanium/hanium/NHI-Agent/`
- 내부 ZIP: `.archive-review/hanium/hanium/NHI-Agent-upgrade.zip`
- 내부 ZIP 추출본: `.archive-review/nested-upgrade/NHI-Agent-upgrade/`

주 소스에는 기존 저장소에 없는 소스·테스트·설정 파일 50개와 변경 파일 40개가 있었다.
이 90개 파일의 기능과 연결된 API·모델·저장소·화면을 함께 반영했다.
파일별 출처와 반영 당시 SHA-256은 [통합 목록](archive-integration-manifest.json)에 기록했다.

## 반영한 기능

| 영역 | 기존 저장소 대비 보완 | 주요 파일 |
| --- | --- | --- |
| 사용 분석 | 승인 권한과 실제 행위 비교, 미사용·폐기 후 사용·프로젝트 간 공유·재사용 의심 신호와 시나리오 | `agents/usage_analysis_agent.py`, `core/usage_models.py` |
| 감사 로그 | GitHub 감사 로그 정규화·수집, 분석 이력 비교, 지속 평가 | `normalization/github_audit.py`, `backend/services/github_continuous_assessment.py`, `backend/services/analysis_history.py` |
| SaaS 인벤토리 | Microsoft 365 서비스 주체와 Google Workspace OAuth 클라이언트 수집 및 공통 위험 분석 | `connectors/microsoft_graph_connector.py`, `connectors/google_workspace_connector.py`, `agents/saas_inventory_adapter.py` |
| 실시간 통제 | Agent/NHI/Credential/권한/자원 기준선 비교, ALLOW·ALERT·DENY·QUARANTINE 판정 | `backend/services/agent_access_evaluator.py`, `backend/services/control_service.py` |
| 승인 보류 | 판단 불완전 요청의 관리자 승인, 만료 및 1회용 허가 | `backend/services/control_approval.py` |
| 변경 관리 | 변경 전후 영향도 미리보기, 관리자 1인 승인, 상태 충돌 방지, 내부 Inventory 단순 롤백 | `backend/services/change_control_service.py` |
| 생명주기 | 생성→사용→권한 변경→종료→파기 전이, 노후화·만료·교체 지연, 파기 증적 | `backend/services/lifecycle_service.py`, `backend/services/nhi_aging.py`, `core/destruction_models.py` |
| 런타임 인증 | DPoP 키 바인딩·proof 검증·재사용 방어·단기 토큰 발급 | `security/dpop.py`, `security/replay_store.py` |
| 개인정보 | 감사 로그의 가명처리·민감값 마스킹, 사용 이벤트 보존 기간 | `security/privacy.py`, `security/redaction.py` |
| 대시보드 | Lifecycle·Change Control·Live Control 화면과 합성 데모 데이터 | `frontend/dashboard/governance.js` |
| 데이터·설정 | SQLite 스키마 및 저장 인터페이스 확장, PostgreSQL DDL 보완, 새 설정의 `.env.example` 반영 | `storage/`, `backend/database/postgres_schema.sql`, `core/config.py` |

GitHub 조직 인벤토리 토큰과 감사 로그 토큰은 저장소 스캔 토큰과 분리한다.
관측 데이터가 불완전할 때 미사용·공격으로 단정하지 않는 처리도 함께 반영했다.

## 내부 업그레이드 ZIP의 처리

내부 ZIP은 `feature/competition-dashboard` 브랜치의 별도 구현이다.
주 압축본과 사용 분석·DPoP·접근 통제·승인·생명주기 기능이 겹치지만 모델과 API가 다르다.
중복 서비스·저장 모델은 주 압축본의 통합 구현을 사용한다.

내부 ZIP에서 다음 영향 범위 보완을 추가 반영했다.

- Microsoft 365·Google Workspace 서비스 이름 및 쓰기 권한의 외부 전송 가능성.
- GitHub App의 전체/선택 저장소 접근 범위와 개별 자원 목록 미수집 상태를 구분하는 근거.

`frontend/competition_dashboard/` 발표용 화면은 추출본에 보존했다. 이 화면은 현재 API에 없는
`/nhi-lifecycle`, `/demo/control/overview`, `/agent-access/decisions` 등에 의존하고,
생명주기 단계도 `CREATED/IN_USE/...` 형식을 사용한다. 현재 구현의
`CREATION/ACTIVE/...`와 호환되지 않아 실행 경로에는 등록하지 않았다.
발표 화면의 직접 통합은 별도 API 어댑터와 화면 검증이 필요하다.

## 복사에서 제외한 항목

실제 `.env`, 개인키·인증서, 실행 DB, 압축본의 `.git`, 가상환경, 캐시는 활성 프로젝트에 복사하지 않았다.
추출본과 원본 ZIP은 `.gitignore`에 추가했다. 개인키·DB 임시 파일 등의 제외 규칙도 보강했다.
실제 자격 증명은 추출 폴더에만 남아 있으며 이 문서와 통합 목록에는 값을 기록하지 않았다.

## 검증 결과

- `.venv`를 만들고 `requirements.txt` 의존성을 설치했다 (Python 3.14.3).
- `python -m pytest -o addopts= -q`: **371 passed**.
- 내부 ZIP에서 가져온 영향 범위 보완에 대해 회귀 테스트 4개를 추가했다.
- Chrome headless에서 대시보드 로드, 데모 데이터 생성, 생명주기·변경 승인·실시간 통제 화면 탐색을 확인했다.
  임시 SQLite DB와 FastAPI TestClient를 사용했으며 JavaScript 오류와 HTTP 실패가 없었다.
- `python -m pip check`: 의존성 충돌 없음.
- Starlette TestClient의 httpx 사용에 대한 deprecation warning 1개가 있다. 테스트는 모두 통과했다.

실제 외부 SaaS 계정 호출과 PostgreSQL 서버 연동은 실행하지 않았다.
기본 변경 실행기는 인벤토리 상태를 바꾸며, 실제 공급자의 토큰 폐기·교체는
`ChangeExecutor` 공급자 어댑터를 연결해야 한다. 런타임 replay 저장소와 통제 잠금 등은
단일 프로세스 기준이므로 다중 워커 배포 전에는 공유 저장소가 필요하다.

## Windows 실행

```powershell
Copy-Item .env.example .env
# .env에 필요한 연동·관리자·암호화 키 설정
.\.venv\Scripts\python.exe -m uvicorn api.app:app --reload --port 8000
```

대시보드: `http://localhost:8000/dashboard/` · API 문서: `http://localhost:8000/docs`

Git 커밋과 원격 push는 수행하지 않았다.
