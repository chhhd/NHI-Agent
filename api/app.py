"""FastAPI 애플리케이션 — 시스템의 단일 진입점.

    /repositories, /scans, /rescans, /webhooks/github   저장소 연동 + Secret 탐지
    /nhi/*                                              NHI 위험 분석
    /agent/nhi/run                                      Agent 실행 (계획 → 도구 실행)

실행:
    uvicorn api.app:app --reload --port 8000

Webhook 등록 시 GitHub 쪽 Payload URL 은 `POST /webhooks/github` 이다.
"""

from __future__ import annotations

import logging
import hmac
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from agent_runtime.models import NHIAgentRequest
from agent_runtime.orchestrator import run_nhi_agent
from agents.pipeline import NHIAnalysisPipeline, finding_from_dict
from agents.scope_translation_agent import ScopeTranslationAgent
from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)
from connectors.github_connector import GitHubConnector
from connectors.github_webhook import GitHubWebhookHandler, WebhookVerificationError
from connectors.slack_connector import SlackConnector
from core.inventory_models import GitHubNHIInput
from core.models import ScanResult, ScanTrigger, SecretFinding
from core.nhi_models import AnalysisSignals, NHIAnalysisReport
from core.action_models import ActionStatus
from core.config import get_settings
from normalization import observation_from_finding, observation_from_inventory
from processing import ActionService, persist_analysis, persist_report
from rescan.credential_verifier import CredentialVerifier
from rescan.revalidator import Revalidator
from scanner.scan_service import SecretScanService
from storage import Storage, get_default_storage
from backend.models.entities import (
    ConnectorRecord,
    ConnectorStatus,
    FindingStatus,
    ProjectRecord,
)
from backend.services.demo_workspace import (
    clear_demo_workspace,
    seed_demo_workspace,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NHI Risk Analysis Agent API",
    description=(
        "GitHub/Slack 연동 · Secret 탐지 · NHI 위험 분석 · Agent 실행을 제공한다."
    ),
    version="0.5.0",
)

# ---------------------------------------------------------------------------
# 영속화 저장소 (SQLite 기본, NHI_DB_PATH 로 경로 지정 / Storage 구현 교체 가능)
# ---------------------------------------------------------------------------
storage: Storage = get_default_storage()


def _known_fingerprints(repository: str) -> Set[str]:
    return storage.known_fingerprints(repository)


def _store_result(result: ScanResult) -> None:
    storage.save_scan_result(result)
    event_root = ":".join(
        [
            result.trigger.value,
            result.repository,
            result.commit_sha or result.ref or str(result.pull_request or result.started_at),
        ]
    )
    for finding in result.findings:
        storage.save_observation(
            observation_from_finding(
                finding,
                repository=result.repository,
                source_type=f"repository_{result.trigger.value}",
                source_event_id=(
                    f"{event_root}:{finding.file_path}:{finding.line_number}"
                ),
            )
        )
    logger.info(
        "스캔 저장: repo=%s trigger=%s findings=%d",
        result.repository,
        result.trigger.value,
        len(result.findings),
    )


scan_service = SecretScanService()
#: NHI 분석 / 위험 점수화 파이프라인 (스캔 경로·인벤토리 경로 공용)
nhi_pipeline = NHIAnalysisPipeline()
webhook_handler = GitHubWebhookHandler(
    scan_service=scan_service,
    on_result=_store_result,
    known_fingerprints_provider=_known_fingerprints,
)


# ---------------------------------------------------------------------------
# 요청 모델
# ---------------------------------------------------------------------------
class RepositoryRegisterRequest(BaseModel):
    full_name: str = Field(..., description="owner/repo 형식", examples=["octocat/hello-world"])


class ScanRequest(BaseModel):
    full_name: str
    ref: Optional[str] = None
    commit_sha: Optional[str] = None
    pull_request: Optional[int] = None
    verify_credentials: bool = True
    #: True 면 스캔 결과에 NHI 분석(위험 점수·권고)을 함께 담아 응답한다.
    analyze_nhi: bool = False
    #: 원문을 분리된 AES-GCM 저장소에 짧게 보관해 이후 검증/조치에 사용할지 여부.
    persist_secret_material: bool = False
    signals: Optional[Dict[str, Any]] = Field(
        default=None, description="NHI 분석 보조 신호 (repository_public, owner, agent_status ...)"
    )


class RescanRequest(BaseModel):
    full_name: str
    ref: Optional[str] = None
    verify_credentials: bool = True


class SlackVerifyRequest(BaseModel):
    token: str = Field(..., description="검증할 Slack Token")


class NHIAnalyzeRequest(BaseModel):
    """탐지 결과 기반 NHI 분석 요청."""

    full_name: str
    #: 전체 finding 에 공통 적용할 신호
    signals: Optional[Dict[str, Any]] = None
    #: fingerprint 별 개별 신호 (CMDB/감사 로그 연동 시)
    signals_by_fingerprint: Optional[Dict[str, Dict[str, Any]]] = None
    #: 저장소 대신 직접 전달할 탐지 결과 (`ScanResult.to_dict()["findings"]` 형식)
    findings: Optional[List[Dict[str, Any]]] = None
    include_graph: bool = True


class ScopeTranslateRequest(BaseModel):
    scopes: List[str]
    provider: str = "generic"
    secret_type: str = ""


class InventoryAnalyzeRequest(BaseModel):
    """GitHub NHI 정보를 직접 받아 분석한다 (스캔 결과 없이)."""

    nhi: GitHubNHIInput
    #: 코드·인벤토리에 없는 외부 사실 (agent_status, observed_actions, exception_id ...)
    signals: Optional[Dict[str, Any]] = None


class CredentialVerifyRequest(BaseModel):
    full_name: str
    fingerprint: str


class ActionDecisionRequest(BaseModel):
    actor: str = Field(..., min_length=1)
    reason: str = ""


class ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=1)
    repository: str = Field(..., pattern=r"^[^/\s]+/[^/\s]+$")
    description: str = ""
    policy_enabled: bool = True
    schedule_enabled: bool = False
    schedule_cron: Optional[str] = None


class ConnectorCreateRequest(BaseModel):
    name: str = Field(..., min_length=1)
    project_id: Optional[str] = None
    base_url: Optional[str] = None
    secret_ref: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FindingStatusUpdateRequest(BaseModel):
    status: FindingStatus
    actor: str = Field(..., min_length=1)
    note: str = ""
    assigned_to: Optional[str] = None


def _secret_material_store():
    settings = get_settings().secret_storage
    if not settings.master_key:
        return None
    from security.secret_store import AESGCMSecretMaterialStore

    return AESGCMSecretMaterialStore(
        storage,
        settings.master_key,
        key_id=settings.key_id,
        default_ttl_seconds=settings.ttl_seconds,
    )


def _require_admin_key(provided: Optional[str]) -> None:
    expected = get_settings().secret_storage.admin_api_key
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="NHI_ADMIN_API_KEY 가 설정되지 않아 민감 작업 API 가 비활성화되어 있습니다.",
        )
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="올바른 관리자 API Key 가 필요합니다.")


def _seal_findings(findings: Sequence[SecretFinding]) -> None:
    material_store = _secret_material_store()
    if material_store is None:
        raise HTTPException(
            status_code=503,
            detail="NHI_MASTER_KEY 가 설정되지 않아 Secret material 을 저장할 수 없습니다.",
        )
    for finding in findings:
        if not finding.raw_value:
            continue
        finding.secret_ref = str(
            material_store.seal(
                finding.raw_value,
                fingerprint=finding.fingerprint,
            )
        )


# ---------------------------------------------------------------------------
# 예외 → HTTP 상태 변환
# ---------------------------------------------------------------------------
def _http_error(exc: ConnectorError) -> HTTPException:
    if isinstance(exc, AuthenticationError):
        return HTTPException(status_code=401, detail=exc.message)
    if isinstance(exc, PermissionDeniedError):
        return HTTPException(status_code=403, detail=exc.message)
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail=exc.message)
    if isinstance(exc, RateLimitError):
        return HTTPException(status_code=429, detail=exc.message)
    return HTTPException(status_code=502, detail=exc.message)


# ---------------------------------------------------------------------------
# 엔드포인트
# ---------------------------------------------------------------------------
@app.get("/")
def service_info() -> Dict[str, Any]:
    """서비스 개요 (문서는 /docs)."""
    return {
        "service": "NHI Risk Analysis Agent",
        "version": app.version,
        "entry_points": {
            "scan": "POST /scans",
            "nhi_analysis_from_scan": "POST /nhi/analyze",
            "nhi_analysis_from_inventory": "POST /nhi/inventory/analyze",
            "agent": "POST /agent/nhi/run",
            "dashboard": "GET /dashboard/",
            "docs": "GET /docs",
        },
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/repositories", status_code=201)
def register_repository(body: RepositoryRegisterRequest) -> Dict[str, Any]:
    """GitHub Repository 등록."""
    try:
        with GitHubConnector() as gh:
            repo = gh.register_repository(body.full_name)
    except ConnectorError as exc:
        raise _http_error(exc)

    storage.upsert_repository(repo)
    return repo.to_dict()


@app.get("/repositories")
def list_repositories() -> Dict[str, Any]:
    repos = storage.list_repositories()
    return {"count": len(repos), "repositories": repos}


@app.get("/repositories/{owner}/{repo}/branches")
def list_branches(owner: str, repo: str) -> Dict[str, Any]:
    try:
        with GitHubConnector() as gh:
            return {"branches": gh.list_branches(f"{owner}/{repo}")}
    except ConnectorError as exc:
        raise _http_error(exc)


@app.get("/repositories/{owner}/{repo}/files")
def list_files(owner: str, repo: str, ref: Optional[str] = None) -> Dict[str, Any]:
    try:
        with GitHubConnector() as gh:
            files = gh.list_files(f"{owner}/{repo}", ref=ref)
    except ConnectorError as exc:
        raise _http_error(exc)
    return {"count": len(files), "files": files}


@app.post("/scans")
def run_scan(
    body: ScanRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """수동 스캔. commit_sha / pull_request 를 주면 변경 파일만 검사한다."""
    try:
        with GitHubConnector() as gh:
            if body.pull_request is not None:
                targets = gh.scan_targets_for_pull_request(body.full_name, body.pull_request)
                trigger = ScanTrigger.PULL_REQUEST
            elif body.commit_sha:
                targets = gh.scan_targets_for_commit(body.full_name, body.commit_sha)
                trigger = ScanTrigger.PUSH
            else:
                files = gh.list_files(body.full_name, ref=body.ref)
                targets = gh.build_scan_targets(
                    body.full_name, [f["path"] for f in files], ref=body.ref
                )
                trigger = ScanTrigger.MANUAL

            result = scan_service.scan_targets(
                targets,
                repository=body.full_name,
                trigger=trigger,
                ref=body.ref,
                commit_sha=body.commit_sha,
                pull_request=body.pull_request,
                known_fingerprints=_known_fingerprints(body.full_name),
            )

            if body.verify_credentials:
                CredentialVerifier().verify_all(result.findings)
            if body.persist_secret_material:
                _require_admin_key(x_nhi_admin_key)
                _seal_findings(result.findings)
    except ConnectorError as exc:
        raise _http_error(exc)

    _store_result(result)
    payload = result.to_dict()
    if body.analyze_nhi:
        report = nhi_pipeline.analyze_findings(
            result.findings,
            repository=body.full_name,
            default_signals=AnalysisSignals.from_dict(body.signals),
        )
        payload["persistence"] = persist_report(
            storage, report, input_revision=result.commit_sha or result.ref or result.started_at
        )
        payload["nhi_analysis"] = report.to_dict()
    return payload


@app.get("/scans/{owner}/{repo}")
def get_scan_history(owner: str, repo: str, limit: int = 10) -> Dict[str, Any]:
    results = storage.list_scan_results(f"{owner}/{repo}", limit=limit)
    return {"count": len(results), "results": results}


@app.get("/scans")
def list_all_scans(limit: int = 100) -> Dict[str, Any]:
    results = storage.list_all_scan_results(limit=min(max(limit, 1), 500))
    return {"count": len(results), "scans": results}


@app.post("/rescans")
def run_rescan(body: RescanRequest) -> Dict[str, Any]:
    """조치 이후 재스캔 — 해결/미해결/재발 판정."""
    repo = body.full_name
    previous = storage.all_findings(repo)

    try:
        report = Revalidator().rescan_repository(
            repo,
            ref=body.ref,
            previous_findings=previous,
            resolved_fingerprints=storage.resolved_fingerprints(repo),
            verify_credentials=body.verify_credentials,
        )
    except ConnectorError as exc:
        raise _http_error(exc)

    # 재스캔 결과(신규/재발 포함)도 이력에 남긴다.
    _persist_rescan(report)
    return report.to_dict()


def _persist_rescan(report) -> None:
    """재스캔에서 새로 확인된 finding 을 스캔 이력으로 저장."""
    current = list(report.unresolved) + list(report.recurred) + list(report.new)
    if not current:
        return
    result = ScanResult(repository=report.repository, trigger=ScanTrigger.RESCAN)
    result.findings = current
    storage.save_scan_result(result)


@app.post("/findings/{fingerprint}/resolve")
def mark_resolved(fingerprint: str, full_name: str) -> Dict[str, Any]:
    """관리자가 조치 완료로 표시. 이후 재탐지되면 '재발'로 분류된다."""
    storage.mark_resolved(full_name, fingerprint)
    return {"repository": full_name, "fingerprint": fingerprint, "status": "resolved"}


# ---------------------------------------------------------------------------
# NHI 분석 — 탐지 결과 → NHI 식별 / 위험 점수 / 정책 / 조치 권고
# ---------------------------------------------------------------------------
def _load_findings(full_name: str, raw: Optional[List[Dict[str, Any]]]) -> List[SecretFinding]:
    """요청에 findings 가 있으면 그것을, 없으면 저장소의 탐지 결과를 쓴다."""
    if raw:
        return [finding_from_dict(item) for item in raw]
    return storage.all_findings(full_name)


def _run_analysis(
    full_name: str,
    findings: Sequence[SecretFinding],
    *,
    signals: Optional[Dict[str, Any]] = None,
    per_finding: Optional[Dict[str, Dict[str, Any]]] = None,
    include_graph: bool = True,
) -> NHIAnalysisReport:
    if not findings:
        raise HTTPException(
            status_code=404,
            detail=f"분석할 탐지 결과가 없습니다: {full_name} (먼저 POST /scans 를 실행하세요)",
        )
    overrides = {
        fingerprint: AnalysisSignals.from_dict(data)
        for fingerprint, data in (per_finding or {}).items()
    }
    return nhi_pipeline.analyze_findings(
        findings,
        repository=full_name,
        default_signals=AnalysisSignals.from_dict(signals),
        signals_by_fingerprint=overrides,
        build_graph=include_graph,
    )


@app.post("/nhi/analyze")
def analyze_nhi(body: NHIAnalyzeRequest) -> Dict[str, Any]:
    """탐지된 Credential 을 NHI 관점으로 분석한다.

    코드만으로 알 수 없는 사실(Repository 공개 여부, Owner, Agent 상태,
    감사 로그 기반 행위 등)은 `signals` 로 주입하면 점수에 반영된다.
    """
    findings = _load_findings(body.full_name, body.findings)
    report = _run_analysis(
        body.full_name,
        findings,
        signals=body.signals,
        per_finding=body.signals_by_fingerprint,
        include_graph=body.include_graph,
    )
    payload = report.to_dict()
    payload["persistence"] = persist_report(storage, report)
    return payload


@app.get("/nhi/{owner}/{repo}")
def get_nhi_analysis(
    owner: str, repo: str, repository_public: Optional[bool] = None
) -> Dict[str, Any]:
    """저장된 탐지 결과를 기준으로 한 NHI 분석 (요약 + 상세)."""
    full_name = f"{owner}/{repo}"
    signals = {"repository_public": repository_public} if repository_public is not None else None
    report = _run_analysis(full_name, storage.all_findings(full_name), signals=signals)
    return report.to_dict()


@app.get("/nhi/{owner}/{repo}/graph")
def get_nhi_graph(owner: str, repo: str) -> Dict[str, Any]:
    """관계 그래프: AI Agent → NHI → Credential → Permission → Service → Resource."""
    full_name = f"{owner}/{repo}"
    report = _run_analysis(full_name, storage.all_findings(full_name))
    return {"repository": full_name, "graph": report.graph}


@app.get("/nhi/{owner}/{repo}/blast-radius")
def get_blast_radius(owner: str, repo: str) -> Dict[str, Any]:
    """Credential 손상 시 영향 범위 (Repository 합산 + NHI 별)."""
    full_name = f"{owner}/{repo}"
    report = _run_analysis(full_name, storage.all_findings(full_name), include_graph=False)
    return {
        "repository": full_name,
        "summary": nhi_pipeline.blast_radius_summary(report.analyses),
        "by_nhi": [
            {
                "nhi_name": a.profile.nhi_name,
                "nhi_type": a.profile.nhi_type.value,
                "risk_level": a.risk.level.value,
                "blast_radius": a.blast_radius.to_dict(),
            }
            for a in report.analyses
        ],
    }


@app.post("/nhi/inventory/analyze")
def analyze_inventory_nhi(body: InventoryAnalyzeRequest) -> Dict[str, Any]:
    """GitHub NHI 정보를 직접 받아 분석한다.

    스캔 결과가 없어도 (GitHub App / PAT / Actions Credential 목록만으로) 권한·환경·
    저장소 범위·수명 기준으로 같은 100점 체계로 채점한다. 코드 노출 사실이 없는
    입력이므로 평문 노출 관련 정책은 평가하지 않는다.
    """
    observation = observation_from_inventory(body.nhi)
    storage.save_observation(observation)
    analysis = nhi_pipeline.analyze_github_nhi(body.nhi, signals=body.signals)
    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(
        storage, analysis, input_revision=observation.source_event_id
    )
    return payload


@app.post("/nhi/scopes/translate")
def translate_scopes(body: ScopeTranslateRequest) -> Dict[str, Any]:
    """서비스별 Scope → 공통 권한(Read/Write/Delete/Admin) 변환."""
    profile = ScopeTranslationAgent().translate(
        body.scopes, provider=body.provider, secret_type=body.secret_type
    )
    return profile.to_dict()


# ---------------------------------------------------------------------------
# Agent 실행 — 목표를 받아 계획을 세우고 도구를 고른다
# ---------------------------------------------------------------------------
@app.post("/agent/nhi/run")
def run_agent(body: NHIAgentRequest) -> Dict[str, Any]:
    """NHI 분석 Agent 실행.

    기본 분석을 먼저 수행하고, 그 결과를 보고 추가 도구(저장소 Secret 스캔 /
    정책 판정 정리)를 실행할지 정한다. 위험 등급이 낮으면 허용됐더라도 스캔하지 않는다.

    응답에는 실행 계획, 각 단계의 결과와 생성 출처(INITIAL_PLAN / REPLANNER),
    최종 상태가 모두 담긴다.
    """
    state = run_nhi_agent(body)
    payload = state.to_dict()
    if state.analysis is not None:
        payload["persistence"] = persist_analysis(storage, state.analysis)
    return payload


# ---------------------------------------------------------------------------
# 암호화 Credential 재검증 / 분석·조치 이력
# ---------------------------------------------------------------------------
@app.post("/credentials/verify")
def verify_stored_credential(
    body: CredentialVerifyRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """암호화 참조를 이용해 저장된 Credential 을 읽기 전용으로 재검증한다."""
    _require_admin_key(x_nhi_admin_key)
    finding = next(
        (
            item
            for item in storage.all_findings(body.full_name)
            if item.fingerprint == body.fingerprint
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Credential finding 을 찾을 수 없습니다.")
    material_store = _secret_material_store()
    if material_store is None or not finding.secret_ref:
        raise HTTPException(
            status_code=409,
            detail="검증에 사용할 암호화 Secret reference 가 없습니다.",
        )
    CredentialVerifier(material_store=material_store).verify(finding)
    return {
        "fingerprint": finding.fingerprint,
        "provider": finding.provider,
        "credential_active": finding.credential_active,
        "credential_revoked": finding.credential_revoked,
        "raw_scopes": finding.raw_scopes,
        "credential_detail": finding.credential_detail,
    }


@app.get("/analyses")
def list_analysis_history(
    repository: Optional[str] = None, limit: int = 100
) -> Dict[str, Any]:
    analyses = storage.list_analyses(repository=repository, limit=min(max(limit, 1), 500))
    return {"count": len(analyses), "analyses": analyses}


@app.get("/actions")
def list_action_requests(
    status: Optional[ActionStatus] = None, limit: int = 100
) -> Dict[str, Any]:
    actions = storage.list_actions(status=status, limit=min(max(limit, 1), 500))
    return {"count": len(actions), "actions": [action.to_dict() for action in actions]}


@app.get("/actions/{action_id}")
def get_action_request(action_id: str) -> Dict[str, Any]:
    action = storage.get_action(action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="ActionRequest 를 찾을 수 없습니다.")
    return action.to_dict()


@app.post("/actions/{action_id}/approve")
def approve_action(
    action_id: str,
    body: ActionDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_admin_key(x_nhi_admin_key)
    try:
        action = ActionService(storage).approve(action_id, actor=body.actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="ActionRequest 를 찾을 수 없습니다.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return action.to_dict()


@app.post("/actions/{action_id}/cancel")
def cancel_action(
    action_id: str,
    body: ActionDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_admin_key(x_nhi_admin_key)
    try:
        action = ActionService(storage).cancel(
            action_id, actor=body.actor, reason=body.reason
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="ActionRequest 를 찾을 수 없습니다.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return action.to_dict()


# ---------------------------------------------------------------------------
# 운영 Backend — Project / Connector / Finding / NHI / Dashboard / Review
# ---------------------------------------------------------------------------
@app.post("/projects", status_code=201)
def create_project(body: ProjectCreateRequest) -> Dict[str, Any]:
    project = storage.save_project(
        ProjectRecord(
            name=body.name,
            repository=body.repository,
            description=body.description,
            policy_enabled=body.policy_enabled,
            schedule_enabled=body.schedule_enabled,
            schedule_cron=body.schedule_cron,
        )
    )
    storage.append_audit_event(
        "PROJECT_REGISTERED",
        actor="api",
        target=project.project_id,
        detail={"repository": project.repository},
    )
    return storage.get_project(project.project_id) or project.to_dict()


@app.get("/projects")
def get_projects() -> Dict[str, Any]:
    projects = storage.list_projects()
    return {"count": len(projects), "projects": projects}


@app.get("/projects/{project_id}")
def get_project(project_id: str) -> Dict[str, Any]:
    project = storage.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project 를 찾을 수 없습니다.")
    return project


@app.post("/projects/{project_id}/scan")
def scan_project(
    project_id: str,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    project = storage.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project 를 찾을 수 없습니다.")
    return run_scan(
        ScanRequest(full_name=project["repository"], analyze_nhi=True),
        x_nhi_admin_key=x_nhi_admin_key,
    )


def _register_connector(
    provider: str, body: ConnectorCreateRequest
) -> Dict[str, Any]:
    if body.project_id and storage.get_project(body.project_id) is None:
        raise HTTPException(status_code=404, detail="연결할 Project 를 찾을 수 없습니다.")
    connector = ConnectorRecord(
        provider=provider,
        name=body.name,
        project_id=body.project_id,
        base_url=body.base_url,
        secret_ref=body.secret_ref,
        metadata=body.metadata,
        status=(
            ConnectorStatus.CONFIGURED if body.secret_ref else ConnectorStatus.PENDING
        ),
    )
    storage.save_connector(connector)
    storage.append_audit_event(
        "CONNECTOR_REGISTERED",
        actor="api",
        target=connector.connector_id,
        detail={"provider": provider, "project_id": body.project_id},
    )
    payload = connector.to_dict()
    payload.pop("secret_ref", None)
    payload["has_secret_reference"] = bool(connector.secret_ref)
    return payload


@app.post("/connectors/github", status_code=201)
def register_github_connector(body: ConnectorCreateRequest) -> Dict[str, Any]:
    return _register_connector("github", body)


@app.post("/connectors/slack", status_code=201)
def register_slack_connector(body: ConnectorCreateRequest) -> Dict[str, Any]:
    return _register_connector("slack", body)


@app.get("/connectors/status")
def connector_status() -> Dict[str, Any]:
    connectors = storage.list_connectors()
    sanitized = []
    for connector in connectors:
        item = dict(connector)
        item.pop("secret_ref", None)
        item["has_secret_reference"] = bool(connector.get("secret_ref"))
        sanitized.append(item)
    return {"count": len(sanitized), "connectors": sanitized}


@app.get("/findings")
def list_findings(
    status: Optional[FindingStatus] = None,
    risk_level: Optional[str] = None,
    project_id: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    findings = storage.list_finding_records(
        status=status,
        risk_level=risk_level,
        project_id=project_id,
        limit=min(max(limit, 1), 500),
    )
    return {"count": len(findings), "findings": findings}


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> Dict[str, Any]:
    finding = storage.get_finding_record(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding 을 찾을 수 없습니다.")
    return finding


@app.patch("/findings/{finding_id}/status")
def change_finding_status(
    finding_id: str, body: FindingStatusUpdateRequest
) -> Dict[str, Any]:
    try:
        finding = storage.update_finding_status(
            finding_id,
            body.status,
            actor=body.actor,
            note=body.note,
            assigned_to=body.assigned_to,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Finding 을 찾을 수 없습니다.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    storage.append_audit_event(
        "FINDING_STATUS_CHANGED",
        actor=body.actor,
        target=finding_id,
        detail={"status": body.status.value, "note": body.note},
    )
    return finding


@app.post("/findings/{finding_id}/rescan")
def request_finding_rescan(finding_id: str) -> Dict[str, Any]:
    finding = storage.get_finding_record(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding 을 찾을 수 없습니다.")
    try:
        updated = storage.update_finding_status(
            finding_id,
            FindingStatus.RESCAN_PENDING,
            actor="api",
            note="관리자 재스캔 요청",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    storage.append_audit_event(
        "FINDING_RESCAN_REQUESTED",
        actor="api",
        target=finding_id,
        detail={"repository": finding["repository"]},
    )
    return {
        "accepted": True,
        "finding_id": finding_id,
        "repository": finding["repository"],
        "status": updated["status"],
    }


@app.get("/nhi")
def list_nhi_inventory(limit: int = 100) -> Dict[str, Any]:
    records = storage.list_nhi_records(limit=min(max(limit, 1), 500))
    return {"count": len(records), "nhi": records}


@app.get("/nhi/{nhi_id}")
def get_nhi_inventory_item(nhi_id: str) -> Dict[str, Any]:
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")
    return record


@app.get("/dashboard/summary")
def dashboard_summary() -> Dict[str, Any]:
    return storage.dashboard_summary()


@app.post("/demo/workspace", status_code=201)
def create_demo_workspace() -> Dict[str, Any]:
    """실제 Secret이나 외부 API 호출 없이 합성 운영 데이터를 생성한다."""
    return seed_demo_workspace(storage)


@app.delete("/demo/workspace")
def delete_demo_workspace() -> Dict[str, Any]:
    """사용자 데이터는 유지하고 명시적으로 표시된 데모 데이터만 삭제한다."""
    return clear_demo_workspace(storage)


def _require_demo_action(action_id: str):
    action = storage.get_action(action_id)
    if action is None or not action.demo_workspace:
        raise HTTPException(status_code=404, detail="Demo ActionRequest 를 찾을 수 없습니다.")
    return action


@app.post("/demo/reviews/{action_id}/approve")
def approve_demo_review(
    action_id: str, body: ActionDecisionRequest
) -> Dict[str, Any]:
    """합성 Action만 별도 관리자 키 없이 승인한다."""
    _require_demo_action(action_id)
    try:
        action = ActionService(storage).approve(action_id, actor=body.actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return action.to_dict()


@app.post("/demo/reviews/{action_id}/reject")
def reject_demo_review(
    action_id: str, body: ActionDecisionRequest
) -> Dict[str, Any]:
    """합성 Action만 별도 관리자 키 없이 거부한다."""
    _require_demo_action(action_id)
    try:
        action = ActionService(storage).cancel(
            action_id, actor=body.actor, reason=body.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return action.to_dict()


@app.get("/graph")
def global_relationship_graph(limit: int = 100) -> Dict[str, Any]:
    """저장된 최신 분석을 대시보드용 관계 그래프로 합성한다."""
    analyses = storage.list_analyses(limit=min(max(limit, 1), 500))
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[tuple, Dict[str, str]] = {}

    def add_node(node_id: str, node_type: str, label: str, **attributes: Any) -> str:
        nodes.setdefault(
            node_id,
            {"id": node_id, "type": node_type, "label": label, "attributes": attributes},
        )
        return node_id

    def add_edge(source: str, target: str, edge_type: str) -> None:
        edges[(source, target, edge_type)] = {
            "source": source,
            "target": target,
            "type": edge_type,
        }

    for analysis in analyses:
        discovery = analysis.get("discovery") or {}
        credential_id = add_node(
            f"credential:{analysis.get('fingerprint')}",
            "CREDENTIAL",
            analysis.get("masked_value") or discovery.get("secret_name") or "Credential",
            risk_level=analysis.get("risk_level"),
            risk_score=analysis.get("risk_score"),
        )
        nhi_id = add_node(
            f"nhi:{discovery.get('nhi_id')}",
            "NHI",
            analysis.get("nhi_name") or "Unknown NHI",
            owner=analysis.get("owner"),
            risk_level=analysis.get("risk_level"),
        )
        add_edge(nhi_id, credential_id, "AUTHENTICATES_WITH")

        agent_name = discovery.get("linked_ai_agent")
        if agent_name:
            agent_id = add_node(f"agent:{agent_name}", "AI_AGENT", agent_name)
            add_edge(agent_id, nhi_id, "USES")

        for permission in analysis.get("permissions") or []:
            permission_id = add_node(
                f"permission:{analysis.get('fingerprint')}:{permission}",
                "PERMISSION",
                permission,
            )
            add_edge(credential_id, permission_id, "GRANTS")

            blast = analysis.get("blast_radius") or {}
            for service in blast.get("connected_services") or []:
                service_id = add_node(f"service:{service}", "SERVICE", service)
                add_edge(permission_id, service_id, "APPLIES_TO")
                for resource in blast.get("resource_samples") or []:
                    resource_id = add_node(
                        f"resource:{service}:{resource}", "RESOURCE", resource
                    )
                    add_edge(service_id, resource_id, "EXPOSES")

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "stats": {
            node_type: sum(1 for node in nodes.values() if node["type"] == node_type)
            for node_type in (
                "AI_AGENT", "NHI", "CREDENTIAL", "PERMISSION", "SERVICE", "RESOURCE"
            )
        },
    }


@app.post("/reviews/{action_id}/approve")
def approve_review(
    action_id: str,
    body: ActionDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    return approve_action(action_id, body, x_nhi_admin_key)


@app.post("/reviews/{action_id}/reject")
def reject_review(
    action_id: str,
    body: ActionDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    return cancel_action(action_id, body, x_nhi_admin_key)


@app.get("/audit")
def get_audit_log(limit: int = 100) -> Dict[str, Any]:
    events = storage.list_audit_events(limit=min(max(limit, 1), 500))
    return {"count": len(events), "events": events}


@app.get("/reports/summary")
def summary_report(format: str = "json") -> Any:
    summary = storage.dashboard_summary()
    if format.lower() != "markdown":
        return summary
    risk = summary["risk_distribution"]
    lines = [
        "# NHI Security Executive Summary",
        "",
        f"- Projects: {summary['project_count']}",
        f"- NHI: {summary['nhi_count']}",
        f"- Credentials: {summary['credential_count']}",
        f"- Critical / High findings: {summary['critical_high_findings']}",
        f"- Ownerless NHI: {summary['ownerless_nhi_count']}",
        "",
        "## Risk distribution",
        "",
    ]
    lines.extend(f"- {level}: {count}" for level, count in sorted(risk.items()))
    return {"format": "markdown", "content": "\n".join(lines)}


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
@app.post("/integrations/slack/verify")
def verify_slack_token(body: SlackVerifyRequest) -> Dict[str, Any]:
    """Slack Token 유효성 / Scope / 접근 가능 채널 조회."""
    try:
        with SlackConnector(body.token) as slack:
            status = slack.validate_credential(body.token)
            payload = status.to_dict()
            if status.active:
                payload["bot"] = slack.get_bot_info(token=body.token)
                payload["app"] = slack.get_app_info(token=body.token)
                payload["workspace"] = slack.get_workspace_info(token=body.token)
    except ConnectorError as exc:
        raise _http_error(exc)
    return payload


@app.get("/integrations/slack/channels")
def slack_channels(token: Optional[str] = None) -> Dict[str, Any]:
    try:
        with SlackConnector(token) as slack:
            channels = slack.list_channels(token=token)
    except ConnectorError as exc:
        raise _http_error(exc)
    return {"count": len(channels), "channels": channels}


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(default=""),
    x_github_delivery: str = Header(default=""),
    x_hub_signature_256: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """GitHub Webhook 수신 → Push/PR 자동 검사.

    GitHub 은 10초 내 응답을 기대하므로 검증만 동기로 하고
    실제 스캔은 백그라운드로 넘긴다.
    """
    raw_body = await request.body()

    try:
        from connectors.github_webhook import verify_signature

        verify_signature(raw_body, x_hub_signature_256)
    except WebhookVerificationError as exc:
        logger.warning("webhook 서명 검증 실패: %s", exc)
        raise HTTPException(status_code=401, detail=str(exc))

    payload = await request.json()

    background_tasks.add_task(
        _handle_webhook_safely, x_github_event, payload, x_github_delivery
    )
    return {"accepted": True, "event": x_github_event, "delivery": x_github_delivery}


def _handle_webhook_safely(event_type: str, payload: Dict[str, Any], delivery_id: str) -> None:
    """백그라운드 처리 — 예외가 나도 프로세스를 죽이지 않는다."""
    try:
        webhook_handler.handle(event_type, payload, delivery_id=delivery_id)
    except ConnectorError as exc:
        logger.error("webhook 처리 중 Connector 오류 (delivery=%s): %s", delivery_id, exc)
    except Exception:
        logger.exception("webhook 처리 실패 (delivery=%s)", delivery_id)


# 정적 Dashboard 는 API route 등록 뒤에 mount 해 `/dashboard/summary` 를 가리지 않는다.
_dashboard_dir = Path(__file__).resolve().parents[1] / "frontend" / "dashboard"
app.mount(
    "/dashboard",
    StaticFiles(directory=str(_dashboard_dir), html=True),
    name="dashboard",
)
