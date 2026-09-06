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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from agent_runtime.models import GitHubInventoryAgentRequest, NHIAgentRequest
from agent_runtime.orchestrator import run_nhi_agent
from agent_runtime.tools import build_tool_registry
from agents.pipeline import NHIAnalysisPipeline, finding_from_dict
from agents.github_inventory_service import (
    analyze_github_app_nhi_from_connector,
    analyze_github_nhi_from_connector,
)
from agents.slack_inventory_service import analyze_slack_nhi_from_connector
from agents.aws_inventory_service import analyze_aws_nhi_from_connector
from agents.inventory_adapter import _slack_channel_records
from agents.dry_run_service import build_dry_run_result
from agents.scope_translation_agent import ScopeTranslationAgent
from connectors.base_connector import (
    AuthenticationError,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)
from connectors.aws_connector import AWSConnector
from connectors.github_app_connector import GitHubAppConnector
from connectors.github_connector import GitHubConnector
from connectors.github_webhook import GitHubWebhookHandler, WebhookVerificationError
from connectors.google_workspace_connector import GoogleWorkspaceConnector
from connectors.microsoft_graph_connector import MicrosoftGraphConnector
from connectors.slack_connector import SlackConnector
from core.agent_access_models import (
    AgentAccessOutcome,
    AgentAccessProfile,
    AgentApiObservation,
)
from core.inventory_models import GitHubNHIInput, SaaSNHIInput
from core.models import ScanResult, ScanTrigger, SecretFinding
from core.nhi_models import AnalysisSignals, NHIAnalysisReport, NHIType, RecommendedAction
from core.observation_models import CredentialObservation, Evidence
from core.action_models import ActionStatus
from core.approval_models import ApprovalRequest, ApprovalStatus
from core.config import get_settings
from normalization import (
    UsageEventAdapter,
    observation_from_finding,
    observation_from_inventory,
    observation_from_saas_inventory,
)
from processing import ActionService, persist_analysis, persist_report
from rescan.credential_verifier import CredentialVerifier
from rescan.revalidator import Revalidator
from scanner.scan_service import SecretScanService
from security.dpop import InMemoryReplayCache, RuntimeTokenService, TokenBindingError
from security.redaction import sanitize_security_text, sanitize_security_value
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
from backend.services.analysis_history import AnalysisHistoryService
from backend.services.agent_access_evaluator import AgentAccessEvaluator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NHI Risk Analysis Agent API",
    description=(
        "회사 AI Agent의 NHI/API 접근 범위 분석 · 위장/범위 초과 호출 판정 · "
        "GitHub/Slack/Microsoft 365/Google Workspace 연동 · Secret 탐지를 제공한다."
    ),
    version="0.10.0",
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
agent_access_evaluator = AgentAccessEvaluator()
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
    """서버에 설정된 Slack Connector 검증 요청. 원문 Token 입력은 금지한다."""

    model_config = ConfigDict(extra="forbid")


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
    #: 공급자 Audit API 또는 합성 로그에서 받은 원본 이벤트. Token 원문은 넣지 않는다.
    usage_events: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)
    usage_data_complete: bool = False
    usage_source: str = Field(default="audit_log", min_length=1, max_length=100)
    usage_principal_aliases: List[str] = Field(default_factory=list, max_length=20)


class SaaSInventoryAnalyzeRequest(BaseModel):
    """공급자 중립 SaaS NHI 분석 요청."""

    nhi: SaaSNHIInput
    signals: Optional[Dict[str, Any]] = None
    usage_events: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)
    usage_data_complete: bool = False
    usage_source: str = Field(default="audit_log", min_length=1, max_length=100)
    usage_principal_aliases: List[str] = Field(default_factory=list, max_length=20)


class UsageEventNormalizeRequest(BaseModel):
    """공급자별 Audit Log를 공통 UsageEvent와 AnalysisSignals로 변환한다."""

    nhi_id: str = Field(..., min_length=1, max_length=300)
    principal_aliases: List[str] = Field(default_factory=list, max_length=20)
    provider: str = Field(default="generic", min_length=1, max_length=100)
    source: str = Field(default="audit_log", min_length=1, max_length=100)
    declared_permissions: List[str] = Field(default_factory=list, max_length=100)
    events: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)
    data_complete: bool = False


class MicrosoftDiscoveryRequest(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)
    analyze: bool = True


class GoogleDiscoveryRequest(BaseModel):
    max_events: int = Field(default=200, ge=1, le=1000)
    start_time: Optional[str] = Field(
        default=None,
        description="RFC3339 시작 시각. 생략하면 Google Reports API 기본 보존 범위를 사용한다.",
    )
    analyze: bool = True


class RuntimeTokenIssueRequest(BaseModel):
    """연구 경로에서 관리자 요청의 Agent ID에 DPoP-bound 단기 token을 발급한다."""

    agent_id: str = Field(..., min_length=1, max_length=200)
    scopes: List[str] = Field(default_factory=lambda: ["runtime:invoke"])


class CredentialVerifyRequest(BaseModel):
    full_name: str
    fingerprint: str


class ActionDecisionRequest(BaseModel):
    actor: str = Field(..., min_length=1)
    reason: str = ""


class ApprovalDecisionRequest(BaseModel):
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


_runtime_replay_cache = InMemoryReplayCache()


def _runtime_token_service() -> RuntimeTokenService:
    settings = get_settings().runtime_security
    return RuntimeTokenService(
        signing_key=settings.token_signing_key,
        issuer=settings.issuer,
        audience=settings.audience,
        token_ttl_seconds=settings.token_ttl_seconds,
        proof_max_age_seconds=settings.dpop_proof_max_age_seconds,
        clock_skew_seconds=settings.dpop_clock_skew_seconds,
        replay_cache=_runtime_replay_cache,
    )


def _runtime_htu(request: Request) -> str:
    """X-Forwarded-*를 신뢰하지 않고 설정된 public origin 또는 실제 URL을 사용한다."""
    public_base = get_settings().runtime_security.public_base_url.strip()
    if public_base:
        return f"{public_base.rstrip('/')}{request.url.path}"
    return str(request.url).split("#", 1)[0].split("?", 1)[0]


def _single_runtime_header(
    request: Request, name: str, provided: Optional[str]
) -> Optional[str]:
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise TokenBindingError(
            "duplicate_security_header", f"{name} header는 하나만 허용됩니다."
        )
    return provided


def _runtime_source_context(request: Request) -> Dict[str, Any]:
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent", "")[:300],
        "forwarded_headers_trusted": False,
    }


def _runtime_audit(
    *,
    request: Request,
    decision: str,
    reason: str,
    agent_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> str:
    safe_detail = {
        "decision": decision,
        "reason": reason,
        "method": request.method,
        "path": request.url.path,
        **_runtime_source_context(request),
        **(detail or {}),
    }
    event_id = storage.append_audit_event(
        f"RUNTIME_ACCESS_{decision}",
        actor=agent_id or "unauthenticated-agent",
        target=request.url.path,
        detail=safe_detail,
    )
    replay_suspected = bool(safe_detail.get("token_replay_suspected"))
    signals = {
        "token_replay_suspected": replay_suspected,
        "sender_constrained": safe_detail.get("sender_constrained"),
        "token_binding_method": safe_detail.get("token_binding_method"),
        "request_source_ip": safe_detail.get("source_ip"),
        "request_user_agent": safe_detail.get("user_agent"),
        "observed_actions": [f"{request.method} {request.url.path}"],
    }
    storage.save_observation(
        CredentialObservation(
            source_type="runtime_dpop_gateway",
            source_event_id=event_id,
            provider="internal_runtime",
            raw_type="DPOP_BOUND_ACCESS_TOKEN",
            fingerprint=f"nhi:runtime:{agent_id or 'unknown'}",
            masked_value="dpop-bound-token",
            evidence=[
                Evidence(
                    source="runtime_gateway",
                    field="access_decision",
                    value={"decision": decision, "reason": reason},
                    confidence=1.0,
                )
            ],
            raw_metadata={
                "agent_id": agent_id,
                "analysis_signals": signals,
                **safe_detail,
            },
        )
    )
    return event_id


def _persist_runtime_replay_analysis(
    *,
    trigger_event_id: str,
    agent_id: str,
    request: Request,
    detail: Dict[str, Any],
) -> None:
    """차단 이벤트를 기존 NHI 위험 엔진에 자동 입력한다.

    인증 차단은 분석 저장 실패와 무관하게 유지되어야 하므로 실패는 기록만 하고
    호출자에게 내부 오류를 노출하지 않는다.
    """
    source = _runtime_source_context(request)
    signals = AnalysisSignals(
        agent_name=agent_id,
        agent_status="active",
        observed_actions=[f"{request.method} {request.url.path}"],
        token_replay_suspected=True,
        sender_constrained=True,
        token_binding_method="DPoP",
        request_source_ip=source.get("source_ip"),
        request_user_agent=source.get("user_agent"),
    )
    inventory = SaaSNHIInput(
        provider="runtime",
        nhi_id=agent_id,
        nhi_name=agent_id,
        nhi_type=NHIType.AI_AGENT_CREDENTIAL,
        active=True,
        raw_scopes=[
            str(scope)
            for scope in detail.get("scopes", [])
            if isinstance(scope, str) and scope
        ],
        connected_services=["internal_api_gateway"],
        account={
            "token_binding_method": "DPoP",
            "binding_jkt": detail.get("binding_jkt"),
        },
    )
    try:
        analysis = nhi_pipeline.analyze_saas_nhi(inventory, signals=signals)
        persistence = persist_analysis(storage, analysis, input_revision=trigger_event_id)
        storage.append_audit_event(
            "RUNTIME_REPLAY_ANALYZED",
            actor="nhi-risk-engine",
            target=agent_id,
            detail={
                "trigger_event_id": trigger_event_id,
                "risk_level": analysis.risk.level.value,
                "risk_score": analysis.risk.score,
                "forced_rules": [
                    item["rule_id"] for item in analysis.risk.forced_rules
                ],
                **persistence,
            },
        )
    except Exception:
        logger.exception("runtime replay incident 분석 저장 실패 (agent_id=%s)", agent_id)


def _runtime_deny_response(
    exc: TokenBindingError,
    *,
    request: Request,
    stage: str,
    agent_id: Optional[str] = None,
) -> JSONResponse:
    agent_id = agent_id or exc.context.get("agent_id")
    replay_suspected = exc.code in {
        "dpop_proof_replay",
        "sender_key_mismatch",
        "dpop_token_hash_mismatch",
    }
    event_id = _runtime_audit(
        request=request,
        decision="DENY",
        reason=exc.code,
        agent_id=agent_id,
        detail={
            "stage": stage,
            "token_replay_suspected": replay_suspected,
            "sender_constrained": True if agent_id else None,
            "token_binding_method": "DPoP",
            **{
                key: value
                for key, value in exc.context.items()
                if key in {"token_jti", "binding_jkt", "proof_jkt", "proof_jti"}
            },
        },
    )
    if replay_suspected and agent_id:
        _persist_runtime_replay_analysis(
            trigger_event_id=event_id,
            agent_id=agent_id,
            request=request,
            detail=exc.context,
        )
    status_code = exc.status_code
    if stage == "token_issuance" and status_code == 401:
        status_code = 400
    return JSONResponse(
        status_code=status_code,
        content={
            "decision": "DENY",
            "authenticated_as": None,
            "reason": exc.code,
            "message": exc.message,
            "audit_event_id": event_id,
            "source_context": _runtime_source_context(request),
        },
        headers={"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'},
    )


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
            "saas_discovery": "POST /integrations/{github|microsoft|google}/discover",
            "agent_access_profiles": "PUT|GET /agent-access/profiles",
            "agent_access_evaluation": "POST /agent-access/evaluate",
            "agent_access_decisions": "GET /agent-access/decisions",
            "research_dpop_token": "POST /runtime/tokens/issue",
            "research_protected_runtime": "GET|POST /runtime/protected",
            "analysis_orchestrator": "POST /agent/nhi/run",
            "dashboard": "GET /dashboard/",
            "competition_dashboard": "GET /competition/",
            "docs": "GET /docs",
        },
        "operational_limitations": [
            "실제 차단은 사내 API Gateway가 /agent-access/evaluate 결과를 적용해야 함",
            "IdP/RBAC 및 공급자별 전체 인벤토리 동기화는 아직 미구현",
            "/runtime/*는 DPoP 연구 검증용이며 회사 Agent Registry를 대체하지 않음",
        ],
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/runtime/tokens/issue")
def issue_runtime_token(
    body: RuntimeTokenIssueRequest,
    request: Request,
    dpop: Optional[str] = Header(default=None, alias="DPoP"),
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> JSONResponse:
    """검증된 DPoP public key에 바인딩된 단기 AI Agent token을 발급한다.

    이 프로젝트에는 별도 IdP/계정 DB가 없으므로 관리자 key가 Agent 승인을 대신한다.
    운영 환경에서는 이 발급 경계를 조직 IdP 또는 workload identity provider로 교체한다.
    """
    _require_admin_key(x_nhi_admin_key)
    try:
        token = _runtime_token_service().issue_token(
            agent_id=body.agent_id,
            scopes=body.scopes,
            dpop_proof=_single_runtime_header(request, "DPoP", dpop),
            method=request.method,
            htu=_runtime_htu(request),
        )
    except TokenBindingError as exc:
        return _runtime_deny_response(exc, request=request, stage="token_issuance")

    event_id = _runtime_audit(
        request=request,
        decision="ALLOW",
        reason="dpop_bound_token_issued",
        agent_id=body.agent_id,
        detail={
            "stage": "token_issuance",
            "token_type": token["token_type"],
            "token_jti": token["token_jti"],
            "proof_jti": token["proof_jti"],
            "binding_jkt": token["cnf"]["jkt"],
            "sender_constrained": True,
            "token_binding_method": "DPoP",
        },
    )
    response_body = {
        key: value for key, value in token.items() if key not in {"proof_jti", "token_jti"}
    }
    response_body["audit_event_id"] = event_id
    return JSONResponse(
        content=response_body,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@app.get("/runtime/protected")
@app.post("/runtime/protected")
def runtime_protected_resource(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    dpop: Optional[str] = Header(default=None, alias="DPoP"),
) -> Any:
    """token 문자열뿐 아니라 Agent private key 보유까지 증명해야 하는 보호 API."""
    try:
        principal = _runtime_token_service().authorize(
            authorization=_single_runtime_header(request, "Authorization", authorization),
            dpop_proof=_single_runtime_header(request, "DPoP", dpop),
            method=request.method,
            htu=_runtime_htu(request),
        )
    except TokenBindingError as exc:
        return _runtime_deny_response(exc, request=request, stage="resource_access")

    event_id = _runtime_audit(
        request=request,
        decision="ALLOW",
        reason="dpop_proof_verified",
        agent_id=principal.agent_id,
        detail={
            "stage": "resource_access",
            "token_jti": principal.token_id,
            "proof_jti": principal.proof_jti,
            "binding_jkt": principal.binding_jkt,
            "sender_constrained": True,
            "token_binding_method": "DPoP",
        },
    )
    return {
        "decision": "ALLOW",
        "authenticated_as": principal.agent_id,
        "token_type": "DPoP",
        "binding_method": "DPoP-ES256",
        "scopes": list(principal.scopes),
        "token_expires_at": principal.expires_at,
        "audit_event_id": event_id,
        "source_context": _runtime_source_context(request),
    }


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


@app.get("/nhi/{nhi_id}/history/compare")
def compare_nhi_analysis_history(
    nhi_id: str,
    base_analysis_id: Optional[str] = None,
    target_analysis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """동일 NHI의 두 분석을 비교해 위험·정책·권한·권고 변화를 반환한다."""
    try:
        return AnalysisHistoryService(storage).compare(
            nhi_id,
            base_analysis_id=base_analysis_id,
            target_analysis_id=target_analysis_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=exc.args[0]) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/nhi/{nhi_id}/history")
def get_nhi_analysis_history(nhi_id: str, limit: int = 100) -> Dict[str, Any]:
    """NHI에 연결된 분석 결정 이력을 최신순으로 조회한다."""
    return AnalysisHistoryService(storage).list_history(
        nhi_id, limit=min(max(limit, 1), 500)
    )


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


def _signals_from_usage_events(
    *,
    nhi_id: str,
    provider: str,
    raw_signals: Optional[Dict[str, Any]],
    records: List[Dict[str, Any]],
    data_complete: bool,
    source: str,
    principal_aliases: Sequence[str] = (),
    declared_permissions: Sequence[str] = (),
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Audit Log를 NHI 분석 신호로 병합하고 수집 완전성 근거를 만든다."""
    adapter = UsageEventAdapter()
    adaptation = adapter.adapt(records, provider=provider, source=source)
    # 파싱 실패가 한 건이라도 있으면 요청자가 complete=true라고 했더라도 실제
    # 분석 범위는 불완전하다. 실패를 무시한 채 '미사용'을 확정하지 않는다.
    effective_complete = data_complete and not adaptation.failures
    derived = adapter.to_signals(
        adaptation.events,
        principal_ids=[nhi_id, *principal_aliases],
        declared_permissions=declared_permissions,
        data_complete=effective_complete,
    )
    merged = adapter.merge_into_signals(
        AnalysisSignals.from_dict(raw_signals), derived
    )
    summary = {
        **adaptation.summary(),
        "matched_event_count": derived.extra["usage_event_count"],
        "requested_data_complete": data_complete,
        "effective_data_complete": effective_complete,
        "principal_count": 1 + len(principal_aliases),
        "source": sanitize_security_text(source),
    }
    return merged.to_dict(), summary


@app.post("/nhi/inventory/analyze")
def analyze_inventory_nhi(body: InventoryAnalyzeRequest) -> Dict[str, Any]:
    """GitHub NHI 정보를 직접 받아 분석한다.

    스캔 결과가 없어도 (GitHub App / PAT / Actions Credential 목록만으로) 권한·환경·
    저장소 범위·수명 기준으로 같은 100점 체계로 채점한다. 코드 노출 사실이 없는
    입력이므로 평문 노출 관련 정책은 평가하지 않는다.
    """
    observation = observation_from_inventory(body.nhi)
    storage.save_observation(observation)
    usage_ingestion = None
    signals = body.signals
    if body.usage_events or body.usage_data_complete:
        signals, usage_ingestion = _signals_from_usage_events(
            nhi_id=body.nhi.nhi_id,
            provider="github",
            raw_signals=body.signals,
            records=body.usage_events,
            data_complete=body.usage_data_complete,
            source=body.usage_source,
            principal_aliases=body.usage_principal_aliases,
        )
    analysis = nhi_pipeline.analyze_github_nhi(body.nhi, signals=signals)
    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(
        storage, analysis, input_revision=observation.source_event_id
    )
    if usage_ingestion is not None:
        payload["usage_ingestion"] = usage_ingestion
    return payload


@app.post("/nhi/github/inventory/analyze")
def analyze_github_inventory_from_api() -> Dict[str, Any]:
    """Fetch the configured GitHub inventory, analyze it, and persist the result."""
    try:
        with GitHubConnector() as connector:
            analysis = analyze_github_nhi_from_connector(
                connector, pipeline=nhi_pipeline
            )
    except ConnectorError as exc:
        raise _http_error(exc)

    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(storage, analysis)
    return payload


@app.post("/nhi/github/app/inventory/analyze")
def analyze_github_app_inventory_from_api() -> Dict[str, Any]:
    """Fetch every configured GitHub App installation's inventory, analyze, and persist each result.

    한 App 은 여러 조직/계정에 설치될 수 있으므로 PAT 엔드포인트
    (`/nhi/github/inventory/analyze`, 단일 결과)와 달리 installation 당 하나씩
    분석 결과를 만들어 목록으로 반환한다. 분석·저장 로직 자체는 완전히
    동일하다 — `analyze_github_app_nhi_from_connector()` 가 기존
    `NHIAnalysisPipeline.analyze_github_nhi()` 를 그대로 재사용한다.
    """
    try:
        with GitHubAppConnector() as connector:
            analyses = analyze_github_app_nhi_from_connector(
                connector, pipeline=nhi_pipeline
            )
    except ConnectorError as exc:
        raise _http_error(exc)

    results = []
    for analysis, nhi in analyses:
        provider_detail = {
            "github_app": {
                "installation_id": nhi.installation_id,
                "repository_selection": nhi.repository_selection,
                "credential_verified": nhi.credential_verified,
            }
        }
        payload = analysis.to_dict()
        payload["persistence"] = persist_analysis(
            storage, analysis, provider_detail=provider_detail
        )
        results.append(payload)

    return {"count": len(results), "analyses": results}


@app.post("/nhi/slack/inventory/analyze")
def analyze_slack_inventory_from_api() -> Dict[str, Any]:
    """Fetch the configured Slack credential's inventory, analyze it, and persist the result.

    GitHub PAT 엔드포인트(`/nhi/github/inventory/analyze`)와 동일한 단일 결과
    형태다 — `analyze_slack_nhi_from_connector()` 가 기존
    `NHIAnalysisPipeline.analyze_slack_nhi()` 를 그대로 재사용한다.
    """
    try:
        with SlackConnector() as connector:
            analysis, nhi = analyze_slack_nhi_from_connector(
                connector, pipeline=nhi_pipeline
            )
    except ConnectorError as exc:
        raise _http_error(exc)

    provider_detail = {
        "slack": {
            "channels": _slack_channel_records(nhi),
            "channels_error": nhi.channels_error,
        }
    }

    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(
        storage, analysis, provider_detail=provider_detail
    )
    return payload


@app.post("/nhi/aws/inventory/analyze")
def analyze_aws_inventory_from_api() -> Dict[str, Any]:
    """Fetch the configured AWS IAM Access Key inventory, analyze it, and persist the result.

    GitHub PAT/Slack 엔드포인트와 동일한 단일 결과 형태다 —
    `analyze_aws_nhi_from_connector()` 가 기존 `NHIAnalysisPipeline.analyze_aws_nhi()`
    를 그대로 재사용한다. `AWSConnector` 는 `BaseConnector` 를 상속하지 않아
    (SigV4 서명 — boto3 가 직접 처리) 다른 Connector 처럼 `with ... as` 컨텍스트
    매니저로 감싸지 않고 바로 생성한다. `provider_detail` 저장 구조는 아직
    건드리지 않는다 — 응답/저장 모양은 GitHub/Slack 과 동일하다.
    """
    try:
        connector = AWSConnector()
        analysis, nhi = analyze_aws_nhi_from_connector(connector, pipeline=nhi_pipeline)
    except ConnectorError as exc:
        raise _http_error(exc)

    provider_detail = {
        "aws": {
            "access_key_id": nhi.access_key_id,
            "broad_access": nhi.broad_access,
            "policy_fetch_errors": list(nhi.policy_fetch_errors),
        }
    }

    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(
        storage, analysis, provider_detail=provider_detail
    )
    return payload


@app.post("/nhi/inventory/saas/analyze")
def analyze_saas_inventory_nhi(body: SaaSInventoryAnalyzeRequest) -> Dict[str, Any]:
    """Microsoft/Google 등 공급자 중립 SaaS NHI를 기존 정책 엔진으로 분석한다."""
    observation = observation_from_saas_inventory(body.nhi)
    storage.save_observation(observation)
    usage_ingestion = None
    signals = body.signals
    if body.usage_events or body.usage_data_complete:
        signals, usage_ingestion = _signals_from_usage_events(
            nhi_id=body.nhi.nhi_id,
            provider=body.nhi.provider,
            raw_signals=body.signals,
            records=body.usage_events,
            data_complete=body.usage_data_complete,
            source=body.usage_source,
            principal_aliases=body.usage_principal_aliases,
        )
    analysis = nhi_pipeline.analyze_saas_nhi(body.nhi, signals=signals)
    payload = analysis.to_dict()
    payload["persistence"] = persist_analysis(
        storage, analysis, input_revision=observation.source_event_id
    )
    if usage_ingestion is not None:
        payload["usage_ingestion"] = usage_ingestion
    return payload


@app.post("/nhi/usage/normalize")
def normalize_usage_events(body: UsageEventNormalizeRequest) -> Dict[str, Any]:
    """원본 감사 이벤트를 NHI 파이프라인 입력용 AnalysisSignals로 정규화한다."""
    signals, summary = _signals_from_usage_events(
        nhi_id=body.nhi_id,
        provider=body.provider,
        raw_signals=None,
        records=body.events,
        data_complete=body.data_complete,
        source=body.source,
        principal_aliases=body.principal_aliases,
        declared_permissions=body.declared_permissions,
    )
    return {**summary, "signals": signals}


@app.post("/nhi/scopes/translate")
def translate_scopes(body: ScopeTranslateRequest) -> Dict[str, Any]:
    """서비스별 Scope → 공통 권한(Read/Write/Delete/Admin) 변환."""
    profile = ScopeTranslationAgent().translate(
        body.scopes, provider=body.provider, secret_type=body.secret_type
    )
    return profile.to_dict()


# ---------------------------------------------------------------------------
# 회사 AI Agent 접근 기준선 / 위장·범위 초과 API 호출 판정
# ---------------------------------------------------------------------------
def _load_agent_access_profile(agent_id: str) -> Optional[AgentAccessProfile]:
    data = storage.get_agent_access_profile(agent_id)
    if data is None:
        return None
    try:
        return AgentAccessProfile.model_validate(data)
    except ValueError as exc:
        logger.exception("저장된 Agent 접근 기준선 복원 실패 (agent_id=%s)", agent_id)
        raise HTTPException(status_code=500, detail="저장된 Agent 접근 기준선이 올바르지 않습니다.") from exc


@app.get("/agent-access/rules")
def list_agent_access_rules() -> Dict[str, Any]:
    """위장·권한 초과·정보 접근 판정 규칙 카탈로그."""
    rules = agent_access_evaluator.rule_catalog()
    return {"count": len(rules), "rules": rules}


@app.put("/agent-access/profiles/{agent_id}")
def upsert_agent_access_profile(
    agent_id: str,
    body: AgentAccessProfile,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """회사에서 승인한 Agent ↔ NHI ↔ 권한·자원 기준선을 등록·갱신한다."""
    _require_admin_key(x_nhi_admin_key)
    if agent_id != body.agent_id:
        raise HTTPException(status_code=409, detail="URL과 본문의 agent_id가 다릅니다.")
    existing = storage.get_agent_access_profile(agent_id)
    now = datetime.now(timezone.utc).isoformat()
    profile = body.model_copy(
        update={
            "created_at": (
                str(existing.get("created_at"))
                if isinstance(existing, dict) and existing.get("created_at")
                else now
            ),
            "updated_at": now,
        },
        deep=True,
    )
    payload = profile.model_dump(mode="json")
    payload["metadata"] = sanitize_security_value(payload.get("metadata") or {})
    storage.upsert_agent_access_profile(agent_id, payload)
    storage.append_audit_event(
        "AGENT_ACCESS_PROFILE_UPSERTED",
        actor="admin-api",
        target=agent_id,
        detail={
            "grant_count": len(profile.grants),
            "inventory_complete": profile.inventory_complete,
            "require_sender_constraint": profile.require_sender_constraint,
        },
    )
    return payload


@app.get("/agent-access/profiles")
def list_agent_access_profiles(
    limit: int = 100,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """등록된 회사 AI Agent 접근 기준선을 조회한다."""
    _require_admin_key(x_nhi_admin_key)
    profiles = storage.list_agent_access_profiles(limit=min(max(limit, 1), 500))
    return {"count": len(profiles), "profiles": profiles}


@app.get("/agent-access/profiles/{agent_id}/scope")
def get_agent_access_scope(
    agent_id: str,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Agent가 어떤 NHI로 어떤 권한·자원까지 접근 가능한지 요약한다."""
    _require_admin_key(x_nhi_admin_key)
    profile = _load_agent_access_profile(agent_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Agent 접근 기준선을 찾을 수 없습니다.")
    return agent_access_evaluator.summarize_scope(profile)


@app.post("/agent-access/evaluate")
def evaluate_agent_api_access(
    body: AgentApiObservation,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Gateway/Audit Log 호출을 승인 기준선과 비교해 ALLOW/REVIEW/DENY한다.

    악의적 의도 자체를 추측하지 않는다. 인증 주체 불일치, Token/proof 재사용,
    승인 NHI·Credential·권한·자원 초과처럼 검증 가능한 사실만 판정한다.
    """
    _require_admin_key(x_nhi_admin_key)
    profile = _load_agent_access_profile(body.claimed_agent_id)
    decision = agent_access_evaluator.evaluate(profile, body)
    payload = decision.model_dump(mode="json")
    storage.save_agent_access_decision(payload)
    storage.append_audit_event(
        "AGENT_API_ACCESS_EVALUATED",
        actor=body.authenticated_agent_id or "unverified-agent",
        target=body.claimed_agent_id,
        detail={
            "decision_id": decision.decision_id,
            "event_id": decision.event_id,
            "outcome": decision.outcome.value,
            "overall_severity": (
                decision.overall_severity.value if decision.overall_severity else None
            ),
            "rule_ids": [finding.rule_id for finding in decision.findings],
        },
    )
    return payload


@app.get("/agent-access/decisions")
def list_agent_access_decisions(
    agent_id: Optional[str] = None,
    outcome: Optional[AgentAccessOutcome] = None,
    limit: int = 100,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Agent API 접근 판정 이력. outcome=DENY로 위장·범위 초과 후보만 조회 가능."""
    _require_admin_key(x_nhi_admin_key)
    decisions = storage.list_agent_access_decisions(
        agent_id=agent_id,
        outcome=outcome.value if outcome else None,
        limit=min(max(limit, 1), 500),
    )
    return {"count": len(decisions), "decisions": decisions}


# ---------------------------------------------------------------------------
# 분석 Orchestrator — 목표를 받아 계획을 세우고 보안 도구를 고른다
# ---------------------------------------------------------------------------
@app.post("/agent/nhi/run")
def run_analysis_orchestrator(body: NHIAgentRequest) -> Dict[str, Any]:
    """NHI 분석 Orchestrator 실행.

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


@app.post("/connectors/microsoft", status_code=201)
def register_microsoft_connector(body: ConnectorCreateRequest) -> Dict[str, Any]:
    return _register_connector("microsoft", body)


@app.post("/connectors/google", status_code=201)
def register_google_connector(body: ConnectorCreateRequest) -> Dict[str, Any]:
    return _register_connector("google_workspace", body)


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
def list_nhi_inventory(limit: int = 100, provider: Optional[str] = None) -> Dict[str, Any]:
    """NHI 인벤토리 목록.

    `provider` 를 생략하면 기존과 동일하게 전체를 반환한다. 지정하면 정확히
    일치하는 것만 반환하고, 저장된 레코드가 하나도 없는 provider(오타 포함)는
    오류가 아니라 빈 목록으로 처리한다 — provider 값 자체를 검증하는
    허용 목록은 두지 않는다(새 provider 추가 시 이 엔드포인트를 매번 손댈
    필요가 없게 하기 위함).
    """
    records = storage.list_nhi_records(limit=min(max(limit, 1), 500), provider=provider)
    return {"count": len(records), "nhi": records}


@app.get("/nhi/{nhi_id}")
def get_nhi_inventory_item(nhi_id: str) -> Dict[str, Any]:
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")
    return record


@app.post("/nhi/{nhi_id}/dry-run")
def dry_run_nhi_action(nhi_id: str) -> Dict[str, Any]:
    """저장된 NHI 의 `recommended_action` 기준으로, 실제 변경 없이 예상 조치
    결과만 계산한다 (기본 구조). 실제 Credential 폐기/회전/권한 축소 등
    조치 실행과 승인 처리는 이번 단계에서 구현하지 않는다 —
    `agents/dry_run_service.py` 참고.
    """
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")
    return build_dry_run_result(nhi_id, record)


@app.post("/nhi/{nhi_id}/approval-request")
def create_nhi_approval_request(nhi_id: str) -> Dict[str, Any]:
    """NHI 의 현재 `recommended_action` 을 기준으로 승인 요청을 생성한다 (기본 흐름).

    Dry-run 과 마찬가지로 실제 권한 변경은 하지 않는다 — 승인 상태
    (pending/approved/rejected)와 감사 가능한 기록만 남긴다. 승인이 나도
    자동으로 실행되지 않는다(실행 엔진 연결은 이후 별도 단계).
    """
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")

    recommended_action = record.get("recommended_action") or RecommendedAction.MONITOR.value
    approval = storage.create_approval(
        ApprovalRequest(target_nhi_id=nhi_id, recommended_action=recommended_action)
    )
    storage.append_audit_event(
        "APPROVAL_REQUESTED",
        actor="api",
        target=approval.approval_id,
        detail={"target_nhi_id": nhi_id, "recommended_action": recommended_action},
    )
    return approval.to_dict()


@app.get("/approvals")
def list_nhi_approval_requests(limit: int = 100) -> Dict[str, Any]:
    approvals = storage.list_approvals(limit=min(max(limit, 1), 500))
    return {"count": len(approvals), "approvals": [item.to_dict() for item in approvals]}


def _decide_approval(
    approval_id: str,
    body: ApprovalDecisionRequest,
    x_nhi_admin_key: Optional[str],
    *,
    new_status: ApprovalStatus,
    audit_event_type: str,
) -> Dict[str, Any]:
    _require_admin_key(x_nhi_admin_key)
    approval = storage.get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="승인 요청을 찾을 수 없습니다.")
    if approval.status is not ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"이미 처리된 승인 요청입니다 (status={approval.status.value}).",
        )
    approval.status = new_status
    approval.decided_at = datetime.now(timezone.utc).isoformat()
    storage.update_approval(approval)
    storage.append_audit_event(
        audit_event_type,
        actor=body.actor,
        target=approval.approval_id,
        detail={
            "target_nhi_id": approval.target_nhi_id,
            "recommended_action": approval.recommended_action,
            "reason": body.reason,
        },
    )
    return approval.to_dict()


@app.post("/approvals/{approval_id}/approve")
def approve_nhi_approval_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """승인 요청을 승인 상태로 전이한다. 실제 권한 변경은 수행하지 않는다."""
    return _decide_approval(
        approval_id,
        body,
        x_nhi_admin_key,
        new_status=ApprovalStatus.APPROVED,
        audit_event_type="APPROVAL_GRANTED",
    )


@app.post("/approvals/{approval_id}/reject")
def reject_nhi_approval_request(
    approval_id: str,
    body: ApprovalDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """승인 요청을 거부 상태로 전이한다."""
    return _decide_approval(
        approval_id,
        body,
        x_nhi_admin_key,
        new_status=ApprovalStatus.REJECTED,
        audit_event_type="APPROVAL_REJECTED",
    )


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
# GitHub / Microsoft 365 / Google Workspace NHI Discovery
# ---------------------------------------------------------------------------
def _github_agent_run_summary(
    state,
    *,
    persistence_succeeded: int,
    persistence_failures: Sequence[Dict[str, str]],
) -> Dict[str, Any]:
    """민감하거나 큰 원문 없이 GitHub 수집 Agent 실행을 감사 가능한 형태로 요약한다."""
    collection = state.github_collection_result or {}
    scan = state.secret_scan_result or {}
    analyses = state.inventory_analyses
    inventory = state.collected_inventory
    repository_complete = sum(
        1 for item in inventory if item.repository_inventory_complete
    )
    security_event_count = sum(len(item.security_events) for item in analyses)
    scenario_count = sum(len(item.scenario_matches) for item in analyses)
    forced_critical_count = sum(
        1
        for analysis in analyses
        for scenario in analysis.scenario_matches
        if scenario.forced_critical
    )
    plan = [
        {
            "step": action.step,
            "action_type": action.action_type.value,
            "created_by": action.created_by.value,
            "completed": action.completed,
            "failed": action.failed,
            "reason": sanitize_security_text(action.reason),
            "error_message": (
                sanitize_security_text(action.error_message)
                if action.error_message
                else None
            ),
        }
        for action in state.plan
    ]
    return {
        "kind": "github_inventory_agent_run",
        "organization": getattr(state.request, "organization", "unknown"),
        "status": state.status.value,
        "replan_count": state.replan_count,
        "replan_notes": [sanitize_security_text(note) for note in state.replan_notes],
        "plan": plan,
        "collection": {
            "count": collection.get("count", len(inventory)),
            "total_count": collection.get("total_count"),
            "pages_fetched": collection.get("pages_fetched", 0),
            "inventory_complete": collection.get("inventory_complete") is True,
            "retrieval_truncated": collection.get("truncated") is True,
            "failure_count": len(collection.get("failures") or []),
            "coverage_note": sanitize_security_text(collection.get("coverage_note")),
        },
        "repository_coverage": {
            "complete_count": repository_complete,
            "incomplete_count": len(inventory) - repository_complete,
            "note": (
                "미수집 저장소 범위는 0개 접근이 아니라 UNKNOWN으로 해석한다."
            ),
        },
        "analysis": {
            "count": len(analyses),
            "usage_complete_count": sum(
                1 for item in analyses if item.usage_analysis.data_complete
            ),
            "event_count": security_event_count,
            "scenario_count": scenario_count,
            "forced_critical_count": forced_critical_count,
        },
        "secret_scan": {
            "scan_executed": scan.get("scan_executed"),
            "scan_complete": scan.get("scan_complete") is True,
            "planned": scan.get("repository_count_planned", 0),
            "scanned": scan.get("repository_count_scanned", 0),
            "failed": scan.get("repository_count_failed", 0),
            "skipped": scan.get("repository_count_skipped", 0),
            "finding_count": scan.get("finding_count"),
            "reason": sanitize_security_text(scan.get("reason")),
        },
        "persistence": {
            "succeeded": persistence_succeeded,
            "failed": len(persistence_failures),
            "complete": not persistence_failures,
            "failures": list(persistence_failures),
        },
    }


@app.post("/integrations/github/discover")
def discover_github_nhi(
    body: GitHubInventoryAgentRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """조직의 GitHub App installation을 수집하고 선택적으로 전건 분석한다.

    서버 설정의 수집 전용 ``GITHUB_INVENTORY_TOKEN``만 사용한다. 조직 계정은
    installation 대상일 뿐 보안 Owner가 아니므로 Owner로 자동 지정하지 않는다.
    """
    _require_admin_key(x_nhi_admin_key)
    registry = build_tool_registry(
        collection_connector_factory=GitHubConnector.for_inventory,
        connector_factory=GitHubConnector,
    )
    state = run_nhi_agent(body, registry=registry)
    if state.status.value == "FAILED":
        raise HTTPException(
            status_code=state.error_status_code or 502,
            detail=state.error_message or "GitHub 조직 인벤토리 Agent 실행 실패",
        )

    payload = state.to_dict()
    analyses_by_nhi_id = {
        analysis.profile.nhi_id: analysis for analysis in state.inventory_analyses
    }
    observation_ids: List[str] = []
    persistence: List[Dict[str, Any]] = []
    persistence_failures: List[Dict[str, str]] = []
    for item in state.collected_inventory:
        try:
            observation = observation_from_inventory(item)
            observation_ids.append(storage.save_observation(observation))
        except Exception as exc:  # 실행 전체를 성공처럼 숨기지 않고 item 단위로 보고한다.
            logger.exception("GitHub inventory observation 저장 실패: %s", item.nhi_id)
            persistence_failures.append(
                {
                    "nhi_id": item.nhi_id,
                    "stage": "observation",
                    "error": type(exc).__name__,
                }
            )
            continue
        analysis = analyses_by_nhi_id.get(f"github:{item.nhi_id}")
        if analysis is None:
            if body.analyze:
                persistence_failures.append(
                    {
                        "nhi_id": item.nhi_id,
                        "stage": "analysis",
                        "error": "AnalysisMissing",
                    }
                )
            continue
        try:
            saved = persist_analysis(
                storage, analysis, input_revision=observation.source_event_id
            )
            persistence.append({"nhi_id": item.nhi_id, **saved})
        except Exception as exc:
            logger.exception("GitHub inventory analysis 저장 실패: %s", item.nhi_id)
            persistence_failures.append(
                {
                    "nhi_id": item.nhi_id,
                    "stage": "analysis",
                    "error": type(exc).__name__,
                }
            )
    run_summary = _github_agent_run_summary(
        state,
        persistence_succeeded=len(persistence),
        persistence_failures=persistence_failures,
    )
    audit_event_id = storage.append_audit_event(
        "GITHUB_INVENTORY_AGENT_COMPLETED",
        actor="github-inventory-agent",
        target=body.organization,
        detail=run_summary,
    )
    payload["observation_ids"] = observation_ids
    payload["persistence"] = persistence
    payload["persistence_failures"] = persistence_failures
    payload["run_summary"] = run_summary
    payload["audit_event_id"] = audit_event_id
    return payload


def _persist_discovered_inventory(
    items: Sequence[SaaSNHIInput], *, analyze: bool
) -> Dict[str, Any]:
    inventory: List[Dict[str, Any]] = []
    analyses: List[Dict[str, Any]] = []
    observation_ids: List[str] = []
    for item in items:
        observation = observation_from_saas_inventory(item)
        observation_ids.append(storage.save_observation(observation))
        inventory.append(item.model_dump(mode="json"))
        if analyze:
            analysis = nhi_pipeline.analyze_saas_nhi(item)
            payload = analysis.to_dict()
            payload["persistence"] = persist_analysis(
                storage, analysis, input_revision=observation.source_event_id
            )
            analyses.append(payload)
    return {
        "count": len(inventory),
        "inventory": inventory,
        "analyzed": analyze,
        "analyses": analyses,
        "observation_ids": observation_ids,
    }


@app.post("/integrations/microsoft/discover")
def discover_microsoft_nhi(
    body: MicrosoftDiscoveryRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Microsoft Graph에서 service principal과 OAuth/API 권한을 읽기 전용 수집한다."""
    _require_admin_key(x_nhi_admin_key)
    try:
        with MicrosoftGraphConnector() as connector:
            items = connector.discover_service_principals(limit=body.limit)
    except ConnectorError as exc:
        raise _http_error(exc)
    payload = _persist_discovered_inventory(items, analyze=body.analyze)
    payload["inventory_complete"] = False
    payload["coverage_note"] = (
        f"Microsoft Graph service principal 최대 {body.limit}건과 조회 가능한 권한·Owner 기준이며, "
        "전사 전체 인벤토리 snapshot으로 단정하지 않습니다."
    )
    return payload


@app.post("/integrations/google/discover")
def discover_google_nhi(
    body: GoogleDiscoveryRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Google Workspace OAuth Token 감사 이벤트를 Client ID별로 읽기 전용 수집한다."""
    _require_admin_key(x_nhi_admin_key)
    try:
        with GoogleWorkspaceConnector() as connector:
            items = connector.discover_oauth_clients(
                max_events=body.max_events,
                start_time=body.start_time,
            )
    except ConnectorError as exc:
        raise _http_error(exc)
    payload = _persist_discovered_inventory(items, analyze=body.analyze)
    payload["coverage_note"] = (
        "Google Admin Reports API 보존 기간 안에서 관측된 OAuth 이벤트 기준이며 "
        "전체 현재 토큰 인벤토리로 단정하지 않습니다."
    )
    return payload


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
@app.post("/integrations/slack/verify")
def verify_slack_token(
    body: SlackVerifyRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """서버에 설정된 Slack Token의 유효성·Scope·접근 가능 채널을 조회한다.

    Token을 요청 body로 받으면 access log/APM에 원문이 남을 수 있으므로 허용하지 않는다.
    """
    _require_admin_key(x_nhi_admin_key)
    token = get_settings().slack.bot_token
    if not token:
        raise HTTPException(status_code=503, detail="SLACK_BOT_TOKEN이 설정되지 않았습니다.")
    try:
        with SlackConnector(token) as slack:
            status = slack.validate_credential()
            payload = status.to_dict()
            if status.active:
                payload["bot"] = slack.get_bot_info()
                payload["app"] = slack.get_app_info()
                payload["workspace"] = slack.get_workspace_info()
    except ConnectorError as exc:
        raise _http_error(exc)
    return payload


@app.get("/integrations/slack/channels")
def slack_channels(
    request: Request,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """서버에 설정된 Slack Token으로 접근 가능한 채널을 조회한다."""
    _require_admin_key(x_nhi_admin_key)
    if request.query_params:
        raise HTTPException(
            status_code=400,
            detail="Slack Token 또는 설정값을 query parameter로 전달할 수 없습니다.",
        )
    token = get_settings().slack.bot_token
    if not token:
        raise HTTPException(status_code=503, detail="SLACK_BOT_TOKEN이 설정되지 않았습니다.")
    try:
        with SlackConnector(token) as slack:
            channels = slack.list_channels()
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
_competition_dashboard_dir = (
    Path(__file__).resolve().parents[1] / "frontend" / "competition_dashboard"
)
app.mount(
    "/competition",
    StaticFiles(directory=str(_competition_dashboard_dir), html=True),
    name="competition-dashboard",
)

_dashboard_dir = Path(__file__).resolve().parents[1] / "frontend" / "dashboard"
app.mount(
    "/dashboard",
    StaticFiles(directory=str(_dashboard_dir), html=True),
    name="dashboard",
)
