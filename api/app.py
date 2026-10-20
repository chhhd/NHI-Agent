"""FastAPI 애플리케이션 — 시스템의 단일 진입점.

    /repositories, /scans, /rescans, /webhooks/github   저장소 연동 + Secret 탐지
    /nhi/*                                              NHI 위험 분석
    /agent/nhi/run                                      Agent 실행 (계획 → 도구 실행)
    /control/*                                          실시간 통제 (인가 질의 · 이벤트 판정 · 격리)
    /changes/*                                          변경 승인 (영향도 미리보기 · 승인 · 롤백)
    /lifecycle/*                                        NHI 생명주기 (생성 → 사용 → 권한변경 → 종료 → 파기)

실행:
    uvicorn api.app:app --reload --port 8000

Webhook 등록 시 GitHub 쪽 Payload URL 은 `POST /webhooks/github` 이다.
"""

from __future__ import annotations

import logging
import hmac
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from agent_runtime.models import GitHubInventoryAgentRequest, NHIAgentRequest
from agent_runtime.orchestrator import run_nhi_agent
from agent_runtime.tools import build_tool_registry
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
from connectors.google_workspace_connector import GoogleWorkspaceConnector
from connectors.microsoft_graph_connector import MicrosoftGraphConnector
from connectors.github_webhook import GitHubWebhookHandler, WebhookVerificationError
from connectors.slack_connector import SlackConnector
from core.inventory_models import GitHubNHIInput, SaaSNHIInput
from core.models import ScanResult, ScanTrigger, SecretFinding
from core.nhi_models import AnalysisSignals, NHIAnalysisReport, NHIType
from core.action_models import ActionStatus
from core.observation_models import CredentialObservation, Evidence
from core.config import get_settings
from normalization import (
    observation_from_finding,
    observation_from_inventory,
    observation_from_saas_inventory,
)
from processing import ActionService, persist_analysis, persist_report
from rescan.credential_verifier import CredentialVerifier
from rescan.revalidator import Revalidator
from normalization.usage_ingestion import signals_from_usage_events as _signals_from_usage_events
from scanner.scan_service import SecretScanService
from security.admin_identity import (
    OPERATOR_ROLES,
    AdminDirectory,
    AdminIdentity,
    AdminIdentityError,
)
from security.dpop import RuntimeTokenService, TokenBindingError
from security.redaction import sanitize_security_text
from security.replay_store import StorageReplayCache
from storage import Storage, get_default_storage
from backend.models.entities import (
    ConnectorRecord,
    ConnectorStatus,
    FindingStatus,
    ProjectRecord,
)
from backend.services.analysis_history import AnalysisHistoryService
from backend.services.github_continuous_assessment import (
    GitHubContinuousAssessmentService,
)
from backend.services.change_control_service import (
    ApproverNotAuthorized,
    ChangeControlService,
    ChangeError,
    ChangeExecutionError,
    ChangeNotAllowed,
    SeparationOfDutiesError,
)
from backend.services.agent_access_evaluator import AgentAccessEvaluator
from backend.services.control_approval import ApprovalError
from backend.services.control_service import ControlService
from backend.services.nhi_aging import NHIAgingService
from core.agent_access_models import AgentAccessProfile, AgentApiObservation
from core.governance_models import utcnow
from backend.services.demo_workspace import (
    clear_demo_workspace,
    seed_demo_workspace,
)
from backend.services.lifecycle_service import LifecycleError, LifecycleService
from backend.services.nhi_state import is_demo, load_nhi
from core.governance_models import ChangeStatus, ChangeType, ControlEventType

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


class SaaSInventoryAnalyzeRequest(BaseModel):
    """공급자 중립 SaaS NHI 분석 요청."""

    nhi: SaaSNHIInput
    signals: Optional[Dict[str, Any]] = None
    usage_events: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)
    usage_data_complete: bool = False
    usage_source: str = Field(default="audit_log", min_length=1, max_length=100)
    usage_principal_aliases: List[str] = Field(default_factory=list, max_length=20)


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


class GitHubContinuousAssessmentRequest(BaseModel):
    """GitHub 인벤토리와 Audit Log를 한 번에 수집·재평가한다."""

    organization: str = Field(
        ...,
        min_length=1,
        max_length=39,
        pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$",
    )
    inventory_limit: int = Field(default=100, ge=1, le=500)
    audit_limit: int = Field(default=1000, ge=1, le=10000)
    since: Optional[str] = Field(
        default=None,
        description="ISO 8601 시작 시각. 생략하면 저장된 checkpoint 또는 최근 24시간.",
    )
    signals: Optional[Dict[str, Any]] = None
    signals_by_nhi_id: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")


class RuntimeTokenIssueRequest(BaseModel):
    """연구 경로에서 관리자 요청의 Agent ID에 DPoP-bound 단기 token을 발급한다."""

    agent_id: str = Field(..., min_length=1, max_length=200)
    scopes: List[str] = Field(default_factory=lambda: ["runtime:invoke"])


class UsageEventNormalizeRequest(BaseModel):
    """공급자별 Audit Log를 공통 UsageEvent와 AnalysisSignals로 변환한다."""

    nhi_id: str = Field(..., min_length=1, max_length=300)
    principal_aliases: List[str] = Field(default_factory=list, max_length=20)
    provider: str = Field(default="generic", min_length=1, max_length=100)
    source: str = Field(default="audit_log", min_length=1, max_length=100)
    declared_permissions: List[str] = Field(default_factory=list, max_length=100)
    events: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)
    data_complete: bool = False


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


class CredentialVerifyRequest(BaseModel):
    full_name: str
    fingerprint: str


class ActionDecisionRequest(BaseModel):
    #: 개인 관리자 키를 쓰면 생략한다(키의 관리자 ID 가 쓰인다). 다른 이름을 적으면 403.
    actor: Optional[str] = Field(default=None, min_length=1)
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


def _directory() -> AdminDirectory:
    settings = get_settings()
    return AdminDirectory(
        storage,
        bootstrap_key=settings.secret_storage.admin_api_key,
        require_verified=settings.governance.require_verified_admin,
    )


def _authenticate_admin(provided: Optional[str]) -> AdminIdentity:
    try:
        return _directory().authenticate(provided)
    except AdminIdentityError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)


def _require_admin_key(provided: Optional[str]) -> AdminIdentity:
    """유효한 관리자 키(공유 키 또는 개인 키)인지만 확인한다. `actor` 가 필요 없는 작업용."""
    return _authenticate_admin(provided)


def _acting_admin(
    provided: Optional[str],
    declared_actor: Optional[str],
    *,
    roles: Optional[Sequence[str]] = tuple(OPERATOR_ROLES),
) -> Tuple[str, AdminIdentity]:
    """`actor` 가 필요한 작업의 신원 확정.

    - 개인 키: `actor` 는 키의 관리자 ID 로 정해진다. 본문에 다른 이름을 적으면 403.
    - 공유 키(bootstrap): 개인 계정이 있거나 strict 설정이면 거부(403). 그렇지 않은 초기 구성에서만
      본문 `actor` 를 쓰며, 이때 `identity.verified=false` 로 감사에 남는다.
    """
    identity = _authenticate_admin(provided)
    if identity.verified:
        if declared_actor and declared_actor.strip() != identity.admin_id:
            raise HTTPException(
                status_code=403,
                detail=f"actor '{declared_actor}' 는 인증된 관리자 '{identity.admin_id}' 와 다릅니다.",
            )
        if roles and not identity.has_any(roles):
            raise HTTPException(
                status_code=403,
                detail=f"이 작업은 {'/'.join(sorted(roles))} 역할이 필요합니다 (보유: {', '.join(sorted(identity.roles))}).",
            )
        return identity.admin_id, identity
    if _directory().strict:
        raise HTTPException(
            status_code=403,
            detail="개인 관리자 키(nhik.…)가 필요합니다. 공유 키는 관리자 계정 관리 전용입니다.",
        )
    if not declared_actor or not declared_actor.strip():
        raise HTTPException(status_code=422, detail="actor 가 필요합니다.")
    return declared_actor.strip(), identity


def _acting_admin_unless_demo(
    nhi_id: str,
    provided: Optional[str],
    declared_actor: Optional[str],
    *,
    roles: Optional[Sequence[str]] = tuple(OPERATOR_ROLES),
) -> Tuple[str, AdminIdentity]:
    """합성 데모 NHI 는 관리자 키 없이 체험할 수 있다. 키를 보냈다면 그대로 검증한다."""
    if not provided and is_demo(_nhi_or_404(nhi_id)):
        actor = (declared_actor or "demo-user").strip()
        return actor, AdminIdentity(actor, frozenset(), False, "demo")
    return _acting_admin(provided, declared_actor, roles=roles)


def _roles_for(identity: AdminIdentity) -> Optional[List[str]]:
    """개인 키로 확정된 신원만 역할을 서비스 계층에 전달한다(공유 키는 역할을 알 수 없다)."""
    return sorted(identity.roles) if identity.verified else None


#: 재전송·키 불일치로 보는 DPoP 거부 코드 (탈취된 Token/proof 재사용 의심)
_REPLAY_SUSPECT_CODES = frozenset(
    {"dpop_proof_replay", "sender_key_mismatch", "dpop_token_hash_mismatch"}
)


def _runtime_replay_cache() -> StorageReplayCache:
    """proof jti 단일 사용을 저장소에 기록한다 — 프로세스 재시작·다중 워커 사이에서도 유지된다."""
    return StorageReplayCache(storage)


def _runtime_token_service() -> RuntimeTokenService:
    settings = get_settings().runtime_security
    return RuntimeTokenService(
        signing_key=settings.token_signing_key,
        issuer=settings.issuer,
        audience=settings.audience,
        token_ttl_seconds=settings.token_ttl_seconds,
        proof_max_age_seconds=settings.dpop_proof_max_age_seconds,
        clock_skew_seconds=settings.dpop_clock_skew_seconds,
        replay_cache=_runtime_replay_cache(),
    )


def _issuing_admin(provided: Optional[str]) -> AdminIdentity:
    """Agent 에 token 을 발급할 수 있는 관리자. 개인 계정 모드에서는 공유 키로 발급할 수 없다."""
    identity = _authenticate_admin(provided)
    if identity.verified:
        if not identity.has_any(OPERATOR_ROLES):
            raise HTTPException(status_code=403, detail="Agent token 발급 권한이 없습니다.")
    elif _directory().strict:
        raise HTTPException(
            status_code=403,
            detail="개인 관리자 키(nhik.…)가 필요합니다. 공유 키는 관리자 계정 관리 전용입니다.",
        )
    return identity


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
    replay_suspected = exc.code in _REPLAY_SUSPECT_CODES
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
            "github_continuous_assessment": "POST /integrations/github/continuous-assessment",
            "agent": "POST /agent/nhi/run",
            "change_preview": "POST /changes/preview",
            "realtime_authorize": "POST /control/authorize",
            "lifecycle": "GET /lifecycle",
            "dashboard": "GET /dashboard/",
            "docs": "GET /docs",
        },
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
    issuer = _issuing_admin(x_nhi_admin_key)
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
            "issued_by": issuer.admin_id,
            "issuer_verified": issuer.verified,
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


# `/nhi/{owner}/{repo}` 와 경로 모양이 같으므로 반드시 그보다 먼저 등록해야 가려지지 않는다.
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
    actor, _ = _acting_admin(x_nhi_admin_key, body.actor)
    try:
        action = ActionService(storage).approve(action_id, actor=actor)
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
    actor, _ = _acting_admin(x_nhi_admin_key, body.actor)
    try:
        action = ActionService(storage).cancel(
            action_id, actor=actor, reason=body.reason
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
        action = ActionService(storage).approve(action_id, actor=body.actor or "demo-user")
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
            action_id, actor=body.actor or "demo-user", reason=body.reason
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
# 거버넌스 — 실시간 통제 · 변경 승인 · 생명주기
# ---------------------------------------------------------------------------
class ChangePreviewRequest(BaseModel):
    nhi_id: str = Field(..., min_length=1)
    change_type: ChangeType
    #: TOKEN_ROTATE: grace_period_hours / SCOPE_CHANGE: target_permissions, target_scopes
    params: Dict[str, Any] = Field(default_factory=dict)


class ChangeProposeRequest(ChangePreviewRequest):
    requested_by: Optional[str] = Field(default=None, min_length=1)
    reason: str = ""


class ChangeDecisionRequest(BaseModel):
    actor: Optional[str] = Field(default=None, min_length=1)
    reason: str = ""
    #: CRITICAL 등급은 변경 전·후 형상과 영향도를 확인했음을 명시해야 승인된다.
    acknowledge_impact: bool = False
    #: TOKEN_DISPOSE(파기) 승인에 필요하다: method, verified_by(수행자와 다른 사람), verification_check,
    #: verification_result(AUTH_REJECTED_401/403 · NOT_FOUND_404 · MATERIAL_ABSENT), performed_by(생략 시 승인자)
    destruction_evidence: Optional[Dict[str, Any]] = None


class LifecycleAdvanceRequest(BaseModel):
    actor: Optional[str] = Field(default=None, min_length=1)
    reason: str = ""


class ControlEventRequest(BaseModel):
    nhi_id: str = Field(..., min_length=1)
    event_type: ControlEventType
    #: permission, resource, source_ip, requests_per_min, baseline_per_min ...
    attributes: Dict[str, Any] = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    nhi_id: str = Field(..., min_length=1)
    permission: str = Field(..., min_length=1, examples=["WRITE"])
    resource: Optional[str] = None
    source_ip: Optional[str] = None


class QuarantineRequest(BaseModel):
    actor: Optional[str] = Field(default=None, min_length=1)
    reason: str = ""


def _change_service() -> ChangeControlService:
    return ChangeControlService(storage)


def _control_service() -> ControlService:
    return ControlService(storage, changes=_change_service())


def _lifecycle_service() -> LifecycleService:
    return LifecycleService(storage)


def _nhi_or_404(nhi_id: str) -> Dict[str, Any]:
    try:
        return load_nhi(storage, nhi_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")


def _require_admin_unless_demo(nhi_id: str, provided: Optional[str]) -> None:
    """합성 데모 NHI 는 관리자 키 없이 체험할 수 있다 (기존 /demo/reviews 와 같은 규칙)."""
    if not is_demo(_nhi_or_404(nhi_id)):
        _require_admin_key(provided)


def _governance_http(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail="NHI 또는 변경 요청을 찾을 수 없습니다.")
    if isinstance(exc, (SeparationOfDutiesError, ApproverNotAuthorized)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ChangeNotAllowed):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ChangeExecutionError):
        return HTTPException(status_code=502, detail=str(exc))
    if isinstance(exc, (ChangeError, LifecycleError)):
        return HTTPException(status_code=409, detail=str(exc))
    raise exc


def _change_nhi_id(change_id: str) -> str:
    change = storage.get_change_request(change_id)
    if change is None:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")
    return change.nhi_id


def _checked_evidence(evidence: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """개인 계정 모드에서는 검증자가 실제 등록된 관리자여야 한다(이름만 적은 검증을 막는다)."""
    if not evidence or not _directory().strict:
        return evidence
    verifier = str(evidence.get("verified_by") or "").strip().lower()
    principal = storage.get_admin_principal(verifier)
    if principal is None or principal.get("disabled"):
        raise HTTPException(
            status_code=422,
            detail="개인 관리자 모드에서는 verified_by 가 등록된 활성 관리자여야 합니다.",
        )
    return {**evidence, "verified_by": verifier}


class AgingRunRequest(BaseModel):
    #: 개인 관리자 키를 쓰면 생략한다.
    actor: Optional[str] = Field(default=None, min_length=1)
    nhi_ids: Optional[List[str]] = None
    #: false 면 대상만 계산하고 변경 요청을 만들지 않는다.
    create_changes: bool = True


def _aging_service() -> NHIAgingService:
    return NHIAgingService(storage, changes=_change_service())


# `/lifecycle/{nhi_id}` 보다 먼저 등록해야 "aging" 이 NHI ID 로 해석되지 않는다.
@app.get("/lifecycle/aging")
def lifecycle_aging_candidates() -> Dict[str, Any]:
    """종료·파기 승인 요청 대상(장기 미사용, 보존 기간 경과)을 계산만 한다."""
    items = _aging_service().candidates()
    return {"count": len(items), "items": items}


@app.post("/lifecycle/aging/run")
def lifecycle_aging_run(
    body: AgingRunRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """기준일을 넘긴 NHI 마다 종료·파기 승인 요청을 만든다. 자동으로 종료·파기하지 않는다."""
    if body.create_changes:
        actor, _ = _acting_admin(x_nhi_admin_key, body.actor)
    else:  # 대상 계산만 하는 실행은 변경을 만들지 않으므로 유효한 관리자 키면 충분하다
        actor = _authenticate_admin(x_nhi_admin_key).admin_id
    return _aging_service().run(
        triggered_by=actor, create_changes=body.create_changes, nhi_ids=body.nhi_ids
    )


@app.get("/lifecycle")
def lifecycle_report() -> Dict[str, Any]:
    """생성 → 사용 → 권한 변경 → 종료 → 파기 단계별 NHI 분포와 노후화 경보."""
    return _lifecycle_service().report()


@app.get("/lifecycle/{nhi_id}")
def lifecycle_view(nhi_id: str) -> Dict[str, Any]:
    try:
        return _lifecycle_service().view(nhi_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")


@app.post("/lifecycle/{nhi_id}/advance")
def lifecycle_advance(
    nhi_id: str,
    body: LifecycleAdvanceRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """생성 → 사용 활성화, 권한 변경 관찰 종료 → 사용 복귀. 종료·파기는 /changes 로 진행한다."""
    actor, _ = _acting_admin_unless_demo(nhi_id, x_nhi_admin_key, body.actor)
    try:
        result = _lifecycle_service().advance(nhi_id, actor=actor, reason=body.reason)
    except (KeyError, LifecycleError) as exc:
        raise _governance_http(exc)
    storage.append_audit_event(
        "LIFECYCLE_ADVANCED",
        actor=actor,
        target=nhi_id,
        detail={
            "stage": result["stage"],
            "reason": body.reason,
            **({"demo_workspace": True} if result.get("demo_workspace") else {}),
        },
    )
    return result


@app.post("/changes/preview")
def preview_change(body: ChangePreviewRequest) -> Dict[str, Any]:
    """변경 전·후 형상, 영향 범위, 서비스 연속성 위험, 승인 등급, 롤백 계획 (저장 안 함)."""
    try:
        return _change_service().preview(body.nhi_id, body.change_type, body.params)
    except (KeyError, ChangeError) as exc:
        raise _governance_http(exc)


@app.post("/changes", status_code=201)
def propose_change(
    body: ChangeProposeRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """폐기·교체·권한 변경·파기를 제안한다. LOW 등급만 즉시 적용되고 나머지는 승인을 기다린다."""
    actor, identity = _acting_admin_unless_demo(body.nhi_id, x_nhi_admin_key, body.requested_by)
    try:
        change = _change_service().propose(
            body.nhi_id,
            body.change_type,
            requested_by=actor,
            requested_verified=identity.verified,
            reason=body.reason,
            params=body.params,
        )
    except (KeyError, ChangeError, LifecycleError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


@app.get("/changes")
def list_changes(
    status: Optional[ChangeStatus] = None, nhi_id: Optional[str] = None, limit: int = 100
) -> Dict[str, Any]:
    changes = _change_service().list(
        status=status, nhi_id=nhi_id, limit=min(max(limit, 1), 500)
    )
    return {"count": len(changes), "changes": [change.to_dict() for change in changes]}


@app.get("/changes/{change_id}")
def get_change(change_id: str) -> Dict[str, Any]:
    try:
        return _change_service().get(change_id).to_dict()
    except KeyError as exc:
        raise _governance_http(exc)


@app.post("/changes/{change_id}/approve")
def approve_change(
    change_id: str,
    body: ChangeDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """승인 즉시 적용한다. HIGH 이상은 요청자와 다른 관리자만, CRITICAL 은 영향도 확인이 필요하다."""
    actor, identity = _acting_admin_unless_demo(
        _change_nhi_id(change_id), x_nhi_admin_key, body.actor
    )
    try:
        change = _change_service().approve(
            change_id,
            actor=actor,
            verified=identity.verified,
            roles=_roles_for(identity),
            destruction_evidence=_checked_evidence(body.destruction_evidence),
            reason=body.reason,
            acknowledge_impact=body.acknowledge_impact,
        )
    except (KeyError, ChangeError, LifecycleError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


@app.post("/changes/{change_id}/reject")
def reject_change(
    change_id: str,
    body: ChangeDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    actor, _ = _acting_admin_unless_demo(
        _change_nhi_id(change_id), x_nhi_admin_key, body.actor
    )
    try:
        change = _change_service().reject(change_id, actor=actor, reason=body.reason)
    except (KeyError, ChangeError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


@app.post("/changes/{change_id}/rollback")
def rollback_change(
    change_id: str,
    body: ChangeDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """적용된 변경을 변경 전 형상으로 되돌려 서비스 연속성을 확보한다."""
    actor, _ = _acting_admin_unless_demo(
        _change_nhi_id(change_id), x_nhi_admin_key, body.actor
    )
    try:
        change = _change_service().rollback(change_id, actor=actor, reason=body.reason)
    except (KeyError, ChangeError, LifecycleError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


@app.post("/control/authorize")
def control_authorize(
    body: AuthorizeRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """집행 지점이 요청을 통과시키기 전에 묻는 실시간 인가 질의.

    `allowed=false` 면 호출자는 요청을 차단해야 한다. monitor 모드에서는 판정만
    기록하고 항상 `allowed=true` 를 돌려준다.
    """
    _require_admin_unless_demo(body.nhi_id, x_nhi_admin_key)
    try:
        return _control_service().authorize(
            body.nhi_id, body.permission, resource=body.resource, source_ip=body.source_ip
        )
    except (KeyError, ChangeError) as exc:
        raise _governance_http(exc)


@app.put("/agent-access/profiles/{agent_id}")
def put_agent_access_profile(
    agent_id: str,
    body: AgentAccessProfile,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """회사 AI Agent 의 승인 NHI·Credential·권한·자원 기준선을 등록·갱신한다."""
    _require_admin_key(x_nhi_admin_key)
    if body.agent_id != agent_id:
        raise HTTPException(status_code=422, detail="경로의 agent_id 와 본문이 다릅니다.")
    previous = storage.get_agent_access_profile(agent_id)
    profile = body.model_copy(
        update={
            "created_at": previous["created_at"] if previous else body.created_at,
            "updated_at": utcnow(),
        }
    )
    storage.save_agent_access_profile(profile.model_dump(mode="json"))
    storage.append_audit_event(
        "AGENT_ACCESS_PROFILE_SAVED",
        actor="admin-api",
        target=agent_id,
        detail={"grants": len(profile.grants), "inventory_complete": profile.inventory_complete},
    )
    return profile.model_dump(mode="json")


@app.get("/agent-access/profiles")
def list_agent_access_profiles(limit: int = 100) -> Dict[str, Any]:
    profiles = storage.list_agent_access_profiles(limit=min(max(limit, 1), 500))
    return {"count": len(profiles), "profiles": profiles}


@app.get("/agent-access/profiles/{agent_id}")
def get_agent_access_profile(agent_id: str) -> Dict[str, Any]:
    profile = storage.get_agent_access_profile(agent_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Agent 기준선을 찾을 수 없습니다.")
    return profile


@app.get("/agent-access/profiles/{agent_id}/scope")
def get_agent_access_scope(agent_id: str) -> Dict[str, Any]:
    """Agent 가 NHI 를 통해 실제로 닿을 수 있는 범위와 기준선의 사각지대."""
    profile = storage.get_agent_access_profile(agent_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Agent 기준선을 찾을 수 없습니다.")
    return AgentAccessEvaluator().summarize_scope(AgentAccessProfile.model_validate(profile))


@app.get("/agent-access/rules")
def agent_access_rules() -> Dict[str, Any]:
    rules = AgentAccessEvaluator.rule_catalog()
    return {"count": len(rules), "rules": rules}


class AgentSenderEvidence(BaseModel):
    """Gateway 가 Agent 요청에서 그대로 전달한 DPoP 증거.

    Gateway 가 "sender proof 가 유효했다"고 **주장**하게 하지 않고, 원문 증거를 받아 이 서버가
    직접 검증한다. `http_method`/`http_url` 은 Agent 가 호출한 **원래** 요청의 것이다.
    """

    authorization: str = Field(..., min_length=1, max_length=33000, description="`DPoP <access token>`")
    dpop_proof: str = Field(..., min_length=1, max_length=33000)
    http_method: str = Field(..., min_length=1, max_length=16)
    http_url: str = Field(..., min_length=1, max_length=2000, description="query/fragment 제외 원래 URL")


class AgentCallRequest(AgentApiObservation):
    #: 있으면 아래 필드를 서버 검증 결과로 덮어쓴다: authenticated_agent_id, sender_constrained,
    #: binding_method, sender_proof_valid, token_replay_suspected(호출자가 true 로 보낸 값은 유지)
    sender_evidence: Optional[AgentSenderEvidence] = None


def _apply_sender_evidence(
    observation: AgentApiObservation, evidence: AgentSenderEvidence
) -> AgentApiObservation:
    """DPoP 증거를 검증해 신뢰할 수 있는 신원·sender 필드로 관측을 만든다.

    실패하면 인증된 Agent 를 비우고(호출자가 적은 값은 신뢰하지 않는다) `sender_proof_valid=false`
    로 두어 평가기가 SENDER_PROOF_INVALID 로 차단하게 한다. 재전송·키 불일치 코드는
    `token_replay_suspected` 도 켠다.
    """
    try:
        principal = _runtime_token_service().authorize(
            authorization=evidence.authorization,
            dpop_proof=evidence.dpop_proof,
            method=evidence.http_method,
            htu=evidence.http_url,
        )
    except TokenBindingError as exc:
        return observation.model_copy(
            update={
                "authenticated_agent_id": None,
                "sender_constrained": True,
                "binding_method": "DPoP",
                "sender_proof_valid": False,
                "token_replay_suspected": observation.token_replay_suspected
                or exc.code in _REPLAY_SUSPECT_CODES,
            }
        )
    return observation.model_copy(
        update={
            "authenticated_agent_id": principal.agent_id,
            "sender_constrained": True,
            "binding_method": "DPoP",
            "sender_proof_valid": True,
        }
    )


@app.post("/control/agent-calls")
def control_agent_call(
    body: AgentCallRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
    x_nhi_approval_grant: Optional[str] = Header(default=None, alias="X-NHI-Approval-Grant"),
) -> Dict[str, Any]:
    """Gateway 가 Agent 의 NHI 호출을 통과시키기 전에 묻는 실시간 판정.

    `directive`: PASS · ALERT_ONLY · REQUIRE_APPROVAL · BLOCK. `allowed=false` 면 Gateway 는
    요청을 통과시키지 않는다. REQUIRE_APPROVAL 은 관리자 승인 후 받은 1회용 허가를
    `X-NHI-Approval-Grant` 헤더에 담아 같은 요청을 재시도하면 PASS 가 된다.

    `sender_evidence`(DPoP)를 보내면 인증된 Agent 와 sender proof 결과를 서버가 직접 검증해 채운다.
    """
    if storage.get_nhi_record(body.nhi_id) is None or not is_demo(
        load_nhi(storage, body.nhi_id)
    ):
        _require_admin_key(x_nhi_admin_key)
    observation = AgentApiObservation(**body.model_dump(exclude={"sender_evidence"}))
    if body.sender_evidence is not None:
        observation = _apply_sender_evidence(observation, body.sender_evidence)
    try:
        return _control_service().authorize_call(observation, grant_token=x_nhi_approval_grant)
    except (KeyError, ChangeError) as exc:
        raise _governance_http(exc)


class AdminPrincipalCreateRequest(BaseModel):
    admin_id: str = Field(..., min_length=1, max_length=40, examples=["alice"])
    roles: List[str] = Field(..., min_length=1, examples=[["ADMIN"]])
    display_name: str = Field(default="", max_length=100)


def _require_bootstrap(provided: Optional[str]) -> AdminIdentity:
    """관리자 계정 관리는 공유 키(break-glass) 보유자만 한다. 계정이 스스로 권한을 올릴 수 없다."""
    identity = _authenticate_admin(provided)
    if identity.via != "bootstrap":
        raise HTTPException(
            status_code=403, detail="관리자 계정 관리는 공유 관리자 키(NHI_ADMIN_API_KEY)로만 할 수 있습니다."
        )
    return identity


def _principal_call(action, *args, **kwargs):
    try:
        return action(*args, **kwargs)
    except AdminIdentityError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)


@app.get("/admin/whoami")
def admin_whoami(
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    identity = _authenticate_admin(x_nhi_admin_key)
    return {
        "admin_id": identity.admin_id,
        "roles": sorted(identity.roles),
        "verified": identity.verified,
        "via": identity.via,
        "strict": _directory().strict,
    }


@app.get("/admin/principals")
def list_admin_principals(
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_bootstrap(x_nhi_admin_key)
    directory = _directory()
    items = directory.list()
    return {"count": len(items), "strict": directory.strict, "principals": items}


@app.post("/admin/principals", status_code=201)
def create_admin_principal(
    body: AdminPrincipalCreateRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """관리자 계정을 만들고 개인 키를 **한 번만** 돌려준다. 이후 `strict` 로 전환된다."""
    _require_bootstrap(x_nhi_admin_key)
    principal, api_key = _principal_call(
        _directory().create, body.admin_id, body.roles, display_name=body.display_name
    )
    storage.append_audit_event(
        "ADMIN_PRINCIPAL_CREATED", actor="bootstrap", target=principal["admin_id"],
        detail={"roles": principal["roles"]},
    )
    return {"principal": principal, "api_key": api_key, "strict": _directory().strict}


@app.post("/admin/principals/{admin_id}/rotate-key")
def rotate_admin_key(
    admin_id: str,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_bootstrap(x_nhi_admin_key)
    principal, api_key = _principal_call(_directory().rotate_key, admin_id)
    storage.append_audit_event(
        "ADMIN_KEY_ROTATED", actor="bootstrap", target=principal["admin_id"], detail={}
    )
    return {"principal": principal, "api_key": api_key}


@app.post("/admin/principals/{admin_id}/disable")
def disable_admin_principal(
    admin_id: str,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_bootstrap(x_nhi_admin_key)
    principal = _principal_call(_directory().set_disabled, admin_id, True)
    storage.append_audit_event(
        "ADMIN_PRINCIPAL_DISABLED", actor="bootstrap", target=principal["admin_id"], detail={}
    )
    return principal


@app.post("/admin/principals/{admin_id}/enable")
def enable_admin_principal(
    admin_id: str,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_bootstrap(x_nhi_admin_key)
    principal = _principal_call(_directory().set_disabled, admin_id, False)
    storage.append_audit_event(
        "ADMIN_PRINCIPAL_ENABLED", actor="bootstrap", target=principal["admin_id"], detail={}
    )
    return principal


class ApprovalDecisionRequest(BaseModel):
    actor: Optional[str] = Field(default=None, min_length=1)
    reason: str = Field(..., min_length=1)


def _approval_http(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail="승인 대기 요청을 찾을 수 없습니다.")
    return HTTPException(status_code=409, detail=str(exc))


@app.get("/control/approvals")
def list_control_approvals(status: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    holds = _control_service().approvals.list_holds(
        status=status, limit=min(max(limit, 1), 500)
    )
    return {"count": len(holds), "approvals": holds}


@app.post("/control/approvals/{decision_id}/approve")
def approve_control_hold(
    decision_id: str,
    body: ApprovalDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """보류된 호출을 승인한다. 1회용 허가(`grant`)는 이 응답에서 한 번만 볼 수 있다."""
    actor, identity = _acting_admin(x_nhi_admin_key, body.actor)
    try:
        approval, grant = _control_service().approvals.approve(
            decision_id, actor=actor, reason=body.reason, verified=identity.verified
        )
    except (KeyError, ApprovalError) as exc:
        raise _approval_http(exc)
    return {"approval": approval, "grant": grant}


@app.post("/control/approvals/{decision_id}/reject")
def reject_control_hold(
    decision_id: str,
    body: ApprovalDecisionRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    actor, identity = _acting_admin(x_nhi_admin_key, body.actor)
    try:
        return _control_service().approvals.reject(
            decision_id, actor=actor, reason=body.reason, verified=identity.verified
        )
    except (KeyError, ApprovalError) as exc:
        raise _approval_http(exc)


@app.post("/control/events")
def control_event(
    body: ControlEventRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """사용 로그·탐지 이벤트를 받아 판정한다 (사용량 급증, Credential 노출 등)."""
    _require_admin_unless_demo(body.nhi_id, x_nhi_admin_key)
    try:
        return _control_service().evaluate(body.nhi_id, body.event_type, body.attributes)
    except (KeyError, ChangeError) as exc:
        raise _governance_http(exc)


@app.get("/control/events")
def list_control_events(
    after_seq: Optional[int] = None,
    nhi_id: Optional[str] = None,
    verdict: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """`after_seq` 를 주면 그 이후 이벤트만 오래된 순으로 돌려준다 (Dashboard 폴링용)."""
    events = storage.list_control_events(
        after_seq=after_seq, nhi_id=nhi_id, verdict=verdict, limit=min(max(limit, 1), 500)
    )
    return {
        "count": len(events),
        "events": events,
        "last_seq": max((event["seq"] for event in events), default=after_seq or 0),
    }


@app.get("/control/status")
def control_status() -> Dict[str, Any]:
    return _control_service().status()


@app.post("/control/nhi/{nhi_id}/quarantine")
def quarantine_nhi(
    nhi_id: str,
    body: QuarantineRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """수동 격리 — 승인 없이 즉시 적용되며 언제든 해제(롤백)할 수 있다."""
    actor, identity = _acting_admin_unless_demo(nhi_id, x_nhi_admin_key, body.actor)
    try:
        change = _change_service().propose(
            nhi_id,
            ChangeType.QUARANTINE,
            requested_by=actor,
            requested_verified=identity.verified,
            reason=body.reason or "관리자 수동 격리",
        )
    except (KeyError, ChangeError, LifecycleError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


@app.post("/control/nhi/{nhi_id}/release")
def release_nhi(
    nhi_id: str,
    body: QuarantineRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    actor, _ = _acting_admin_unless_demo(nhi_id, x_nhi_admin_key, body.actor)
    try:
        change = _change_service().release_quarantine(
            nhi_id, actor=actor, reason=body.reason
        )
    except (KeyError, ChangeError, LifecycleError) as exc:
        raise _governance_http(exc)
    return change.to_dict()


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


@app.post("/integrations/github/continuous-assessment")
def run_github_continuous_assessment(
    body: GitHubContinuousAssessmentRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """GitHub App 인벤토리와 Audit Log를 결합해 NHI를 지속 재평가한다.

    GitHub 원본 Audit Log는 응답·DB에 저장하지 않는다. actor login과 IP는 수집
    직후 가명처리되고 User-Agent는 제품군만 남으며, 최소화된 이벤트는 설정된
    보존 기간이 지나면 자동 삭제된다.
    """
    _require_admin_key(x_nhi_admin_key)
    try:
        with GitHubConnector.for_inventory() as inventory_connector:
            with GitHubConnector.for_audit() as audit_connector:
                return GitHubContinuousAssessmentService(
                    storage,
                    inventory_connector=inventory_connector,
                    audit_connector=audit_connector,
                    pipeline=nhi_pipeline,
                ).run(
                    body.organization,
                    inventory_limit=body.inventory_limit,
                    audit_limit=body.audit_limit,
                    since=body.since,
                    signals=body.signals,
                    signals_by_nhi_id=body.signals_by_nhi_id,
                )
    except ConnectorError as exc:
        raise _http_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/privacy/retention/run")
def run_privacy_retention(
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """보존 기간이 지난 최소화 UsageEvent를 즉시 물리 삭제한다."""
    identity = _require_admin_key(x_nhi_admin_key)
    deleted = storage.purge_expired_usage_events()
    audit_event_id = storage.append_audit_event(
        "PRIVACY_RETENTION_ENFORCED",
        actor=identity.admin_id,
        target="usage_events",
        detail={"deleted_count": deleted},
    )
    return {"deleted_count": deleted, "audit_event_id": audit_event_id}


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
_dashboard_dir = Path(__file__).resolve().parents[1] / "frontend" / "dashboard"
app.mount(
    "/dashboard",
    StaticFiles(directory=str(_dashboard_dir), html=True),
    name="dashboard",
)
