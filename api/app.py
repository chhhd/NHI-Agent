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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
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
from agents.dry_run_service import build_dry_run_response, get_latest_analysis_snapshot
from backend.services.nhi_lifecycle import event_type_for_transition
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
from core.destruction_models import DestructionEvidence
from core.agent_access_models import (
    AgentAccessDecision,
    AgentAccessOutcome,
    AgentAccessProfile,
    AgentApiObservation,
    NHIAccessContext,
)
from core.inventory_models import GitHubNHIInput, SaaSNHIInput
from core.models import ScanResult, ScanTrigger, SecretFinding
from core.nhi_lifecycle_models import NHILifecycleStatus
from core.nhi_models import (
    AnalysisSignals,
    NHIAnalysisReport,
    NHIType,
    PermissionLevel,
    RecommendedAction,
    days_since,
)
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
from security.dpop import RuntimeTokenService, TokenBindingError
from security.replay_store import StorageReplayCache
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
from backend.services.access_enforcement import (
    AccessControlMode,
    EnforcementAction,
    EnforcementRecommendation,
    build_fail_closed_decision,
    recommend_enforcement,
)
from backend.services.usage_rate import DEFAULT_TRACKER as _CALL_RATE_TRACKER
from backend.services.change_control_service import ChangeControlService
from core.change_control_models import (
    ChangeError,
    ChangeExecutionError,
    ChangeNotAllowed,
    SeparationOfDutiesError,
    StateConflict,
)

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
change_control_service = ChangeControlService(storage)
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


class NHILifecycleUpdateRequest(BaseModel):
    """NHI 생명주기 상태 수동 전이 요청.

    `status`가 `NHILifecycleStatus`(4종)로 한정돼 있어 `PERMISSION_CHANGED`는
    애초에 값으로 들어올 수 없다 — 권한 변경은 상태가 아니라 Timeline
    이벤트이므로 이 엔드포인트가 아니라 조치 승인 흐름에서만 기록된다.

    `destruction_evidence`는 `DECOMMISSIONED` 전이에서만 의미가 있고
    선택 사항이다 — 기존 호출부가 이 필드 없이 호출해도 그대로 동작한다
    (하위 호환). 전달되면 `core.destruction_models.DestructionEvidence`로
    검증한다(`method`/`performed_by`/`verified_by`/`verification_check`/
    `verification_result` 필수, 수행자≠검증자). 이 증적은 우리 내부 관리
    상태를 "파기"로 바꾸는 근거일 뿐 — `method=SECRET_MATERIAL_DELETED`는
    우리가 보관 중인 암호문만 지웠다는 뜻이고, 실제 Provider(GitHub/Slack/
    AWS 등) 측 Credential이 아직 유효한지는 이 필드가 보증하지 않는다
    (`method=PROVIDER_REVOKED`만 Provider 측 폐기를 주장한다. 이 프로젝트는
    Provider API를 직접 호출해 그 주장을 검증하지 않는다 — 그건 여전히
    사람이 확인해야 한다).
    """

    status: NHILifecycleStatus
    actor: str = Field(..., min_length=1)
    note: str = ""
    destruction_evidence: Optional[Dict[str, Any]] = None


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


#: DPoP proof jti 재전송 방지 — SQLite(storage)에 영속화해 다중 워커·프로세스
#: 재시작 사이에서도 단일 사용을 보장한다(`security/replay_store.py`).
#: `InMemoryReplayCache`는 단일 프로세스 테스트/스크립트용으로 계속 남겨둔다
#: (`RuntimeTokenService(replay_cache=...)`로 명시적으로 넘기면 여전히 쓸 수 있다).
_runtime_replay_cache = StorageReplayCache(storage)


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
            "/runtime/protected는 이 서버가 직접 서빙하므로 실제로 차단되지만, "
            "GitHub/Slack/AWS 등 외부 provider API 앞에는 별도 egress 프록시/API "
            "Gateway가 /agent-access/evaluate 결과를 적용해야 실제 차단이 된다",
            "IdP/RBAC 및 공급자별 전체 인벤토리 동기화는 아직 미구현",
            "/runtime/*는 DPoP 연구 검증용이며 회사 Agent Registry를 대체하지 않음",
            "조치 승인 후 실제 Credential 폐기/회전/권한 축소 실행과 "
            "NHI 생명주기 자동 전이는 아직 없음(수동 PATCH만 가능)",
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


def _runtime_access_observation(request: Request, principal: Any) -> AgentApiObservation:
    """DPoP로 증명된 사실 + 실제 HTTP 요청만으로 `AgentApiObservation`을 만든다.

    요청자가 "나는 어떤 NHI/리소스에 접근한다"고 주장할 수 있는 입력 필드가
    이 엔드포인트에는 애초에 없다(요청 바디를 받지 않음) — `nhi_id`는 DPoP가
    증명한 `principal.agent_id`로부터, `resource`/`action`은 서버가 실제로
    받은 HTTP 메서드·경로에서 결정론적으로 파생한다. 어떤 값도 클라이언트가
    보낸 자유 입력에서 가져오지 않는다.
    """
    method = request.method.upper()
    path = request.url.path
    return AgentApiObservation(
        event_id=str(uuid4()),
        claimed_agent_id=principal.agent_id,
        authenticated_agent_id=principal.agent_id,
        provider="runtime",
        nhi_id=f"runtime:{principal.agent_id}",
        credential_fingerprint=f"jkt:{principal.binding_jkt}",
        action=f"{method} {path}",
        permission=PermissionLevel.READ if method == "GET" else PermissionLevel.WRITE,
        resource=path,
        resource_sensitive=False,
        sender_constrained=True,
        binding_method="DPoP",
        sender_proof_valid=True,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:300],
    )


def _runtime_access_control_deny_response(
    *, request: Request, principal: Any, evaluation: AgentAccessEvaluation
) -> JSONResponse:
    """Agent Access 평가가 BLOCK을 권고했을 때의 응답 — DPoP 자체 실패(401/400,
    `_runtime_deny_response`)와는 다른 계층의 실패(403, 인가 거부)다.
    """
    decision = evaluation.decision
    blocking_rule_ids = [f.rule_id for f in decision.findings if f.blocking]
    reason = blocking_rule_ids[0] if blocking_rule_ids else (
        decision.findings[0].rule_id if decision.findings else "access_denied"
    )
    event_id = _runtime_audit(
        request=request,
        decision="DENY",
        reason=reason,
        agent_id=principal.agent_id,
        detail={
            "stage": "resource_access",
            "token_jti": principal.token_id,
            "proof_jti": principal.proof_jti,
            "binding_jkt": principal.binding_jkt,
            "sender_constrained": True,
            "token_binding_method": "DPoP",
            "agent_access_decision_id": decision.decision_id,
            "agent_access_outcome": decision.outcome.value,
            "rule_ids": blocking_rule_ids or [f.rule_id for f in decision.findings],
        },
    )
    return JSONResponse(
        status_code=403,
        content={
            "decision": "DENY",
            "authenticated_as": principal.agent_id,
            "reason": reason,
            "message": evaluation.recommendation.reason,
            "agent_access_decision_id": decision.decision_id,
            "audit_event_id": event_id,
            "source_context": _runtime_source_context(request),
        },
    )


@app.get("/runtime/protected")
@app.post("/runtime/protected")
def runtime_protected_resource(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    dpop: Optional[str] = Header(default=None, alias="DPoP"),
) -> Any:
    """token 문자열뿐 아니라 Agent private key 보유까지 증명해야 하는 보호 API.

    DPoP 검증(인증)에 성공해도 그것만으로 ALLOW하지 않는다 — 이어서 Agent
    Access Evaluator(인가)를 통과해야 한다. 등록되지 않은 Agent, 승인되지
    않은 NHI/자원/작업, `REVIEW` 판정, 평가 실패는 모두 기본 차단(BLOCK)
    한다(`backend/services/access_enforcement.py`). NHI/자원 식별은 요청자가
    주장한 값이 아니라 DPoP로 증명된 `agent_id`와 실제 HTTP 메서드·경로에서만
    만든다(`_runtime_access_observation()`) — 이 엔드포인트는 요청 바디
    자체를 받지 않으므로 호출자가 그 값을 주장할 방법이 구조적으로 없다.

    DPoP 자체 검증 실패(401/400, `TokenBindingError`)는 기존과 완전히
    동일하게 처리한다 — 이 변경은 그 경로 이후에만 추가된다.
    """
    try:
        principal = _runtime_token_service().authorize(
            authorization=_single_runtime_header(request, "Authorization", authorization),
            dpop_proof=_single_runtime_header(request, "DPoP", dpop),
            method=request.method,
            htu=_runtime_htu(request),
        )
    except TokenBindingError as exc:
        return _runtime_deny_response(exc, request=request, stage="resource_access")

    observation = _runtime_access_observation(request, principal)
    evaluation = _evaluate_agent_access(observation)
    payload = _persist_agent_access_evaluation(evaluation)

    if evaluation.recommendation.action is EnforcementAction.BLOCK:
        return _runtime_access_control_deny_response(
            request=request, principal=principal, evaluation=evaluation
        )

    event_id = _runtime_audit(
        request=request,
        decision="ALLOW",
        reason="dpop_proof_verified_and_access_allowed",
        agent_id=principal.agent_id,
        detail={
            "stage": "resource_access",
            "token_jti": principal.token_id,
            "proof_jti": principal.proof_jti,
            "binding_jkt": principal.binding_jkt,
            "sender_constrained": True,
            "token_binding_method": "DPoP",
            "agent_access_decision_id": payload["decision_id"],
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
        "agent_access_decision_id": payload["decision_id"],
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


@app.patch("/nhi/{nhi_id}/lifecycle")
def update_nhi_lifecycle(
    nhi_id: str,
    body: NHILifecycleUpdateRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """NHI 생명주기 상태를 수동으로 전이한다.

    관리적 상태만 바꾼다 — 실제 Credential 폐기/회전/권한 변경은 전혀
    수행하지 않는다(`core/nhi_lifecycle_models.py` 참고). 민감한 조치이므로
    `X-NHI-Admin-Key`가 필요하고, 결과는 `AUDIT` 이벤트로 남는다. 허용되지
    않은 전이(예: `REGISTERED` → `DECOMMISSIONED`)는 409로 거부한다.

    경로가 `/nhi/{nhi_id}/{suffix}` 형태인 다른 2단 경로(`/nhi/{owner}/{repo}`
    등 스캔 기반 엔드포인트)와 겹치지 않도록, 그 경로들보다 먼저 등록한다
    (Starlette는 먼저 등록된 라우트를 우선 매칭한다).
    """
    _require_admin_key(x_nhi_admin_key)
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")

    state = storage.get_nhi_lifecycle_state(nhi_id)
    if state is None:
        # 이 기능 도입 이전부터 있던 NHI — 먼저 REGISTERED로 보정한다.
        state = storage.initialize_nhi_lifecycle(
            nhi_id,
            actor=body.actor,
            note="PATCH /nhi/{id}/lifecycle 처리 전 생명주기 최초 초기화",
        )
    current = NHILifecycleStatus(state["status"])

    if current == body.status:
        return {
            "nhi_id": nhi_id,
            "status": current.value,
            "updated_at": state["updated_at"],
            "changed": False,
        }

    evidence: Optional[DestructionEvidence] = None
    if body.destruction_evidence is not None:
        try:
            evidence = DestructionEvidence.from_dict(
                body.destruction_evidence, default_performer=body.actor
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    try:
        event_type = event_type_for_transition(current, body.status)
        result = storage.update_nhi_lifecycle_status(
            nhi_id,
            body.status,
            event_type=event_type,
            actor=body.actor,
            note=body.note,
            destruction_evidence=evidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    storage.append_audit_event(
        "NHI_LIFECYCLE_STATUS_CHANGED",
        actor=body.actor,
        target=nhi_id,
        detail={
            "from_status": current.value,
            "to_status": body.status.value,
            "event_type": event_type.value,
            "note": body.note,
        },
    )
    return {**result, "changed": True}


@app.get("/nhi/{nhi_id}/timeline")
def get_nhi_timeline(nhi_id: str, limit: int = 200) -> Dict[str, Any]:
    """NHI의 생명주기 이벤트와 분석 스냅샷 이력을 시간순(최신 먼저)으로 합친다.

    기존 `AnalysisHistoryService.list_history()`(분석 결정 이력)는 그대로
    재사용한다 — 여기서 새로 하는 일은 그 결과와 생명주기 이력을
    `type`(`lifecycle_event`/`analysis_snapshot`)으로 구분해 하나의 시간순
    목록으로 합치는 것뿐이다.
    """
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")

    limit = min(max(limit, 1), 1000)
    lifecycle_events = storage.get_nhi_lifecycle_history(nhi_id, limit=limit)
    analysis_history = AnalysisHistoryService(storage).list_history(nhi_id, limit=limit)

    timeline: List[Dict[str, Any]] = []
    for event in lifecycle_events:
        timeline.append(
            {
                "type": "lifecycle_event",
                "occurred_at": event["occurred_at"],
                "event_type": event["event_type"],
                "from_status": event["from_status"],
                "to_status": event["to_status"],
                "changes_status": event["from_status"] != event["to_status"],
                "actor": event["actor"],
                "note": event["note"],
                "detail": event["detail"],
            }
        )
    for analysis in analysis_history["analyses"]:
        timeline.append(
            {
                "type": "analysis_snapshot",
                "occurred_at": analysis.get("analyzed_at"),
                "analysis_id": analysis.get("analysis_id"),
                "risk_score": analysis.get("risk_score"),
                "risk_level": analysis.get("risk_level"),
                "policy_outcome": analysis.get("policy_outcome"),
                "recommended_action": analysis.get("recommended_action"),
            }
        )

    # 두 출처의 시각 형식(ISO8601)이 같으므로 문자열 비교만으로 시간순이
    # 보장된다. 최신 항목이 위로 오도록 내림차순으로 보여준다(다른 목록
    # API — /analyses, /agent-access/decisions 등 — 과 동일한 관례).
    timeline.sort(key=lambda item: item.get("occurred_at") or "", reverse=True)

    lifecycle_state = storage.get_nhi_lifecycle_state(nhi_id)
    return {
        "nhi_id": nhi_id,
        "lifecycle_status": lifecycle_state["status"] if lifecycle_state else None,
        "count": len(timeline),
        "timeline": timeline,
    }


class ChangeProposeRequest(BaseModel):
    """변경 제안 — 조치는 받지 않는다. 최신 분석의 `recommended_action`을
    `build_change_preview()`로 재계산해 자동으로 정한다(요청자가 임의의
    조치를 지정할 수 없다 — Change Preview 엔진과 항상 같은 조치를 보게 한다).
    """

    requested_by: str = Field(..., min_length=1)
    reason: str = ""
    idempotency_key: str = Field(..., min_length=1)
    impact_acknowledged: bool = False


class ChangeApproveRequest(BaseModel):
    approved_by: str = Field(..., min_length=1)


class ChangeActorRequest(BaseModel):
    actor: str = Field(..., min_length=1)
    reason: str = ""


def _change_control_error_response(exc: ChangeError):
    if isinstance(exc, SeparationOfDutiesError):
        raise HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, StateConflict):
        raise HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ChangeNotAllowed):
        raise HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ChangeExecutionError):
        raise HTTPException(status_code=502, detail=str(exc))
    raise HTTPException(status_code=400, detail=str(exc))


@app.post("/nhi/{nhi_id}/changes")
def propose_change(
    nhi_id: str,
    body: ChangeProposeRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """최신 분석의 추천 조치를 Change Preview로 재계산해 승인 요청을 만든다.

    실제 Credential/권한은 전혀 바꾸지 않는다 — `agents/dry_run_service.py::
    build_change_preview()`를 그대로 재사용한 결과만 들어간다. `idempotency_key`가
    이미 쓰인 적 있으면 새로 만들지 않고 기존 요청을 그대로 반환한다. 경로가
    `/nhi/{nhi_id}/{suffix}` 형태라 `/nhi/{owner}/{repo}`보다 먼저 등록한다
    (`/nhi/{nhi_id}/lifecycle` 과 같은 이유).
    """
    _require_admin_key(x_nhi_admin_key)
    try:
        change = change_control_service.propose(
            nhi_id,
            requested_by=body.requested_by,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
            impact_acknowledged=body.impact_acknowledged,
        )
    except ChangeError as exc:
        _change_control_error_response(exc)
    return change.to_dict()


@app.get("/nhi/{nhi_id}/changes")
def list_nhi_changes(
    nhi_id: str,
    status: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    changes = change_control_service.list(nhi_id=nhi_id, limit=min(max(limit, 1), 500))
    if status:
        changes = [c for c in changes if c.status.value == status]
    return {"nhi_id": nhi_id, "count": len(changes), "changes": [c.to_dict() for c in changes]}


@app.get("/changes/{change_id}")
def get_change(change_id: str) -> Dict[str, Any]:
    try:
        return change_control_service.get(change_id).to_dict()
    except KeyError:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")


@app.post("/changes/{change_id}/approve")
def approve_change(
    change_id: str,
    body: ChangeApproveRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """요청자와 다른 사람만 승인할 수 있다(직무 분리) — 같으면 403."""
    _require_admin_key(x_nhi_admin_key)
    try:
        change = change_control_service.approve(change_id, approved_by=body.approved_by)
    except KeyError:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")
    except ChangeError as exc:
        _change_control_error_response(exc)
    storage.append_audit_event(
        "CHANGE_REQUEST_APPROVED",
        actor=body.approved_by,
        target=change_id,
        detail={"nhi_id": change.nhi_id, "change_type": change.change_type.value, "tier": change.tier.value},
    )
    return change.to_dict()


@app.post("/changes/{change_id}/reject")
def reject_change(
    change_id: str,
    body: ChangeActorRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    _require_admin_key(x_nhi_admin_key)
    try:
        change = change_control_service.reject(change_id, actor=body.actor, reason=body.reason)
    except KeyError:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")
    except ChangeError as exc:
        _change_control_error_response(exc)
    storage.append_audit_event(
        "CHANGE_REQUEST_REJECTED", actor=body.actor, target=change_id,
        detail={"nhi_id": change.nhi_id, "reason": body.reason},
    )
    return change.to_dict()


@app.post("/changes/{change_id}/apply")
def apply_change(
    change_id: str,
    body: ChangeActorRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """승인된 변경만 적용한다 — 승인 없이는 422/409로 거부된다.

    실제로 바뀌는 건 NHI Lifecycle 상태뿐이다(`InventoryStateExecutor`).
    응답의 `executor_result.provider_call`은 항상 `"not_configured"`다 —
    실제 GitHub/Slack/AWS Provider를 호출하지 않았다는 뜻이며, 이 필드로
    "내부 상태 변경"과 "실제 Provider 적용"을 API 응답에서 명확히 구분한다.
    """
    _require_admin_key(x_nhi_admin_key)
    try:
        change = change_control_service.apply(change_id, actor=body.actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")
    except ChangeError as exc:
        _change_control_error_response(exc)
    storage.append_audit_event(
        "CHANGE_REQUEST_APPLIED",
        actor=body.actor,
        target=change_id,
        detail={
            "nhi_id": change.nhi_id,
            "change_type": change.change_type.value,
            "status": change.status.value,
            "executor_result": change.executor_result,
        },
    )
    return change.to_dict()


@app.post("/changes/{change_id}/rollback")
def rollback_change(
    change_id: str,
    body: ChangeActorRequest,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """적용된 변경을 유효 기간 내에만 되돌린다 — 기간이 지나면 409로 거부된다."""
    _require_admin_key(x_nhi_admin_key)
    try:
        change = change_control_service.rollback(change_id, actor=body.actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="변경 요청을 찾을 수 없습니다.")
    except ChangeError as exc:
        _change_control_error_response(exc)
    storage.append_audit_event(
        "CHANGE_REQUEST_ROLLED_BACK",
        actor=body.actor,
        target=change_id,
        detail={
            "nhi_id": change.nhi_id,
            "change_type": change.change_type.value,
            "executor_result": change.executor_result,
        },
    )
    return change.to_dict()


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


#: Credential 폐기 신호를 실시간 접근 평가에 신뢰할 수 있는 최대 기간(일).
#: 이보다 오래된 분석은 "확인됨"이 아니라 미확인(None)으로 되돌린다 — 오래된
#: 정보를 최신 상태처럼 써서 활성/비활성을 잘못 단정하지 않기 위함이다.
#: 운영 환경의 재분석 주기에 맞춰 조정한다.
_CREDENTIAL_SIGNAL_MAX_AGE_DAYS = 7


def _latest_credential_revoked_signal(nhi_id: str) -> Optional[bool]:
    """최신 분석에서 확인된 Credential 폐기 여부.

    `True`일 때만 "폐기가 확인됨"을 뜻한다. 분석 자체가 없거나, 너무
    오래됐거나(`_CREDENTIAL_SIGNAL_MAX_AGE_DAYS` 초과), 재현 입력에 값이
    없으면 전부 `None`(미확인)으로 처리한다 — Gateway가 보낸 값은 여기서
    전혀 쓰지 않는다. 저장소의 최신 분석(`get_latest_analysis_snapshot()`,
    Change Preview가 이미 쓰는 조회)만 본다.
    """
    snapshot = get_latest_analysis_snapshot(storage, nhi_id)
    if snapshot is None:
        return None
    age_days = days_since(snapshot.get("analyzed_at"))
    if age_days is None or age_days > _CREDENTIAL_SIGNAL_MAX_AGE_DAYS:
        return None
    finding = (snapshot.get("replay_snapshot") or {}).get("finding") or {}
    revoked = finding.get("credential_revoked")
    return revoked if isinstance(revoked, bool) else None


def _build_nhi_access_context(nhi_id: str) -> NHIAccessContext:
    """서버 저장소만 조회해 `NHIAccessContext`를 만든다.

    `AgentApiObservation`(Gateway가 보낸 요청 본문)의 어떤 필드도 여기서
    참조하지 않는다 — 호출 주체가 "내 NHI는 ACTIVE"라고 자가 신고하게 두면
    이 통제 자체가 무력화되기 때문이다.
    """
    lifecycle_state = storage.get_nhi_lifecycle_state(nhi_id)
    lifecycle_status = (
        NHILifecycleStatus(lifecycle_state["status"]) if lifecycle_state else None
    )
    return NHIAccessContext(
        lifecycle_status=lifecycle_status,
        credential_known_revoked=_latest_credential_revoked_signal(nhi_id),
    )


@dataclass
class AgentAccessEvaluation:
    """`_evaluate_agent_access()` 결과 — 판정 + 집행 권고 + 감사용 부가정보.

    `/agent-access/evaluate`와 `/runtime/protected`가 공유한다. `evaluate()`가
    내부적으로 실패하면 `decision`은 `build_fail_closed_decision()`의 결과이고
    `lifecycle_status`/`credential_known_revoked`는 조회 자체가 실패했으니
    `None`이다.
    """

    decision: AgentAccessDecision
    recommendation: EnforcementRecommendation
    lifecycle_status: Optional[NHILifecycleStatus]
    credential_known_revoked: Optional[bool]
    audit_event_type: str


def _evaluate_agent_access(body: AgentApiObservation) -> AgentAccessEvaluation:
    """Agent 접근 평가의 단일 진입점 — profile/NHI 컨텍스트 조회 → 판정 →
    집행 권고 계산까지 한 번에 처리한다.

    `/agent-access/evaluate`(Gateway/감사 로그 연동)와 `/runtime/protected`
    (DPoP 통과 후 인가 단계)가 이 함수를 공유한다 — 평가 로직이 두 곳에
    따로 구현돼 어긋나지 않도록 한다. NHI 생명주기/Credential 상태는
    `_build_nhi_access_context()`가 서버 저장소에서만 조회하므로, `body`
    (호출 주체가 보낸 값)로 자가 신고할 수 없다.

    평가 로직 내부에서 예외가 나면(예: 저장소 조회 실패) 호출부에 전파하지
    않고 fail-closed 결정(`build_fail_closed_decision()`, outcome=DENY)으로
    대체한다 — 어느 호출부든 "평가기 장애 시 기본 차단"을 따로 구현할
    필요가 없다.

    집행 모드(`NHI_CONTROL_MODE` — enforce/monitor/human_in_the_loop)는
    `recommend_enforcement()`에 그대로 넘긴다. `monitor`/`human_in_the_loop`는
    REVIEW(확정 못한 요청)에만 영향을 준다 — `decision.outcome`이 DENY면
    (비활성 Lifecycle, 폐기 확인된 Credential, 평가 실패 포함) 모드와 무관하게
    항상 BLOCK이다(`backend/services/access_enforcement.py::enforcement_action_for()`
    의 불변식). 호출률은 `body`(호출 주체 자가 신고)가 아니라
    `backend/services/usage_rate.py`가 서버에서 직접 측정한 값만 쓴다.
    """
    profile = _load_agent_access_profile(body.claimed_agent_id)
    call_rate_ratio = _CALL_RATE_TRACKER.observe(body.nhi_id).ratio
    mode = AccessControlMode.from_str(get_settings().access_control.mode)

    try:
        nhi_context = _build_nhi_access_context(body.nhi_id)
        decision = agent_access_evaluator.evaluate(
            profile, body, nhi_context=nhi_context, call_rate_ratio=call_rate_ratio
        )
        lifecycle_status = nhi_context.lifecycle_status
        credential_known_revoked = nhi_context.credential_known_revoked
        audit_event_type = "AGENT_API_ACCESS_EVALUATED"
    except Exception:
        logger.exception(
            "Agent Access 평가 실패 (agent_id=%s, nhi_id=%s) — fail-closed로 응답",
            body.claimed_agent_id,
            body.nhi_id,
        )
        decision = build_fail_closed_decision(body)
        lifecycle_status = None
        credential_known_revoked = None
        audit_event_type = "AGENT_ACCESS_EVALUATOR_UNAVAILABLE"

    recommendation = recommend_enforcement(
        decision, credential_known_revoked=credential_known_revoked, mode=mode
    )
    return AgentAccessEvaluation(
        decision=decision,
        recommendation=recommendation,
        lifecycle_status=lifecycle_status,
        credential_known_revoked=credential_known_revoked,
        audit_event_type=audit_event_type,
    )


def _persist_agent_access_evaluation(evaluation: AgentAccessEvaluation) -> Dict[str, Any]:
    """평가 결과를 저장 + 감사 기록하고, API 응답 payload를 만든다."""
    decision = evaluation.decision
    payload = decision.model_dump(mode="json")
    storage.save_agent_access_decision(dict(payload))
    payload["recommended_enforcement"] = evaluation.recommendation.to_dict()
    storage.append_audit_event(
        evaluation.audit_event_type,
        actor=decision.observation.authenticated_agent_id or "unverified-agent",
        target=decision.observation.claimed_agent_id,
        detail={
            "decision_id": decision.decision_id,
            "event_id": decision.event_id,
            "outcome": decision.outcome.value,
            "overall_severity": (
                decision.overall_severity.value if decision.overall_severity else None
            ),
            "rule_ids": [finding.rule_id for finding in decision.findings],
            "nhi_lifecycle_status": (
                evaluation.lifecycle_status.value if evaluation.lifecycle_status else None
            ),
            "credential_known_revoked": evaluation.credential_known_revoked,
            "recommended_enforcement": evaluation.recommendation.to_dict(),
        },
    )
    return payload


@app.post("/agent-access/evaluate")
def evaluate_agent_api_access(
    body: AgentApiObservation,
    x_nhi_admin_key: Optional[str] = Header(default=None, alias="X-NHI-Admin-Key"),
) -> Dict[str, Any]:
    """Gateway/Audit Log 호출을 승인 기준선과 비교해 ALLOW/REVIEW/DENY한다.

    악의적 의도 자체를 추측하지 않는다. 인증 주체 불일치, Token/proof 재사용,
    승인 NHI·Credential·권한·자원 초과처럼 검증 가능한 사실만 판정한다.

    요청 본문의 `nhi_id`를 기준으로 서버 저장소에서 NHI 생명주기 상태와
    최신 분석의 Credential 폐기 확인 여부를 직접 조회해 판정에 반영한다
    (`_build_nhi_access_context()`) — 이 값은 Gateway가 보낸 본문에서
    가져오지 않는다. 응답에는 기존 필드에 더해 `recommended_enforcement`가
    추가된다(`{action, reason, credential_state}`) — Gateway가 실제로 요청을
    통과/차단시킬 때 이 값을 그대로 적용하면 된다. 정책은 고정이다:
    ALLOW만 통과, REVIEW/DENY는 전부 차단(`backend/services/access_enforcement.py`
    참고). Credential 폐기 여부가 확인되지 않은 경우는 차단 사유와 섞이지
    않도록 `credential_state="unknown"`으로 항상 별도 표시한다.

    평가 로직 내부에서 예외가 나면(예: 저장소 조회 실패) 500을 돌려주는
    대신 fail-closed 응답(outcome=DENY, `recommended_enforcement.action=
    BLOCK`, 전용 규칙 `EVALUATOR_UNAVAILABLE`)을 만든다 — Gateway가 5xx를
    놓치고 기본 허용으로 처리하는 사고를 막기 위함이다. 관리자 키 검증
    실패(401)는 기존처럼 그대로 전파된다(`_evaluate_agent_access()` 호출
    전에 검증한다).
    """
    _require_admin_key(x_nhi_admin_key)
    evaluation = _evaluate_agent_access(body)
    return _persist_agent_access_evaluation(evaluation)


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


def _attach_lifecycle_summary(record: Dict[str, Any], nhi_id: str) -> Dict[str, Any]:
    """`record`(`storage.get_nhi_record()` 결과)에 생명주기 요약을 덧붙인다.

    `lifecycle_status`는 NHI의 관리적 상태다. 기존 필드(예: `recent_analyses`
    안의 Credential 활성/폐기 근거)는 그대로 두고 건드리지 않는다 — NHI
    상태와 Credential 상태를 한 값으로 합치지 않고 서로 다른 자리에 남겨
    구분을 유지한다. 이 기능 도입 이전부터 있던 NHI는 아직 초기화되지
    않았을 수 있으므로 `None`으로 채운다(하위 호환, 오류 아님).
    """
    state = storage.get_nhi_lifecycle_state(nhi_id)
    record["lifecycle_status"] = state["status"] if state else None
    record["lifecycle_updated_at"] = state["updated_at"] if state else None
    return record


@app.get("/nhi/{nhi_id}")
def get_nhi_inventory_item(nhi_id: str) -> Dict[str, Any]:
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")
    return _attach_lifecycle_summary(record, nhi_id)


@app.post("/nhi/{nhi_id}/dry-run")
def dry_run_nhi_action(nhi_id: str) -> Dict[str, Any]:
    """저장된 NHI 의 `recommended_action` 기준으로, 실제 변경 없이 예상 조치
    결과만 계산한다. 실제 Credential 폐기/회전/권한 축소 등 조치 실행과
    승인 처리는 이번 단계에서 구현하지 않는다 — `agents/dry_run_service.py`
    참고.

    기존 5개 응답 필드(`target_nhi_id`/`recommended_action`/`expected_changes`/
    `risk_before`/`risk_after_estimate`)는 항상 그대로 채운다. 이 NHI의 최신
    분석 스냅샷(Change Preview 재현에 필요한 입력 포함)을 찾을 수 있으면
    `change_preview` 키를 추가로 담아, 같은 정책/위험도/영향범위 엔진을
    가정 상태로 재실행한 before/after·calculated/estimated/unknown 구분·
    서비스 의존성 영향을 함께 반환한다. 분석 이력이 없거나(과거 레코드 등)
    재현 입력이 없으면 이 키 없이(또는 `applicable=False`로) 기존과 동일하게
    동작한다.
    """
    record = storage.get_nhi_record(nhi_id)
    if record is None:
        raise HTTPException(status_code=404, detail="NHI 를 찾을 수 없습니다.")
    snapshot = get_latest_analysis_snapshot(storage, nhi_id)
    return build_dry_run_response(nhi_id, record, snapshot)


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
