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
from typing import Any, Dict, List, Optional, Sequence, Set

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
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
from rescan.credential_verifier import CredentialVerifier
from rescan.revalidator import Revalidator
from scanner.scan_service import SecretScanService
from storage import Storage, get_default_storage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="NHI Risk Analysis Agent API",
    description=(
        "GitHub/Slack 연동 · Secret 탐지 · NHI 위험 분석 · Agent 실행을 제공한다."
    ),
    version="0.2.0",
)

# ---------------------------------------------------------------------------
# 영속화 저장소 (SQLite 기본, NHI_DB_PATH 로 경로 지정 / Storage 구현 교체 가능)
# ---------------------------------------------------------------------------
storage: Storage = get_default_storage()


def _known_fingerprints(repository: str) -> Set[str]:
    return storage.known_fingerprints(repository)


def _store_result(result: ScanResult) -> None:
    storage.save_scan_result(result)
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
def run_scan(body: ScanRequest) -> Dict[str, Any]:
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
        payload["nhi_analysis"] = report.to_dict()
    return payload


@app.get("/scans/{owner}/{repo}")
def get_scan_history(owner: str, repo: str, limit: int = 10) -> Dict[str, Any]:
    results = storage.list_scan_results(f"{owner}/{repo}", limit=limit)
    return {"count": len(results), "results": results}


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
    return report.to_dict()


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
    analysis = nhi_pipeline.analyze_github_nhi(body.nhi, signals=body.signals)
    return analysis.to_dict()


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
    return state.to_dict()


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
