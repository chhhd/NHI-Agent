"""GitHub Webhook 수신 및 자동 검사 트리거.

  1. `X-Hub-Signature-256` HMAC 서명 검증
  2. push / pull_request 이벤트 파싱 → 변경 파일 목록 추출
  3. GitHubConnector 로 변경 파일 내용을 가져와 Secret Scan 실행

FastAPI 라우터는 `api/app.py` 에 있고, 이 모듈은 프레임워크에 의존하지 않는다.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from connectors.github_connector import GitHubConnector
from core.config import get_settings
from core.models import ScanResult, ScanTrigger
from scanner.scan_service import SecretScanService

logger = logging.getLogger(__name__)

#: 자동 검사를 실행할 이벤트
HANDLED_EVENTS = {"push", "pull_request"}

#: 검사를 실행할 PR 액션 (reopened/synchronize = 새 커밋 추가)
PR_SCAN_ACTIONS = {"opened", "reopened", "synchronize", "ready_for_review"}

_NULL_SHA = "0" * 40


class WebhookVerificationError(Exception):
    """서명 검증 실패."""


@dataclass
class WebhookEvent:
    """파싱된 Webhook 이벤트."""

    event_type: str
    repository: str
    delivery_id: str = ""
    ref: Optional[str] = None
    before: Optional[str] = None
    after: Optional[str] = None
    commit_shas: List[str] = field(default_factory=list)
    pull_request: Optional[int] = None
    action: Optional[str] = None
    sender: Optional[str] = None
    is_deleted_branch: bool = False

    @property
    def trigger(self) -> ScanTrigger:
        return ScanTrigger.PULL_REQUEST if self.event_type == "pull_request" else ScanTrigger.PUSH


def verify_signature(payload: bytes, signature_header: Optional[str], secret: Optional[str] = None) -> None:
    """`X-Hub-Signature-256` 헤더를 검증한다. 실패 시 예외."""
    secret = secret if secret is not None else get_settings().github.webhook_secret
    if not secret:
        raise WebhookVerificationError(
            "GITHUB_WEBHOOK_SECRET 이 설정되지 않았습니다. 검증 없는 수신은 허용하지 않습니다."
        )
    if not signature_header:
        raise WebhookVerificationError("X-Hub-Signature-256 헤더가 없습니다.")
    if not signature_header.startswith("sha256="):
        raise WebhookVerificationError("지원하지 않는 서명 형식입니다.")

    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    provided = signature_header.split("=", 1)[1]
    if not hmac.compare_digest(expected, provided):
        raise WebhookVerificationError("Webhook 서명이 일치하지 않습니다.")


def parse_event(event_type: str, payload: Dict[str, Any], delivery_id: str = "") -> WebhookEvent:
    """이벤트 페이로드에서 검사에 필요한 정보만 추출."""
    repository = (payload.get("repository") or {}).get("full_name", "")
    sender = (payload.get("sender") or {}).get("login")

    if event_type == "push":
        after = payload.get("after")
        return WebhookEvent(
            event_type=event_type,
            repository=repository,
            delivery_id=delivery_id,
            ref=payload.get("ref"),
            before=payload.get("before"),
            after=after,
            commit_shas=[c.get("id") for c in payload.get("commits", []) if c.get("id")],
            sender=sender,
            is_deleted_branch=bool(payload.get("deleted")) or after == _NULL_SHA,
        )

    if event_type == "pull_request":
        pr = payload.get("pull_request") or {}
        return WebhookEvent(
            event_type=event_type,
            repository=repository,
            delivery_id=delivery_id,
            action=payload.get("action"),
            pull_request=payload.get("number") or pr.get("number"),
            ref=(pr.get("head") or {}).get("ref"),
            after=(pr.get("head") or {}).get("sha"),
            sender=sender,
        )

    return WebhookEvent(event_type=event_type, repository=repository, delivery_id=delivery_id, sender=sender)


class GitHubWebhookHandler:
    """Webhook → 자동 Secret Scan 실행기."""

    def __init__(
        self,
        connector: Optional[GitHubConnector] = None,
        scan_service: Optional[SecretScanService] = None,
        *,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        known_fingerprints_provider: Optional[Callable[[str], set]] = None,
    ) -> None:
        self.connector = connector or GitHubConnector()
        self.scan_service = scan_service or SecretScanService()
        #: 스캔 완료 후 후속 처리 콜백 (DB 저장 / NHI 분석 전달)
        self.on_result = on_result
        #: repo 이름 → 기존 fingerprint 집합 (재발 판정용)
        self.known_fingerprints_provider = known_fingerprints_provider
        self._processed_deliveries: set = set()

    # ------------------------------------------------------------------
    def handle(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        raw_body: Optional[bytes] = None,
        signature: Optional[str] = None,
        delivery_id: str = "",
    ) -> Optional[ScanResult]:
        """Webhook 1건 처리. 검사 대상이 아니면 None."""
        if raw_body is not None:
            verify_signature(raw_body, signature)

        if event_type == "ping":
            logger.info("GitHub webhook ping 수신")
            return None

        if event_type not in HANDLED_EVENTS:
            logger.info("처리 대상이 아닌 이벤트: %s", event_type)
            return None

        # 재전송(delivery 중복) 방어
        if delivery_id and delivery_id in self._processed_deliveries:
            logger.info("이미 처리된 delivery: %s", delivery_id)
            return None
        if delivery_id:
            self._processed_deliveries.add(delivery_id)

        event = parse_event(event_type, payload, delivery_id)
        if not event.repository:
            logger.warning("repository 정보가 없는 이벤트 — 건너뜀")
            return None

        return self.run_scan(event)

    # ------------------------------------------------------------------
    def run_scan(self, event: WebhookEvent) -> Optional[ScanResult]:
        """이벤트에 해당하는 변경 파일을 검사한다."""
        if event.event_type == "push":
            if event.is_deleted_branch:
                logger.info("브랜치 삭제 이벤트 — 검사 생략 (%s)", event.repository)
                return None
            targets = self._push_targets(event)
        else:
            if event.action not in PR_SCAN_ACTIONS:
                logger.info("검사 대상이 아닌 PR 액션: %s", event.action)
                return None
            targets = self.connector.scan_targets_for_pull_request(
                event.repository, int(event.pull_request)
            )

        if not targets:
            logger.info("검사 대상 파일 없음 (%s)", event.repository)

        known = (
            self.known_fingerprints_provider(event.repository)
            if self.known_fingerprints_provider
            else None
        )
        result = self.scan_service.scan_targets(
            targets,
            repository=event.repository,
            trigger=event.trigger,
            ref=event.ref,
            commit_sha=event.after,
            pull_request=event.pull_request,
            known_fingerprints=known,
        )

        if self.on_result:
            self.on_result(result)
        return result

    def _push_targets(self, event: WebhookEvent) -> List[Any]:
        """push 이벤트의 변경 파일 → ScanTarget.

        before..after 비교가 가능하면 compare API 를, 첫 push 등 불가한
        경우에는 개별 커밋을 조회한다.
        """
        repo = event.repository
        if event.before and event.before != _NULL_SHA and event.after:
            try:
                files = self.connector.compare_commits(repo, event.before, event.after)
                paths = [f["path"] for f in files]
                return self.connector.build_scan_targets(repo, paths, ref=event.after)
            except Exception as exc:  # compare 실패 시 커밋 단위로 폴백
                logger.warning("compare 실패(%s) — 커밋 단위로 폴백", exc)

        paths: List[str] = []
        for sha in event.commit_shas or ([event.after] if event.after else []):
            try:
                paths.extend(f["path"] for f in self.connector.get_commit_files(repo, sha))
            except Exception as exc:
                logger.warning("커밋 %s 변경 파일 조회 실패: %s", sha, exc)

        return self.connector.build_scan_targets(repo, sorted(set(paths)), ref=event.after)
