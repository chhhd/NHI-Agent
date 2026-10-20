"""GitHub API Connector.

담당 기능
  * Repository 등록 / 정보 조회
  * 브랜치 및 파일 목록 조회
  * 파일 내용 조회 (스캐너 입력 생성)
  * Commit 변경 파일 조회
  * Pull Request 변경 파일 조회
  * Rate Limit / 인증 오류 / 권한 부족 처리
"""

from __future__ import annotations

import base64
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

from connectors.base_connector import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    NotFoundError,
    RateLimitError,
)
from core.config import get_settings
from core.inventory_models import GitHubNHIInput, GitHubNHIType
from core.models import CredentialStatus, ScanTarget
from scanner.regex_scanner import is_scannable_path

logger = logging.getLogger(__name__)

#: 변경 파일 중 삭제된 것은 스캔 대상이 아니다.
_SCANNABLE_STATUSES = {"added", "modified", "renamed", "copied", "changed"}


def _latest_audit_cursor(events: List[Dict[str, Any]]) -> Optional[str]:
    """오래된 순 응답의 마지막 이벤트를 다음 증분 수집용 증적으로 남긴다."""
    if not events:
        return None
    latest = events[-1]
    value = latest.get("created_at") or latest.get("@timestamp")
    return str(value) if value is not None else None


@dataclass
class Repository:
    """등록된 Repository 정보."""

    full_name: str                      # owner/repo
    default_branch: str = "main"
    private: bool = True
    html_url: str = ""
    registered_at: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def owner(self) -> str:
        return self.full_name.split("/")[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/")[-1]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "full_name": self.full_name,
            "owner": self.owner,
            "name": self.name,
            "default_branch": self.default_branch,
            "private": self.private,
            "html_url": self.html_url,
            "registered_at": self.registered_at,
        }


@dataclass
class GitHubOrganizationDiscoveryResult:
    """조직의 GitHub App installation 인벤토리와 수집 완전성."""

    organization: str
    items: List[GitHubNHIInput] = field(default_factory=list)
    total_count: Optional[int] = None
    pages_fetched: int = 0
    inventory_complete: bool = False
    retrieval_truncated: bool = False
    failures: List[Dict[str, str]] = field(default_factory=list)

    @property
    def coverage_note(self) -> str:
        return (
            "조직의 GitHub App installation 목록은 수집했지만 이 API는 각 설치가 "
            "접근하는 개별 저장소 이름을 제공하지 않는다. repository_selection은 "
            "평가하되 저장소 목록 미확인을 0개 접근으로 해석하지 않는다."
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collection_executed": True,
            "organization": self.organization,
            "total_count": self.total_count,
            "count": len(self.items),
            "pages_fetched": self.pages_fetched,
            "inventory_complete": self.inventory_complete,
            "truncated": self.retrieval_truncated,
            "parse_failure_count": len(self.failures),
            "failures": list(self.failures),
            "coverage_note": self.coverage_note,
            "inventory": [item.model_dump(mode="json") for item in self.items],
        }


@dataclass
class GitHubAuditLogResult:
    """메모리에만 머무는 GitHub 조직 Audit Log 수집 결과.

    ``events`` 원문은 개인정보 최소화 계층을 통과하기 전에는 직렬화하거나
    영속화하지 않는다. API 응답에는 건수·완전성·cursor만 노출한다.
    """

    organization: str
    events: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    pages_fetched: int = 0
    collection_complete: bool = False
    retrieval_truncated: bool = False
    latest_cursor: Optional[str] = None
    parse_failure_count: int = 0

    def summary(self) -> Dict[str, Any]:
        return {
            "organization": self.organization,
            "event_count": len(self.events),
            "pages_fetched": self.pages_fetched,
            "collection_complete": self.collection_complete,
            "retrieval_truncated": self.retrieval_truncated,
            "latest_cursor": self.latest_cursor,
            "parse_failure_count": self.parse_failure_count,
        }


class GitHubConnector(BaseConnector):
    """GitHub REST API v3 Connector."""

    provider = "github"

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        api_base: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        fallback_to_default_token: bool = True,
        **kwargs: Any,
    ) -> None:
        settings = get_settings().github
        resolved_token = token
        if fallback_to_default_token and not resolved_token:
            resolved_token = settings.token
        super().__init__(
            base_url=api_base or settings.api_base,
            token=resolved_token,
            client=client,
            **kwargs,
        )
        self.rate_limit_buffer = settings.rate_limit_buffer
        self.max_wait_seconds = settings.max_wait_seconds
        self.api_version = settings.api_version

    @classmethod
    def for_inventory(cls, **kwargs: Any) -> "GitHubConnector":
        """조직 App 인벤토리 전용 토큰으로 Connector를 만든다.

        ``GITHUB_INVENTORY_TOKEN``이 비어 있어도 일반 ``GITHUB_TOKEN``으로
        fallback하지 않는다. 두 권한 경계를 섞으면 조직 관리 read credential이
        저장소 파일 스캔에 재사용될 수 있기 때문이다.
        """
        settings = get_settings().github
        return cls(
            token=settings.inventory_token,
            fallback_to_default_token=False,
            **kwargs,
        )

    @classmethod
    def for_audit(cls, **kwargs: Any) -> "GitHubConnector":
        """조직 Audit Log 읽기 전용 토큰으로 Connector를 만든다."""
        settings = get_settings().github
        return cls(
            token=settings.audit_token,
            fallback_to_default_token=False,
            **kwargs,
        )

    # ------------------------------------------------------------------
    def default_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": "nhi-secret-agent/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    # ------------------------------------------------------------------
    # 자격 증명
    # ------------------------------------------------------------------
    def validate_credential(self, token: Optional[str] = None) -> CredentialStatus:
        """토큰 유효성 확인 및 Scope 조회.

        `GET /user` 응답 헤더의 `X-OAuth-Scopes` 로 부여된 Scope 를 얻는다.
        (fine-grained PAT 은 헤더가 비어 있을 수 있다.)
        """
        headers = {"Authorization": f"Bearer {token}"} if token else None
        status = CredentialStatus(provider=self.provider)
        try:
            response = self.get("/user", headers=headers)
        except ConnectorError as exc:
            status.active = False if exc.status_code == 401 else None
            status.revoked = exc.status_code == 401
            status.error = exc.message
            return status

        payload = response.json()
        raw_scopes = response.headers.get("X-OAuth-Scopes", "")
        status.active = True
        status.revoked = False
        status.raw_scopes = [s.strip() for s in raw_scopes.split(",") if s.strip()]
        status.account = {
            "login": payload.get("login"),
            "id": payload.get("id"),
            "type": payload.get("type"),
            "name": payload.get("name"),
        }
        (
            status.accessible_resources,
            status.resource_inventory_complete,
            status.resource_inventory_note,
        ) = self._accessible_repositories(headers)
        return status

    # ------------------------------------------------------------------
    # 조직 GitHub App installation 인벤토리
    # ------------------------------------------------------------------
    def discover_organization_apps(
        self, organization: str, *, limit: int = 100
    ) -> GitHubOrganizationDiscoveryResult:
        """``GET /orgs/{org}/installations``을 페이지 순회해 NHI로 정규화한다.

        이 endpoint는 조직 내 모든 GitHub App installation을 보여 주지만 개별
        repository 이름은 제공하지 않는다. 다른 App의 installation token을 발급할
        수도 없으므로 저장소 범위를 꾸며내지 않고 불완전 상태로 남긴다.
        """
        if not self.token:
            raise AuthenticationError(
                "GitHub 조직 App 인벤토리 수집에 GITHUB_INVENTORY_TOKEN이 필요합니다.",
                status_code=401,
            )
        org = (organization or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org):
            raise ConnectorError("올바른 GitHub organization 이름이 아닙니다.", status_code=400)
        if limit < 1 or limit > 2000:
            raise ConnectorError("GitHub 인벤토리 limit은 1~2000이어야 합니다.", status_code=400)

        raw_items: List[Dict[str, Any]] = []
        failures: List[Dict[str, str]] = []
        total_count: Optional[int] = None
        pages_fetched = 0
        received_count = 0
        page = 1
        while received_count < limit and page <= 20:
            per_page = min(100, limit - received_count)
            response = self.get(
                f"/orgs/{org}/installations",
                params={"per_page": per_page, "page": page},
            )
            payload = response.json()
            if not isinstance(payload, dict):
                raise ConnectorError(
                    "GitHub organization installations 응답 형식이 올바르지 않습니다."
                )
            raw_total = payload.get("total_count")
            if isinstance(raw_total, int) and raw_total >= 0:
                total_count = raw_total
            batch = payload.get("installations")
            if not isinstance(batch, list):
                raise ConnectorError(
                    "GitHub organization installations 응답에 installations가 없습니다."
                )

            pages_fetched += 1
            accepted_batch = batch[: limit - received_count]
            received_count += len(accepted_batch)
            for index, item in enumerate(accepted_batch):
                if isinstance(item, dict):
                    raw_items.append(item)
                    continue
                failures.append(
                    {
                        "installation_id": "unknown",
                        "error": (
                            "installation 항목 형식이 객체가 아님 "
                            f"(page={page}, index={index})"
                        ),
                    }
                )
            if not batch:
                break
            if total_count is not None and received_count >= min(total_count, limit):
                break
            if 'rel="next"' not in response.headers.get("Link", ""):
                break
            page += 1

        retrieval_complete = (
            total_count is not None and received_count >= total_count
        )
        items: List[GitHubNHIInput] = []
        seen_installation_ids: set[int] = set()
        for raw in raw_items:
            try:
                item = self._organization_installation_to_nhi(
                    raw, organization=org, inventory_complete=retrieval_complete
                )
            except (KeyError, TypeError, ValueError) as exc:
                failures.append(
                    {
                        "installation_id": str(raw.get("id") or "unknown"),
                        "error": f"필수 installation 필드 파싱 실패: {exc}",
                    }
                )
                continue

            installation_id = int(item.account["installation_id"])
            if installation_id in seen_installation_ids:
                failures.append(
                    {
                        "installation_id": str(installation_id),
                        "error": "중복 installation_id 항목을 제외함",
                    }
                )
                continue
            seen_installation_ids.add(installation_id)
            items.append(item)

        complete = retrieval_complete and not failures
        for item in items:
            item.inventory_is_complete = complete
        return GitHubOrganizationDiscoveryResult(
            organization=org,
            items=items,
            total_count=total_count,
            pages_fetched=pages_fetched,
            inventory_complete=complete,
            retrieval_truncated=not retrieval_complete,
            failures=failures,
        )

    def collect_organization_audit_log(
        self,
        organization: str,
        *,
        since: Optional[str] = None,
        limit: int = 1000,
    ) -> GitHubAuditLogResult:
        """조직 Audit Log를 오래된 순으로 페이지 수집한다.

        이 메서드는 공급자 원문을 메모리로만 반환한다. 호출자는 즉시 최소 공통
        ``UsageEvent``로 변환해야 하며 원문 JSON을 DB·로그·API 응답에 남기면 안 된다.
        """
        if not self.token:
            raise AuthenticationError(
                "GitHub Audit Log 수집에 GITHUB_AUDIT_TOKEN이 필요합니다.",
                status_code=401,
            )
        org = (organization or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org):
            raise ConnectorError("올바른 GitHub organization 이름이 아닙니다.", status_code=400)
        if limit < 1 or limit > 10000:
            raise ConnectorError("GitHub Audit Log limit은 1~10000이어야 합니다.", status_code=400)

        events: List[Dict[str, Any]] = []
        parse_failure_count = 0
        pages_fetched = 0
        has_more = False
        page = 1
        while len(events) < limit and page <= 100:
            per_page = min(100, limit - len(events))
            params: Dict[str, Any] = {
                "include": "all",
                "order": "asc",
                "per_page": per_page,
                "page": page,
            }
            if since:
                # GitHub Audit Log 검색 구문. 정밀 시각은 수집 후 normalizer가 다시 거른다.
                params["phrase"] = f"created:>={str(since).strip()[:10]}"
            response = self.get(f"/orgs/{org}/audit-log", params=params)
            payload = response.json()
            if not isinstance(payload, list):
                raise ConnectorError("GitHub Audit Log 응답 형식이 올바르지 않습니다.")
            pages_fetched += 1
            events.extend(item for item in payload if isinstance(item, dict))
            parse_failure_count += sum(1 for item in payload if not isinstance(item, dict))
            has_more = 'rel="next"' in response.headers.get("Link", "")
            if not payload or not has_more:
                break
            page += 1

        truncated = has_more
        return GitHubAuditLogResult(
            organization=org,
            events=events[:limit],
            pages_fetched=pages_fetched,
            collection_complete=not truncated and parse_failure_count == 0,
            retrieval_truncated=truncated,
            latest_cursor=_latest_audit_cursor(events[:limit]),
            parse_failure_count=parse_failure_count,
        )

    @staticmethod
    def _organization_installation_to_nhi(
        payload: Dict[str, Any], *, organization: str, inventory_complete: bool
    ) -> GitHubNHIInput:
        installation_id = int(payload["id"])
        account = payload.get("account") or {}
        if not isinstance(account, dict):
            account = {}
        account_login = str(account.get("login") or organization)
        app_id = payload.get("app_id")
        app_slug = str(payload.get("app_slug") or f"github-app-{app_id or 'unknown'}")
        raw_permissions = payload.get("permissions") or {}
        if not isinstance(raw_permissions, dict):
            raise TypeError("permissions")
        permissions = {
            str(resource): str(level)
            for resource, level in raw_permissions.items()
            if resource and level
        }
        events = payload.get("events") or []
        if not isinstance(events, list):
            events = []
        repository_selection = str(payload.get("repository_selection") or "unknown")
        suspended_at = payload.get("suspended_at")

        return GitHubNHIInput(
            nhi_id=f"github-app-installation:{installation_id}",
            nhi_name=f"{app_slug}@{account_login}",
            nhi_type=GitHubNHIType.GITHUB_APP,
            # installation 대상 조직은 보안 책임자가 아니므로 Owner로 승격하지 않는다.
            owner=None,
            active=suspended_at is None,
            account={
                "installation_id": installation_id,
                "app_id": app_id,
                "app_slug": app_slug,
                "login": account_login,
                "account_id": account.get("id"),
                "account_type": account.get("type"),
                "target_type": payload.get("target_type"),
            },
            repositories=[],
            repository_selection=repository_selection,
            repository_inventory_complete=False,
            inventory_is_complete=inventory_complete,
            collection_source="github_org_installations_api",
            collection_evidence=[
                f"GET /orgs/{organization}/installations",
                f"installation_id={installation_id}",
                f"repository_selection={repository_selection}",
                "개별 접근 저장소 이름은 이 API 응답에 포함되지 않음",
            ],
            subscribed_events=[str(event) for event in events if event],
            suspended_at=suspended_at,
            raw_permissions=permissions,
            created_at=payload.get("created_at"),
        )

    def _accessible_repositories(
        self, headers: Optional[Dict[str, str]], *, max_pages: int = 5
    ) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
        """토큰으로 접근 가능한 Repository를 페이지 단위로 수집한다.

        토큰의 실제 Scope는 ``X-OAuth-Scopes`` 또는 별도 권한 API에서만 판단한다.
        Repository 응답의 ``permissions``는 개별 리소스 메타데이터로만 보존하며,
        토큰 전체 권한을 추정하는 근거로 승격하지 않는다.
        """
        resources: List[Dict[str, Any]] = []
        malformed_items = 0
        for page in range(1, max_pages + 1):
            try:
                response = self.get(
                    "/user/repos",
                    params={"per_page": 100, "page": page, "sort": "updated"},
                    headers=headers,
                )
            except ConnectorError as exc:
                logger.info("접근 가능 repo 조회 미완료(page=%d): %s", page, exc)
                return (
                    resources,
                    False,
                    f"GitHub Repository 조회가 {page}페이지에서 중단됨",
                )

            try:
                payload = response.json()
            except ValueError:
                logger.info("접근 가능 repo JSON 해석 오류(page=%d)", page)
                return resources, False, "GitHub Repository 응답을 해석할 수 없음"
            if not isinstance(payload, list):
                logger.info("접근 가능 repo 응답 형식 오류(page=%d)", page)
                return resources, False, "GitHub Repository 응답 형식을 확인할 수 없음"

            for item in payload:
                if not isinstance(item, dict):
                    malformed_items += 1
                    continue
                owner = item.get("owner")
                resources.append(
                    {
                        "name": item.get("name"),
                        "full_name": item.get("full_name"),
                        "private": item.get("private"),
                        "owner_login": owner.get("login") if isinstance(owner, dict) else None,
                    }
                )
            has_next = 'rel="next"' in response.headers.get("Link", "")
            if not has_next:
                if malformed_items:
                    return (
                        resources,
                        False,
                        f"GitHub Repository 응답 {malformed_items}건을 해석하지 못함",
                    )
                return resources, True, None

        return (
            resources,
            False,
            f"GitHub Repository 조회 상한({max_pages * 100}개)에 도달함",
        )

    # ------------------------------------------------------------------
    # Repository
    # ------------------------------------------------------------------
    def get_repository(self, full_name: str) -> Repository:
        """Repository 정보 조회."""
        payload = self.get(f"/repos/{full_name}").json()
        return Repository(
            full_name=payload["full_name"],
            default_branch=payload.get("default_branch", "main"),
            private=payload.get("private", True),
            html_url=payload.get("html_url", ""),
            raw=payload,
        )

    def register_repository(self, full_name: str) -> Repository:
        """Repository 등록.

        실제 접근 가능 여부와 Webhook 권한을 확인한 뒤 등록 정보를 반환한다.
        (영속화는 `storage/` 의 Repository 테이블에서 담당)
        """
        repo = self.get_repository(full_name)
        permissions = repo.raw.get("permissions", {})
        if not permissions.get("pull", True):
            raise ConnectorError(
                f"{full_name} 에 대한 읽기 권한이 없습니다. 토큰 Scope 를 확인하세요."
            )
        repo.registered_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        logger.info("repository 등록: %s (default_branch=%s)", full_name, repo.default_branch)
        return repo

    def list_branches(self, full_name: str) -> List[Dict[str, Any]]:
        """브랜치 목록 조회."""
        branches = self._paginate(f"/repos/{full_name}/branches", per_page=100)
        return [
            {
                "name": b.get("name"),
                "commit_sha": (b.get("commit") or {}).get("sha"),
                "protected": b.get("protected", False),
            }
            for b in branches
        ]

    def list_files(
        self, full_name: str, ref: Optional[str] = None, *, scannable_only: bool = True
    ) -> List[Dict[str, Any]]:
        """전체 파일 목록 조회 (Git Tree recursive)."""
        ref = ref or self.get_repository(full_name).default_branch
        payload = self.get(
            f"/repos/{full_name}/git/trees/{ref}", params={"recursive": "1"}
        ).json()

        if payload.get("truncated"):
            logger.warning("%s@%s 트리가 잘렸습니다. 일부 파일이 누락될 수 있습니다.", full_name, ref)

        files = [
            {"path": item["path"], "sha": item.get("sha"), "size": item.get("size", 0)}
            for item in payload.get("tree", [])
            if item.get("type") == "blob"
        ]
        if scannable_only:
            files = [f for f in files if is_scannable_path(f["path"])]
        return files

    # ------------------------------------------------------------------
    # 파일 내용
    # ------------------------------------------------------------------
    def get_file_content(self, full_name: str, path: str, ref: Optional[str] = None) -> Optional[str]:
        """파일 내용을 텍스트로 조회. 바이너리/미존재 시 None."""
        params = {"ref": ref} if ref else None
        try:
            payload = self.get(f"/repos/{full_name}/contents/{path}", params=params).json()
        except NotFoundError:
            return None

        if isinstance(payload, list):  # 디렉터리
            return None

        encoding = payload.get("encoding")
        content = payload.get("content", "")
        if encoding != "base64":
            return content if isinstance(content, str) else None

        try:
            raw = base64.b64decode(content)
        except Exception:
            return None
        if b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", errors="replace")

    def build_scan_targets(
        self, full_name: str, paths: Iterable[str], ref: Optional[str] = None
    ) -> List[ScanTarget]:
        """경로 목록 → 스캐너 입력(ScanTarget) 변환."""
        targets: List[ScanTarget] = []
        for path in paths:
            if not is_scannable_path(path):
                continue
            content = self.get_file_content(full_name, path, ref=ref)
            if content is None:
                continue
            targets.append(ScanTarget(path=path, content=content, ref=ref))
        return targets

    # ------------------------------------------------------------------
    # 변경 파일
    # ------------------------------------------------------------------
    def get_commit_files(self, full_name: str, sha: str) -> List[Dict[str, Any]]:
        """Commit 변경 파일 목록."""
        payload = self.get(f"/repos/{full_name}/commits/{sha}").json()
        return self._normalize_files(payload.get("files", []))

    def compare_commits(self, full_name: str, base: str, head: str) -> List[Dict[str, Any]]:
        """두 커밋 사이 변경 파일 (push 이벤트의 before..after 처리용)."""
        payload = self.get(f"/repos/{full_name}/compare/{base}...{head}").json()
        return self._normalize_files(payload.get("files", []))

    def get_pull_request_files(self, full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Pull Request 변경 파일 목록."""
        files = self._paginate(f"/repos/{full_name}/pulls/{pr_number}/files", per_page=100)
        return self._normalize_files(files)

    def get_pull_request(self, full_name: str, pr_number: int) -> Dict[str, Any]:
        return self.get(f"/repos/{full_name}/pulls/{pr_number}").json()

    @staticmethod
    def _normalize_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for f in files:
            status = f.get("status", "modified")
            if status not in _SCANNABLE_STATUSES:
                continue
            normalized.append(
                {
                    "path": f.get("filename"),
                    "status": status,
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "sha": f.get("sha"),
                    "patch": f.get("patch"),
                }
            )
        return normalized

    # ------------------------------------------------------------------
    # 변경분 기반 스캔 타깃
    # ------------------------------------------------------------------
    def scan_targets_for_commit(self, full_name: str, sha: str) -> List[ScanTarget]:
        files = self.get_commit_files(full_name, sha)
        return self.build_scan_targets(full_name, [f["path"] for f in files], ref=sha)

    def scan_targets_for_pull_request(self, full_name: str, pr_number: int) -> List[ScanTarget]:
        pr = self.get_pull_request(full_name, pr_number)
        head_sha = (pr.get("head") or {}).get("sha")
        files = self.get_pull_request_files(full_name, pr_number)
        return self.build_scan_targets(full_name, [f["path"] for f in files], ref=head_sha)

    # ------------------------------------------------------------------
    # Rate Limit
    # ------------------------------------------------------------------
    def get_rate_limit(self) -> Dict[str, Any]:
        """현재 Rate Limit 상태 조회 (이 호출 자체는 한도를 소모하지 않는다)."""
        return self.get("/rate_limit").json()

    def _rate_limit_wait(self, response: httpx.Response) -> Optional[float]:
        """GitHub 의 Rate Limit 규약을 반영한 대기 시간 계산.

        * 429 또는 403 + `x-ratelimit-remaining: 0` → primary rate limit
        * 403 + `retry-after` → secondary rate limit (abuse detection)
        """
        headers = response.headers
        status = response.status_code

        retry_after = headers.get("retry-after")
        if status in (403, 429) and retry_after:
            try:
                return self._capped(float(retry_after))
            except ValueError:
                pass

        remaining = headers.get("x-ratelimit-remaining")
        if status in (403, 429) and remaining is not None and remaining.isdigit():
            if int(remaining) <= self.rate_limit_buffer:
                reset = headers.get("x-ratelimit-reset")
                if reset and reset.isdigit():
                    return self._capped(max(0.0, int(reset) - time.time()) + 1.0)
                return self._capped(60.0)

        if status == 429:
            return self._capped(60.0)
        return None

    def _capped(self, seconds: float) -> float:
        """대기 시간이 과도하면 즉시 RateLimitError 로 올린다."""
        if seconds > self.max_wait_seconds:
            raise RateLimitError(
                f"GitHub Rate Limit 해제까지 {seconds:.0f}초가 필요합니다. "
                f"(허용 대기 {self.max_wait_seconds}초 초과) — 나중에 재시도하세요.",
                retry_after=seconds,
                status_code=429,
            )
        return seconds

    # ------------------------------------------------------------------
    def _paginate(self, path: str, *, per_page: int = 100, max_pages: int = 20) -> List[Any]:
        """Link 헤더 기반 페이지네이션."""
        results: List[Any] = []
        page = 1
        while page <= max_pages:
            response = self.get(path, params={"per_page": per_page, "page": page})
            batch = response.json()
            if not isinstance(batch, list) or not batch:
                break
            results.extend(batch)
            if len(batch) < per_page or 'rel="next"' not in response.headers.get("Link", ""):
                break
            page += 1
        return results
