"""Scope Translation Agent — 서비스별 API Scope → 공통 권한(Read/Write/Delete/Admin).

서비스마다 Scope 표기가 달라 그대로는 비교·점수화가 불가능하다.
이 Agent 가 공통 권한 4종으로 정규화해 위험 점수와 Blast Radius 계산의
단일 기준을 만든다.

우선순위
  1. provider 별 매핑 테이블 (정확)
  2. 공통 매핑 테이블
  3. 문자열 휴리스틱 (inferred=True 로 표시)
  4. Scope 자체를 못 얻은 경우 Secret 유형 기준 보수적 가정 (assumed=True)

AWS 는 이 우선순위를 타지 않는다. IAM Action(`s3:GetObject` 등)은 OAuth
Scope 와 표기 체계가 달라 공통 매핑 테이블/문자열 휴리스틱으로 다루면
`iam:DeleteUser` 같은 Action 을 "DELETE"로 잘못 분류하는 등 부정확해진다
— `agents/aws_permission_mapper.py::map_action()` 을 그대로 재사용하는
별도 경로(`_translate_aws()`)로 처리하고, 이 파일의 `SCOPE_TABLE`/
`COMMON_SCOPE_TABLE`/`_infer()` 휴리스틱은 건드리지 않는다(GitHub/Slack
동작 무변경). `map_action()` 이 모른다고 답한(`None`) Action 은 추측하지
않고 "해석 불가"로 남긴다.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Tuple

from agents.aws_permission_mapper import map_action
from core.models import SecretFinding
from core.nhi_models import (
    PERMISSION_RANK,
    PermissionLevel,
    PermissionProfile,
    ScopeMapping,
)

logger = logging.getLogger(__name__)

R, W, D, A = (
    PermissionLevel.READ,
    PermissionLevel.WRITE,
    PermissionLevel.DELETE,
    PermissionLevel.ADMIN,
)

#: provider 별 Scope → (공통 권한, 설명)
SCOPE_TABLE: Dict[str, Dict[str, Tuple[PermissionLevel, str]]] = {
    "slack": {
        "channels:history": (R, "Slack 채널 메시지 조회"),
        "channels:read": (R, "Slack 채널 목록 조회"),
        "groups:read": (R, "비공개 채널 목록 조회"),
        "groups:history": (R, "비공개 채널 메시지 조회"),
        "im:history": (R, "DM 메시지 조회"),
        "mpim:history": (R, "그룹 DM 메시지 조회"),
        "users:read": (R, "사용자 목록 조회"),
        "users:read.email": (R, "사용자 이메일 조회"),
        "files:read": (R, "Slack 파일 조회"),
        "team:read": (R, "워크스페이스 정보 조회"),
        "chat:write": (W, "Slack 메시지 작성"),
        "chat:write.public": (W, "미참여 공개 채널 메시지 작성"),
        "files:write": (W, "Slack 파일 업로드"),
        "channels:manage": (A, "채널 생성·보관·삭제 관리"),
        "groups:write": (W, "비공개 채널 관리"),
        "im:write": (W, "DM 발송"),
        "reactions:write": (W, "리액션 추가"),
        "files:delete": (D, "Slack 파일 삭제"),
        "chat:delete": (D, "Slack 메시지 삭제"),
        "admin": (A, "워크스페이스 관리자 권한"),
        "admin.users:write": (A, "사용자 계정 관리"),
        "admin.conversations:write": (A, "전체 대화 관리"),
    },
    # GitHub 은 두 가지 표기가 섞여 들어온다.
    #   * OAuth/PAT scope   — `repo`, `delete_repo`, `admin:org` ...
    #   * App 권한(자원:수준) — `contents:write`, `administration:write` ...
    # 둘을 같은 테이블에 둬서 인벤토리 입력과 토큰 검증 결과를 같은 기준으로 변환한다.
    "github": {
        "metadata:read": (R, "Repository 메타데이터 조회"),
        "contents:read": (R, "Repository 파일 조회"),
        "actions:read": (R, "GitHub Actions 워크플로 조회"),
        "issues:read": (R, "이슈 조회"),
        "pull_requests:read": (R, "PR 조회"),
        "deployments:read": (R, "배포 정보 조회"),
        "administration:read": (R, "저장소 설정 조회"),
        "members:read": (R, "조직 구성원·팀 조회"),
        "secrets:read": (R, "Actions Secret 목록 조회"),
        "repo:status": (R, "커밋 상태 조회"),
        "read:org": (R, "Organization 정보 조회"),
        "read:user": (R, "사용자 정보 조회"),
        "read:packages": (R, "패키지 조회"),
        "security_events": (R, "보안 이벤트 조회"),
        "contents:write": (W, "GitHub Repository 파일 수정"),
        "actions:write": (W, "GitHub Actions 워크플로 실행·수정"),
        "deployments:write": (W, "배포 생성·관리"),
        "public_repo": (W, "공개 Repository 쓰기"),
        "workflow": (W, "GitHub Actions 워크플로 수정"),
        "issues:write": (W, "이슈 생성·수정"),
        "pull_requests:write": (W, "PR 생성·수정"),
        "write:packages": (W, "패키지 게시"),
        "gist": (W, "Gist 생성·수정"),
        "delete_repo": (D, "Repository 삭제"),
        "delete:packages": (D, "패키지 삭제"),
        # 저장소 설정·구성원·Secret 관리는 write 라도 실질적으로 관리자 권한이다.
        "administration:write": (A, "저장소 설정과 관리 기능 접근"),
        "members:write": (A, "조직 구성원·팀 관리"),
        "secrets:write": (A, "Actions·환경 Secret 관리"),
        "repo": (A, "Repository 전반 접근"),
        "admin:org": (A, "Organization 관리"),
        "admin:repo_hook": (A, "Repository Webhook 관리"),
        "admin:public_key": (A, "배포 키 관리"),
        "admin:enterprise": (A, "Enterprise 관리"),
        "site_admin": (A, "사이트 관리자"),
    },
    "gitlab": {
        "read_api": (R, "GitLab API 읽기"),
        "read_repository": (R, "저장소 조회"),
        "read_registry": (R, "컨테이너 레지스트리 조회"),
        "read_user": (R, "사용자 정보 조회"),
        "write_repository": (W, "저장소 쓰기"),
        "write_registry": (W, "레지스트리 게시"),
        "api": (A, "GitLab API 전체 접근"),
        "sudo": (A, "다른 사용자 권한 대행"),
        "admin_mode": (A, "관리자 모드"),
    },
    "notion": {
        "read_content": (R, "Notion 페이지·DB 조회"),
        "read_user_with_email": (R, "사용자 정보 조회"),
        "read_comment": (R, "댓글 조회"),
        "insert_content": (W, "Notion 페이지 생성"),
        "update_content": (W, "Notion 페이지 수정"),
        "insert_comment": (W, "댓글 작성"),
    },
    "huggingface": {
        "read": (R, "모델·데이터셋 조회"),
        "repo.content.read": (R, "Repository 콘텐츠 조회"),
        "write": (W, "모델·데이터셋 업로드"),
        "repo.content.write": (W, "Repository 콘텐츠 수정"),
        "repo.write": (W, "Repository 쓰기"),
        "inference.endpoints.write": (W, "추론 엔드포인트 생성"),
        "repo.delete": (D, "Repository 삭제"),
        "org.write": (A, "Organization 관리"),
        "admin": (A, "전체 관리 권한"),
    },
}

#: provider 무관 공통 표기
COMMON_SCOPE_TABLE: Dict[str, Tuple[PermissionLevel, str]] = {
    "read": (R, "읽기 전용"),
    "readonly": (R, "읽기 전용"),
    "read-only": (R, "읽기 전용"),
    "list": (R, "목록 조회"),
    "get": (R, "단건 조회"),
    "view": (R, "조회"),
    "write": (W, "쓰기"),
    "create": (W, "생성"),
    "update": (W, "수정"),
    "edit": (W, "수정"),
    "put": (W, "수정"),
    "post": (W, "생성"),
    "push": (W, "업로드"),
    "delete": (D, "삭제"),
    "destroy": (D, "삭제"),
    "purge": (D, "영구 삭제"),
    "drop": (D, "삭제"),
    "admin": (A, "관리자"),
    "owner": (A, "소유자"),
    "manage": (A, "관리"),
    "superuser": (A, "최고 권한"),
    "root": (A, "최고 권한"),
    "*": (A, "전체 권한"),
    "full_access": (A, "전체 권한"),
}

#: 휴리스틱 판정용 토큰 (뒤쪽일수록 강한 권한)
_HEURISTIC_TOKENS: Tuple[Tuple[PermissionLevel, Tuple[str, ...]], ...] = (
    (R, ("read", "list", "view", "get", "history", "search", "scan", "describe")),
    (W, ("write", "create", "update", "edit", "insert", "upload", "push", "send", "publish")),
    (D, ("delete", "remove", "destroy", "purge", "drop", "terminate")),
    (A, ("admin", "manage", "owner", "root", "superuser", "full", "*", "sudo")),
)

#: Scope 를 확인할 수 없을 때 Secret 유형별 보수적 가정
ASSUMED_PERMISSIONS: Dict[str, List[PermissionLevel]] = {
    "SLACK_BOT_TOKEN": [R, W],
    "SLACK_USER_TOKEN": [R, W],
    "SLACK_APP_TOKEN": [R, W],
    "SLACK_WEBHOOK_URL": [W],
    "SLACK_SIGNING_SECRET": [R],
    "GITHUB_PAT": [R, W, D, A],
    "GITHUB_FINE_GRAINED_PAT": [R, W],
    "GITLAB_PAT": [R, W, A],
    "AWS_ACCESS_KEY_ID": [R, W, D, A],
    "AWS_SECRET_ACCESS_KEY": [R, W, D, A],
    "GOOGLE_API_KEY": [R, W],
    "GCP_SERVICE_ACCOUNT_KEY": [R, W, D, A],
    "ANTHROPIC_API_KEY": [R, W],
    "OPENAI_API_KEY": [R, W],
    "HUGGINGFACE_TOKEN": [R, W],
    "NOTION_INTEGRATION_TOKEN": [R, W],
    "STRIPE_SECRET_KEY": [R, W, D, A],
    "SENDGRID_API_KEY": [R, W],
    "NPM_ACCESS_TOKEN": [R, W],
    "PRIVATE_KEY_BLOCK": [R, W, D, A],
    "JWT_TOKEN": [R, W],
    "BASIC_AUTH_URL": [R, W],
    "GENERIC_API_KEY": [R, W],
}

#: 가정 시 기본값 (알 수 없는 유형)
DEFAULT_ASSUMED = [R, W]


class ScopeTranslationAgent:
    """서비스별 Scope 를 공통 권한으로 변환한다."""

    def translate(
        self,
        raw_scopes: Iterable[str],
        *,
        provider: str = "generic",
        secret_type: str = "",
        assume_if_missing: bool = True,
    ) -> PermissionProfile:
        scopes = [s.strip() for s in (raw_scopes or []) if s and s.strip()]
        profile = PermissionProfile(raw_scopes=scopes)

        if (provider or "").strip().lower() == "aws":
            return self._translate_aws(profile, scopes, secret_type, assume_if_missing)

        if not scopes and assume_if_missing:
            return self._assume(profile, secret_type)

        table = SCOPE_TABLE.get(provider.lower(), {})
        for scope in scopes:
            mapping = self._translate_one(scope, table)
            profile.mappings.append(mapping)
            if mapping.permission is None:
                profile.unknown_scopes.append(scope)

        permissions = {m.permission for m in profile.mappings if m.permission}
        if not permissions:
            # Scope 는 있었지만 하나도 해석하지 못한 경우 → 가정으로 대체
            logger.info("해석 가능한 scope 없음 (provider=%s) — 유형 기준 가정", provider)
            if assume_if_missing:
                return self._assume(profile, secret_type)
            return profile

        profile.permissions = self._sorted(permissions)
        return profile

    def translate_scope(self, scope: str, *, provider: str = "generic") -> ScopeMapping:
        """Scope 1건만 변환한다 (감사 로그의 행위 → 권한 변환 등에 사용)."""
        if (provider or "").strip().lower() == "aws":
            return self._map_aws_action(scope)
        return self._translate_one(scope, SCOPE_TABLE.get((provider or "").lower(), {}))

    def translate_finding(
        self,
        finding: SecretFinding,
        *,
        assume_if_missing: bool = True,
    ) -> PermissionProfile:
        """`SecretFinding` 의 raw_scopes 를 변환한다."""
        return self.translate(
            finding.raw_scopes,
            provider=finding.provider,
            secret_type=finding.secret_type,
            assume_if_missing=assume_if_missing,
        )

    # ------------------------------------------------------------------
    # AWS — GitHub/Slack 과 완전히 분리된 경로
    #
    # IAM Action(`s3:GetObject` 등)은 OAuth Scope 가 아니라서 `SCOPE_TABLE`/
    # `COMMON_SCOPE_TABLE`/`_infer()` 문자열 휴리스틱을 그대로 타면 부정확
    # 하다(예: `_infer()` 는 "delete" 토큰만 보고 `iam:DeleteUser` 를 DELETE
    # 로 분류하지만, 실제로는 신원 자체를 지우는 ADMIN 급 행위다).
    # `agents/aws_permission_mapper.py::map_action()` 이 이미 이 구분을
    # 정확히 하므로 그 결과를 그대로 재사용하고, 이 클래스에서 다시
    # 해석하거나 짐작을 보태지 않는다.
    # ------------------------------------------------------------------
    def _translate_aws(
        self,
        profile: PermissionProfile,
        scopes: List[str],
        secret_type: str,
        assume_if_missing: bool,
    ) -> PermissionProfile:
        """AWS Action 문자열 목록을 `map_action()` 으로 그대로 변환한다.

        `map_action()` 이 알아보지 못한(`None`) Action 은 추측하지 않고
        "해석 불가"로 남긴다 — GitHub/Slack 처럼 문자열 휴리스틱으로
        대체하지 않는다. `assume_if_missing` 의미(Scope 자체가 없을 때만
        Secret 유형 기준으로 가정)는 다른 provider 와 동일하게 유지한다.
        """
        if not scopes and assume_if_missing:
            return self._assume(profile, secret_type)

        for scope in scopes:
            mapping = self._map_aws_action(scope)
            profile.mappings.append(mapping)
            if mapping.permission is None:
                profile.unknown_scopes.append(scope)

        permissions = {m.permission for m in profile.mappings if m.permission}
        if not permissions:
            logger.info("해석 가능한 AWS Action 없음 — 유형 기준 가정 여부만 확인")
            if assume_if_missing:
                return self._assume(profile, secret_type)
            return profile

        profile.permissions = self._sorted(permissions)
        return profile

    @staticmethod
    def _map_aws_action(action: str) -> ScopeMapping:
        """AWS Action 1건 → `ScopeMapping`. `map_action()` 을 그대로 감싼다."""
        level = map_action(action)
        return ScopeMapping(
            raw_scope=action,
            permission=level,
            description="AWS Action 매핑" if level is not None else "해석 불가한 AWS Action",
            # map_action() 은 AWS 명명 관례에 기반한 확정 규칙이라(추측이
            # 아니라 정책상 그렇게 정의됨) inferred=False 로 취급한다 —
            # GitHub/Slack 의 문자열 휴리스틱(`_infer()`)과는 성격이 다르다.
            inferred=False,
        )

    # ------------------------------------------------------------------
    def _translate_one(
        self, scope: str, table: Dict[str, Tuple[PermissionLevel, str]]
    ) -> ScopeMapping:
        key = scope.strip().lower()

        entry = table.get(key) or COMMON_SCOPE_TABLE.get(key)
        if entry:
            return ScopeMapping(raw_scope=scope, permission=entry[0], description=entry[1])

        # `repo:status` 처럼 접두만 일치하는 경우
        for known, value in table.items():
            if key.startswith(f"{known}:") or key.startswith(f"{known}."):
                return ScopeMapping(
                    raw_scope=scope,
                    permission=value[0],
                    description=f"{value[1]} (상위 scope {known} 기준)",
                    inferred=True,
                )

        inferred = self._infer(key)
        if inferred is not None:
            return ScopeMapping(
                raw_scope=scope,
                permission=inferred,
                description="문자열 패턴으로 추정한 권한",
                inferred=True,
            )
        return ScopeMapping(raw_scope=scope, permission=None, description="해석 불가한 scope")

    @staticmethod
    def _infer(scope: str) -> Optional[PermissionLevel]:
        """토큰 매칭 — 가장 강한 권한을 채택한다."""
        found: Optional[PermissionLevel] = None
        for level, tokens in _HEURISTIC_TOKENS:
            if any(token in scope for token in tokens):
                if found is None or PERMISSION_RANK[level] > PERMISSION_RANK[found]:
                    found = level
        return found

    def _assume(self, profile: PermissionProfile, secret_type: str) -> PermissionProfile:
        assumed = ASSUMED_PERMISSIONS.get(secret_type, DEFAULT_ASSUMED)
        profile.permissions = self._sorted(assumed)
        profile.assumed = True
        profile.mappings.append(
            ScopeMapping(
                raw_scope="(scope 미확인)",
                permission=profile.highest,
                description=f"{secret_type or '미분류'} 유형 기준 보수적 가정",
                inferred=True,
            )
        )
        return profile

    @staticmethod
    def _sorted(permissions: Iterable[PermissionLevel]) -> List[PermissionLevel]:
        return sorted(set(permissions), key=lambda p: PERMISSION_RANK[p])


def expand_permissions(permissions: Iterable[PermissionLevel]) -> set:
    """상위 권한이 함의하는 하위 권한까지 펼친다 (ADMIN ⊃ DELETE ⊃ WRITE ⊃ READ)."""
    perms = set(permissions)
    if PermissionLevel.ADMIN in perms:
        perms |= {PermissionLevel.DELETE, PermissionLevel.WRITE, PermissionLevel.READ}
    if PermissionLevel.DELETE in perms:
        perms |= {PermissionLevel.WRITE, PermissionLevel.READ}
    if PermissionLevel.WRITE in perms:
        perms.add(PermissionLevel.READ)
    return perms
