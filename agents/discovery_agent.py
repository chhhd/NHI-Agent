"""Discovery Agent — 탐지된 Credential 이 어떤 NHI 에 연결되는지 식별한다.

수행 항목
  1. Secret 유형 분석          (pattern_registry 기준)
  2. Provider 식별             (탐지 결과 + 변수명/문맥 보정)
  3. NHI 유형 분류             (SLACK_BOT / GITHUB_MACHINE_USER / AI_AGENT_CREDENTIAL ...)
  4. Bot·서비스 계정 식별
  5. 연결된 AI Agent 추정
  6. Owner 후보 추출
  7. Credential–NHI 관계 생성
  8. 식별 불가 시 UNKNOWN_NHI 처리
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

from agents.heuristics import (
    context_lines,
    context_text,
    extract_variable_name,
    humanize,
    owner_candidates_from_text,
    path_parts,
    path_text,
)
from core.models import SecretFinding
from core.nhi_models import AnalysisSignals, NHIProfile, NHIType
from scanner.pattern_registry import PATTERN_REGISTRY

logger = logging.getLogger(__name__)

#: Secret 유형 → NHI 유형
SECRET_TYPE_TO_NHI: Dict[str, NHIType] = {
    "SLACK_BOT_TOKEN": NHIType.SLACK_BOT,
    "SLACK_USER_TOKEN": NHIType.SLACK_USER_TOKEN,
    "SLACK_APP_TOKEN": NHIType.SLACK_APP,
    "SLACK_WEBHOOK_URL": NHIType.SLACK_WEBHOOK,
    "SLACK_SIGNING_SECRET": NHIType.SIGNING_KEY,
    "GITHUB_PAT": NHIType.GITHUB_MACHINE_USER,
    "GITHUB_FINE_GRAINED_PAT": NHIType.GITHUB_MACHINE_USER,
    "GITLAB_PAT": NHIType.GITLAB_SERVICE_ACCOUNT,
    "AWS_ACCESS_KEY_ID": NHIType.CLOUD_SERVICE_ACCOUNT,
    "AWS_SECRET_ACCESS_KEY": NHIType.CLOUD_SERVICE_ACCOUNT,
    "GOOGLE_API_KEY": NHIType.CLOUD_SERVICE_ACCOUNT,
    "GCP_SERVICE_ACCOUNT_KEY": NHIType.CLOUD_SERVICE_ACCOUNT,
    "ANTHROPIC_API_KEY": NHIType.AI_AGENT_CREDENTIAL,
    "OPENAI_API_KEY": NHIType.AI_AGENT_CREDENTIAL,
    "HUGGINGFACE_TOKEN": NHIType.AI_AGENT_CREDENTIAL,
    "NOTION_INTEGRATION_TOKEN": NHIType.NOTION_INTEGRATION,
    "STRIPE_SECRET_KEY": NHIType.PAYMENT_SERVICE_ACCOUNT,
    "SENDGRID_API_KEY": NHIType.MAIL_SERVICE_ACCOUNT,
    "NPM_ACCESS_TOKEN": NHIType.REGISTRY_SERVICE_ACCOUNT,
    "PRIVATE_KEY_BLOCK": NHIType.SIGNING_KEY,
    "JWT_TOKEN": NHIType.GENERIC_SERVICE_ACCOUNT,
    "BASIC_AUTH_URL": NHIType.GENERIC_SERVICE_ACCOUNT,
    "GENERIC_API_KEY": NHIType.GENERIC_SERVICE_ACCOUNT,
}

#: provider 를 알 수 없을 때 변수명/문맥에서 찾는 키워드
PROVIDER_KEYWORDS: Dict[str, tuple] = {
    "slack": ("slack", "xoxb", "xoxp"),
    "github": ("github", "gh_token", "ghp_"),
    "gitlab": ("gitlab", "glpat"),
    "aws": ("aws", "amazon", "s3_", "dynamodb"),
    "google": ("google", "gcp", "firebase", "bigquery"),
    "anthropic": ("anthropic", "claude"),
    "openai": ("openai", "gpt", "chatgpt"),
    "huggingface": ("huggingface", "hugging_face", "hf_"),
    "notion": ("notion",),
    "stripe": ("stripe",),
    "sendgrid": ("sendgrid",),
    "npm": ("npm", "registry.npmjs"),
}

#: AI Agent 연결 추정 키워드
AI_AGENT_KEYWORDS = (
    "agent", "langchain", "llamaindex", "llama_index", "crewai", "autogen",
    "assistant", "copilot", "chatbot", "llm", "rag", "mcp", "claude", "gpt",
    "openai", "anthropic", "bedrock", "vertex",
)

#: AI Agent 가 직접 사용하는 provider
AI_PROVIDERS = {"anthropic", "openai", "huggingface"}

#: Agent 이름으로 쓰기엔 총칭적인 디렉터리 (더 구체적인 조각을 찾는다)
_GENERIC_AGENT_DIRS = {"agents", "agent", "bots", "bot", "llm", "llms", "ai", "mcp"}

#: 서비스 계정으로 볼 수 있는 경로/변수 키워드
SERVICE_ACCOUNT_KEYWORDS = (
    "service", "svc", "ci", "cd", "pipeline", "deploy", "automation", "worker",
    "cron", "batch", "integration", "machine", "runner",
)

BOT_KEYWORDS = ("bot", "webhook", "notifier", "alert")

#: 변수명에서 잘라낼 접미 토큰 (이름 추출용)
_NAME_SUFFIXES = (
    "token", "key", "apikey", "api", "secret", "credential", "credentials",
    "password", "pat", "access", "auth", "id",
)

#: 이름으로 쓰기엔 정보가 없는 변수명
_GENERIC_VARIABLE_NAMES = {
    "", "token", "key", "secret", "api", "apikey", "api-key", "password",
    "credential", "credentials", "auth", "value", "config", "settings",
}


class DiscoveryAgent:
    """Credential → NHI 매핑."""

    def analyze(
        self, finding: SecretFinding, signals: Optional[AnalysisSignals] = None
    ) -> NHIProfile:
        signals = signals or AnalysisSignals()
        account = self._account(finding)
        evidence: List[str] = []

        provider = self._identify_provider(finding, evidence)
        nhi_type = self._classify_nhi_type(finding, provider, account, evidence)
        name = self._resolve_name(finding, provider, account, nhi_type, evidence)
        is_bot, is_service_account = self._classify_actor(finding, nhi_type, account, evidence)
        linked_agent = self._infer_ai_agent(finding, provider, nhi_type, signals, evidence)
        owner, owner_candidates, owner_source = self._resolve_owner(
            finding, account, signals, evidence
        )

        identified = self._is_identified(nhi_type, account, name)
        if not identified:
            nhi_type = NHIType.UNKNOWN_NHI
            evidence.append("NHI 를 특정할 근거가 부족해 UNKNOWN_NHI 로 분류")

        pattern = PATTERN_REGISTRY.get(finding.secret_type)
        profile = NHIProfile(
            nhi_id=self._build_nhi_id(provider, name, account, finding, identified),
            nhi_name=name,
            nhi_type=nhi_type,
            provider=provider,
            secret_type=finding.secret_type,
            secret_name=pattern.name if pattern else "Unclassified High Entropy String",
            is_bot=is_bot,
            is_service_account=is_service_account,
            linked_ai_agent=linked_agent,
            owner=owner,
            owner_candidates=owner_candidates,
            owner_source=owner_source,
            account=account,
            identified=identified,
            evidence=evidence,
            credential_fingerprint=finding.fingerprint,
        )
        profile.confidence = self._confidence(profile, account)
        return profile

    # ------------------------------------------------------------------
    # 1) Secret 유형 / 2) Provider
    # ------------------------------------------------------------------
    @staticmethod
    def _account(finding: SecretFinding) -> Dict[str, object]:
        detail = finding.credential_detail or {}
        account = detail.get("account") or {}
        return dict(account) if isinstance(account, dict) else {}

    def _identify_provider(self, finding: SecretFinding, evidence: List[str]) -> str:
        provider = (finding.provider or "unknown").lower()
        if provider not in ("", "unknown", "generic"):
            evidence.append(f"패턴 기반 provider 식별: {provider}")
            return provider

        haystack = " ".join(
            [extract_variable_name(finding) or "", path_text(finding.file_path), context_text(finding)]
        ).lower()
        for candidate, keywords in PROVIDER_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                evidence.append(f"문맥 키워드로 provider 추정: {candidate}")
                return candidate
        evidence.append("provider 식별 불가")
        return provider or "unknown"

    # ------------------------------------------------------------------
    # 3) NHI 유형
    # ------------------------------------------------------------------
    def _classify_nhi_type(
        self,
        finding: SecretFinding,
        provider: str,
        account: Dict[str, object],
        evidence: List[str],
    ) -> NHIType:
        nhi_type = SECRET_TYPE_TO_NHI.get(finding.secret_type)

        # GitHub 은 계정 유형으로 App / Machine User 를 구분할 수 있다.
        if nhi_type is NHIType.GITHUB_MACHINE_USER:
            login = str(account.get("login") or "").lower()
            if str(account.get("type") or "").lower() == "bot" or login.endswith("[bot]"):
                evidence.append("GitHub 계정 유형이 Bot — GITHUB_APP 으로 분류")
                return NHIType.GITHUB_APP

        if nhi_type is not None:
            evidence.append(f"Secret 유형 {finding.secret_type} → NHI 유형 {nhi_type.value}")
            return nhi_type

        # 패턴에 없는 유형(엔트로피 탐지 등)은 provider 로 한 번 더 시도
        by_provider = {
            "slack": NHIType.SLACK_BOT,
            "github": NHIType.GITHUB_MACHINE_USER,
            "gitlab": NHIType.GITLAB_SERVICE_ACCOUNT,
            "aws": NHIType.CLOUD_SERVICE_ACCOUNT,
            "google": NHIType.CLOUD_SERVICE_ACCOUNT,
            "notion": NHIType.NOTION_INTEGRATION,
        }
        if provider in AI_PROVIDERS:
            evidence.append("AI provider Credential — AI_AGENT_CREDENTIAL 로 분류")
            return NHIType.AI_AGENT_CREDENTIAL
        if provider in by_provider:
            evidence.append(f"provider {provider} 기준 NHI 유형 추정")
            return by_provider[provider]
        return NHIType.UNKNOWN_NHI

    # ------------------------------------------------------------------
    # NHI 이름
    # ------------------------------------------------------------------
    def _resolve_name(
        self,
        finding: SecretFinding,
        provider: str,
        account: Dict[str, object],
        nhi_type: NHIType,
        evidence: List[str],
    ) -> str:
        from_account = self._name_from_account(provider, account)
        if from_account:
            evidence.append(f"자격 증명 검증 응답에서 NHI 이름 확인: {from_account}")
            return from_account

        from_variable = self._name_from_variable(extract_variable_name(finding))
        if from_variable:
            evidence.append(f"변수명에서 NHI 이름 추정: {from_variable}")
            return from_variable

        # 마지막 수단 — 유형 + fingerprint 축약
        short = (finding.fingerprint or "").split(":")[-1][:8] or "unknown"
        return f"{humanize(nhi_type.value)}-{short}"

    @staticmethod
    def _name_from_account(provider: str, account: Dict[str, object]) -> Optional[str]:
        keys_by_provider = {
            "slack": ("user", "bot_id", "team"),
            "github": ("login", "name"),
            "gitlab": ("username", "token_name", "name"),
            "notion": ("name", "workspace_name"),
            "huggingface": ("token_name", "name"),
        }
        for key in keys_by_provider.get(provider, ("name", "login", "username")):
            value = account.get(key)
            if isinstance(value, str) and value.strip():
                return humanize(value.strip())
        return None

    @staticmethod
    def _name_from_variable(variable: Optional[str]) -> Optional[str]:
        if not variable:
            return None
        tokens = [t for t in re.split(r"[^A-Za-z0-9]+", humanize(variable)) if t]
        while tokens and tokens[-1].lower() in _NAME_SUFFIXES:
            tokens.pop()
        name = "-".join(tokens).lower()
        if name in _GENERIC_VARIABLE_NAMES:
            return None
        return name or None

    # ------------------------------------------------------------------
    # 4) Bot / 서비스 계정
    # ------------------------------------------------------------------
    def _classify_actor(
        self,
        finding: SecretFinding,
        nhi_type: NHIType,
        account: Dict[str, object],
        evidence: List[str],
    ) -> tuple:
        haystack = " ".join(
            [extract_variable_name(finding) or "", path_text(finding.file_path), context_text(finding)]
        ).lower()

        is_bot = nhi_type in {
            NHIType.SLACK_BOT,
            NHIType.SLACK_APP,
            NHIType.SLACK_WEBHOOK,
            NHIType.GITHUB_APP,
            NHIType.NOTION_INTEGRATION,
        }
        if account.get("bot_id") or str(account.get("type") or "").lower() == "bot":
            is_bot = True
        if not is_bot and any(k in haystack for k in BOT_KEYWORDS):
            is_bot = True
            evidence.append("문맥에 bot/webhook 키워드 — Bot 계정으로 판단")

        is_service_account = is_bot or nhi_type in {
            NHIType.CLOUD_SERVICE_ACCOUNT,
            NHIType.GITHUB_MACHINE_USER,
            NHIType.GITLAB_SERVICE_ACCOUNT,
            NHIType.PAYMENT_SERVICE_ACCOUNT,
            NHIType.MAIL_SERVICE_ACCOUNT,
            NHIType.REGISTRY_SERVICE_ACCOUNT,
            NHIType.AI_AGENT_CREDENTIAL,
            NHIType.GENERIC_SERVICE_ACCOUNT,
        }
        if not is_service_account and any(k in haystack for k in SERVICE_ACCOUNT_KEYWORDS):
            is_service_account = True
            evidence.append("CI/배포/자동화 문맥 — 서비스 계정으로 판단")

        if is_bot:
            evidence.append("Bot 계정으로 식별")
        return is_bot, is_service_account

    # ------------------------------------------------------------------
    # 5) 연결된 AI Agent 추정
    # ------------------------------------------------------------------
    def _infer_ai_agent(
        self,
        finding: SecretFinding,
        provider: str,
        nhi_type: NHIType,
        signals: AnalysisSignals,
        evidence: List[str],
    ) -> Optional[str]:
        if signals.agent_name:
            evidence.append(f"외부 신호로 AI Agent 확인: {signals.agent_name}")
            return signals.agent_name

        haystack = " ".join(
            [extract_variable_name(finding) or "", path_text(finding.file_path), context_text(finding)]
        ).lower()
        hits = [k for k in AI_AGENT_KEYWORDS if k in haystack]
        if not hits and provider not in AI_PROVIDERS and nhi_type is not NHIType.AI_AGENT_CREDENTIAL:
            return None

        # 경로 조각 중 agent 를 가장 잘 설명하는 이름을 고른다.
        # `agents/support_agent/config.py` 처럼 상위가 총칭 디렉터리인 경우가 많아
        # 깊은 쪽부터 보고, 총칭 이름은 건너뛴다.
        for part in reversed(path_parts(finding.file_path)):
            stem = part.rsplit(".", 1)[0]
            if stem in _GENERIC_AGENT_DIRS or len(stem) <= 3:
                continue
            if any(k in stem for k in AI_AGENT_KEYWORDS):
                evidence.append(f"경로에서 AI Agent 추정: {stem} (키워드: {', '.join(hits[:3])})")
                return humanize(stem)

        variable_name = self._name_from_variable(extract_variable_name(finding))
        if variable_name and any(k in variable_name for k in AI_AGENT_KEYWORDS):
            evidence.append(f"변수명에서 AI Agent 추정: {variable_name}")
            return variable_name

        if provider in AI_PROVIDERS or nhi_type is NHIType.AI_AGENT_CREDENTIAL:
            evidence.append(f"{provider} Credential — AI Agent 사용으로 추정 (이름 미상)")
            return f"unnamed-{provider}-agent"
        return None

    # ------------------------------------------------------------------
    # 6) Owner 후보
    # ------------------------------------------------------------------
    def _resolve_owner(
        self,
        finding: SecretFinding,
        account: Dict[str, object],
        signals: AnalysisSignals,
        evidence: List[str],
    ) -> tuple:
        candidates: List[str] = []

        def _add(value: Optional[object]) -> None:
            if isinstance(value, str) and value.strip() and value.strip() not in candidates:
                candidates.append(value.strip())

        # (a) 외부 신호 — 가장 신뢰도가 높다
        if signals.owner:
            _add(signals.owner)
            evidence.append(f"외부 신호로 Owner 확정: {signals.owner}")
        # (b) 자격 증명 검증 응답
        for key in ("team", "workspace_name", "login", "username", "name", "owner_type"):
            _add(account.get(key))
        owner_from_account = next(
            (
                str(account[k]).strip()
                for k in ("team", "workspace_name", "login", "username")
                if isinstance(account.get(k), str) and str(account[k]).strip()
            ),
            None,
        )
        # (c) 코드 주석의 소유자 표기
        from_comment = owner_candidates_from_text(context_lines(finding))
        for value in from_comment:
            _add(value)
        # (d) 경로 기반 팀 추정 (후보로만 사용)
        for part in path_parts(finding.file_path)[:-1]:
            if part in {"src", "app", "config", "configs", "lib", "services", "packages"}:
                continue
            if len(part) > 2 and "." not in part:
                _add(part)
                break
        # (e) Repository owner
        if signals.repository and "/" in signals.repository:
            _add(signals.repository.split("/")[0])

        if signals.owner:
            return signals.owner, candidates, "external_signal"
        if owner_from_account:
            evidence.append(f"자격 증명 응답에서 Owner 확인: {owner_from_account}")
            return owner_from_account, candidates, "credential_account"
        if from_comment:
            evidence.append(f"코드 주석에서 Owner 확인: {from_comment[0]}")
            return from_comment[0], candidates, "code_comment"

        evidence.append("Owner 미확정 — 후보만 존재")
        return None, candidates, None

    # ------------------------------------------------------------------
    # 7) Credential–NHI 관계 / 8) 식별 불가 처리
    # ------------------------------------------------------------------
    @staticmethod
    def _build_nhi_id(
        provider: str,
        name: str,
        account: Dict[str, object],
        finding: SecretFinding,
        identified: bool,
    ) -> str:
        short = (finding.fingerprint or "").split(":")[-1][:12] or "unknown"
        if not identified:
            return f"unknown-nhi:{short}"
        for key in ("bot_id", "app_id", "id", "user_id", "team_id"):
            value = account.get(key)
            if value:
                return f"{provider}:{value}"
        return f"{provider}:{name}"

    @staticmethod
    def _is_identified(nhi_type: NHIType, account: Dict[str, object], name: str) -> bool:
        if nhi_type is NHIType.UNKNOWN_NHI:
            return False
        if account:
            return True
        # 계정 정보가 없어도 유형이 확정되면 식별된 것으로 본다.
        return bool(name)

    @staticmethod
    def _confidence(profile: NHIProfile, account: Dict[str, object]) -> float:
        score = 0.2
        if account:
            score += 0.35
        if profile.provider not in ("unknown", "generic", ""):
            score += 0.15
        if profile.nhi_type is not NHIType.UNKNOWN_NHI:
            score += 0.15
        if profile.owner:
            score += 0.1
        if profile.linked_ai_agent:
            score += 0.05
        return round(min(score, 0.99), 2)
