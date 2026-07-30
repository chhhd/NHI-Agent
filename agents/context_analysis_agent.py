"""Context Analysis Agent — Secret 이 "어디서, 어떻게" 쓰이는지 판단한다.

수행 항목
  1. 파일 경로 분석
  2. 변수명 분석
  3. 주변 코드 분석
  4. 테스트·예제 값 여부 판단
  5. 운영·개발 환경 분류
  6. 실제 사용 중인 Secret 여부 판단
  7. 데이터 민감도 추론
  8. 분석 신뢰도 계산

판단 근거는 모두 `path_signals` / `code_signals` / `notes` 에 남겨
위험 점수의 "근거" 로 그대로 사용할 수 있게 한다.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from agents.heuristics import (
    context_text,
    contains_any,
    extract_variable_name,
    looks_like_placeholder,
    path_parts,
    path_text,
)
from core.models import SecretFinding
from core.nhi_models import AnalysisSignals, ContextInsight, DataSensitivity, Environment

logger = logging.getLogger(__name__)

#: 환경 판정 키워드 (우선순위 순으로 평가)
ENVIRONMENT_KEYWORDS: Dict[Environment, Tuple[str, ...]] = {
    Environment.TEST: (
        "test", "tests", "spec", "specs", "fixture", "fixtures", "mock", "mocks",
        "example", "examples", "sample", "samples", "demo", "docs", "tutorial",
    ),
    Environment.PRODUCTION: (
        "prod", "production", "prd", "live", "release", "main", "master",
    ),
    Environment.STAGING: ("stage", "staging", "stg", "qa", "uat", "preprod", "sandbox"),
    Environment.DEVELOPMENT: ("dev", "develop", "development", "local", "localhost"),
}

#: 배포·운영 인프라 경로 (운영 가중치)
DEPLOY_PATH_HINTS = (
    "deploy", "k8s", "kubernetes", "helm", "terraform", "ansible", "infra",
    ".github/workflows", ".gitlab-ci", "jenkins", "docker-compose", "manifest",
)

#: 데이터 민감도 키워드
SENSITIVITY_KEYWORDS: Dict[DataSensitivity, Tuple[str, ...]] = {
    DataSensitivity.RESTRICTED: (
        "payment", "billing", "card", "pii", "ssn", "resident", "passport",
        "medical", "health", "salary", "payroll", "credential", "password",
        "private_key", "auth", "identity", "kyc", "account_number",
    ),
    DataSensitivity.CONFIDENTIAL: (
        "customer", "user", "member", "order", "invoice", "contract", "hr",
        "employee", "crm", "analytics", "report", "internal_db", "database",
    ),
    DataSensitivity.INTERNAL: ("config", "service", "internal", "app", "backend"),
    DataSensitivity.PUBLIC: ("public", "docs", "readme", "static", "assets"),
}

#: 소스 코드 파일(=하드코딩) 확장자
SOURCE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".php", ".sh",
)

#: 운영에서 실제 참조됨을 시사하는 코드 신호
IN_USE_CODE_SIGNALS = (
    "client(", "authorization", "bearer", "headers", "requests.", "fetch(",
    "axios", "httpx", "webclient", "connect(", "session", "api_call",
)


class ContextAnalysisAgent:
    """탐지 지점의 문맥을 해석한다."""

    def analyze(
        self, finding: SecretFinding, signals: Optional[AnalysisSignals] = None
    ) -> ContextInsight:
        signals = signals or AnalysisSignals()
        insight = ContextInsight()

        path = path_text(finding.file_path)
        parts = path_parts(finding.file_path)
        code = context_text(finding)

        # 1) 경로 분석
        insight.path_signals = self._path_signals(path, parts)
        # 2) 변수명 분석
        insight.variable_name = extract_variable_name(finding)
        if insight.variable_name:
            insight.notes.append(f"변수명: {insight.variable_name}")
        # 3) 주변 코드 분석
        insight.code_signals = self._code_signals(code)
        insight.hardcoded_in_source = path.endswith(SOURCE_EXTENSIONS)
        if insight.hardcoded_in_source:
            insight.notes.append("소스 코드에 직접 하드코딩됨")

        # 4) 테스트·예제 값 여부
        insight.is_test_or_example = self._is_test_or_example(finding, path, parts, code)
        # 5) 환경 분류
        insight.environment = self._classify_environment(
            path, parts, code, insight, signals
        )
        # 6) 실제 사용 여부
        insight.in_use = self._is_in_use(finding, insight, code, signals)
        # 7) 데이터 민감도
        insight.data_sensitivity = self._infer_sensitivity(finding, path, code, insight)
        # 8) 신뢰도
        insight.confidence = self._confidence(finding, insight, signals)
        insight.project_hint = self._project_hint(parts, signals)
        return insight

    # ------------------------------------------------------------------
    @staticmethod
    def _path_signals(path: str, parts: List[str]) -> List[str]:
        signals: List[str] = []
        for env, keywords in ENVIRONMENT_KEYWORDS.items():
            hits = [k for k in keywords if k in parts or k in path]
            if hits:
                signals.append(f"경로에 {env.value} 키워드: {', '.join(sorted(set(hits))[:3])}")
        deploy_hits = [h for h in DEPLOY_PATH_HINTS if h in path]
        if deploy_hits:
            signals.append(f"배포·인프라 경로: {', '.join(deploy_hits[:3])}")
        if any(p.startswith(".env") for p in parts):
            signals.append("환경설정(.env) 파일")
        return signals

    @staticmethod
    def _code_signals(code: str) -> List[str]:
        signals: List[str] = []
        hits = contains_any(code, IN_USE_CODE_SIGNALS)
        if hits:
            signals.append(f"API 호출 문맥: {', '.join(hits[:3])}")
        if contains_any(code, ("todo", "fixme", "임시", "temporary")):
            signals.append("임시 코드 주석 존재")
        if contains_any(code, ("deprecated", "unused", "legacy", "사용안함")):
            signals.append("미사용/레거시 표기")
        if contains_any(code, ("os.environ", "getenv", "process.env", "secret manager", "vault")):
            signals.append("환경변수·시크릿 매니저 사용 흔적")
        return signals

    # ------------------------------------------------------------------
    # 4) 테스트·예제 값
    # ------------------------------------------------------------------
    @staticmethod
    def _is_test_or_example(
        finding: SecretFinding, path: str, parts: List[str], code: str
    ) -> bool:
        if looks_like_placeholder(finding):
            return True
        test_keywords = ENVIRONMENT_KEYWORDS[Environment.TEST]
        if any(k in parts for k in test_keywords):
            return True
        if path.endswith(".example") or ".example." in path or path.endswith(".sample"):
            return True
        if contains_any(code, ("이 값은 예시", "for example", "dummy", "do not use")):
            return True
        # 외부 검증에서 이미 무효로 확인된 값은 예제일 가능성이 높다
        return finding.credential_active is False and finding.credential_revoked is False

    # ------------------------------------------------------------------
    # 5) 환경 분류
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_environment(
        path: str,
        parts: List[str],
        code: str,
        insight: ContextInsight,
        signals: AnalysisSignals,
    ) -> Environment:
        declared = (signals.extra.get("environment") if signals.extra else None) or None
        if isinstance(declared, str):
            try:
                return Environment(declared.lower())
            except ValueError:
                pass

        variable = (insight.variable_name or "").lower()
        haystack = f"{path} {variable} {code}"

        if insight.is_test_or_example:
            return Environment.TEST

        # 경로 조각이 가장 강한 신호 — 파일명/디렉터리에 명시된 환경을 우선한다.
        for env in (Environment.PRODUCTION, Environment.STAGING, Environment.DEVELOPMENT):
            keywords = ENVIRONMENT_KEYWORDS[env]
            if any(k in parts for k in keywords):
                return env
            if any(f".{k}" in path or f"{k}." in path or f"-{k}" in path for k in keywords):
                return env

        for env in (Environment.PRODUCTION, Environment.STAGING, Environment.DEVELOPMENT):
            if any(k in haystack for k in ENVIRONMENT_KEYWORDS[env]):
                return env

        # 배포 인프라 경로에 있는 Secret 은 운영으로 간주한다 (보수적).
        if any(h in path for h in DEPLOY_PATH_HINTS):
            return Environment.PRODUCTION
        return Environment.UNKNOWN

    # ------------------------------------------------------------------
    # 6) 실제 사용 여부
    # ------------------------------------------------------------------
    @staticmethod
    def _is_in_use(
        finding: SecretFinding,
        insight: ContextInsight,
        code: str,
        signals: AnalysisSignals,
    ) -> Optional[bool]:
        # 외부 검증 결과가 가장 확실한 근거
        if finding.credential_active is True:
            insight.notes.append("외부 API 검증 결과 유효한 자격 증명")
            return True
        if finding.credential_revoked is True:
            insight.notes.append("폐기된 자격 증명")
            return False
        if signals.last_used_at:
            insight.notes.append(f"최근 사용 기록: {signals.last_used_at}")
            return True
        if insight.is_test_or_example:
            return False
        if any("API 호출 문맥" in s for s in insight.code_signals):
            insight.notes.append("코드에서 실제 호출에 사용되는 것으로 보임")
            return True
        if contains_any(code, ("deprecated", "unused", "legacy")):
            return False
        return None

    # ------------------------------------------------------------------
    # 7) 데이터 민감도
    # ------------------------------------------------------------------
    @staticmethod
    def _infer_sensitivity(
        finding: SecretFinding, path: str, code: str, insight: ContextInsight
    ) -> DataSensitivity:
        haystack = f"{path} {code} {insight.variable_name or ''}".lower()

        # 결제/인증 provider 는 문맥과 무관하게 민감도가 높다.
        if finding.provider in {"stripe", "aws", "google"}:
            return DataSensitivity.RESTRICTED

        for level in (
            DataSensitivity.RESTRICTED,
            DataSensitivity.CONFIDENTIAL,
            DataSensitivity.INTERNAL,
        ):
            if contains_any(haystack, SENSITIVITY_KEYWORDS[level]):
                return level

        if insight.is_test_or_example:
            return DataSensitivity.PUBLIC
        return DataSensitivity.UNKNOWN

    # ------------------------------------------------------------------
    # 8) 신뢰도
    # ------------------------------------------------------------------
    @staticmethod
    def _confidence(
        finding: SecretFinding, insight: ContextInsight, signals: AnalysisSignals
    ) -> float:
        score = 0.2
        if finding.credential_active is not None:
            score += 0.3
        if insight.path_signals:
            score += 0.15
        if insight.variable_name:
            score += 0.1
        if insight.code_signals:
            score += 0.1
        if insight.environment is not Environment.UNKNOWN:
            score += 0.1
        if signals.last_used_at or signals.declared_permissions:
            score += 0.05
        return round(min(score, 0.99), 2)

    @staticmethod
    def _project_hint(parts: List[str], signals: AnalysisSignals) -> Optional[str]:
        if signals.project:
            return signals.project
        for part in parts[:-1]:
            if part in {"src", "app", "lib", "config", "configs", "packages", "services"}:
                continue
            if len(part) > 2 and not part.startswith("."):
                return part
        if signals.repository:
            return signals.repository.split("/")[-1]
        return None
