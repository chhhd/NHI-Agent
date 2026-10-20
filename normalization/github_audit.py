"""GitHub 조직 Audit Log를 개인정보 최소화된 ``UsageEvent``로 변환한다."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.inventory_models import GitHubNHIInput
from core.nhi_models import parse_dt
from core.usage_models import UsageEvent
from security.privacy import PrivacyProtector
from security.redaction import sanitize_security_text


@dataclass
class GitHubAuditNormalization:
    events: List[UsageEvent] = field(default_factory=list)
    invalid_event_count: int = 0
    matched_nhi_event_count: int = 0
    unmatched_actor_event_count: int = 0
    unmatched_programmatic_event_count: int = 0
    filtered_before_window_count: int = 0

    def summary(self) -> Dict[str, int]:
        return {
            "normalized_event_count": len(self.events),
            "invalid_event_count": self.invalid_event_count,
            "matched_nhi_event_count": self.matched_nhi_event_count,
            "unmatched_actor_event_count": self.unmatched_actor_event_count,
            "unmatched_programmatic_event_count": self.unmatched_programmatic_event_count,
            "filtered_before_window_count": self.filtered_before_window_count,
        }


class GitHubAuditNormalizer:
    """원본 Audit Log에서 분석 목적상 필요한 필드만 추출한다."""

    def __init__(self, privacy: Optional[PrivacyProtector] = None) -> None:
        self.privacy = privacy or PrivacyProtector()

    def normalize(
        self,
        records: Iterable[Dict[str, Any]],
        *,
        identities: Sequence[GitHubNHIInput],
        since: Optional[str] = None,
    ) -> GitHubAuditNormalization:
        aliases = _identity_aliases(identities)
        since_dt = parse_dt(since)
        result = GitHubAuditNormalization()

        for raw in records:
            if not isinstance(raw, dict):
                result.invalid_event_count += 1
                continue
            occurred_at = _audit_timestamp(raw.get("created_at") or raw.get("@timestamp"))
            action = sanitize_security_text(raw.get("action"))
            if not occurred_at or not action:
                result.invalid_event_count += 1
                continue
            occurred_dt = parse_dt(occurred_at)
            if since_dt is not None and occurred_dt is not None and occurred_dt < since_dt:
                result.filtered_before_window_count += 1
                continue

            canonical = _match_identity(raw, aliases)
            actor = raw.get("actor") or raw.get("actor_id") or "unknown"
            if canonical:
                principal_id = canonical
                result.matched_nhi_event_count += 1
            else:
                result.unmatched_actor_event_count += 1
                if _is_programmatic(raw):
                    result.unmatched_programmatic_event_count += 1
                # 알려진 NHI에 연결되지 않는 사람·앱 활동은 이 시스템의 처리 목적 밖이다.
                # 원본이나 가명 이벤트를 보관하지 않고 집계 건수만 남긴다.
                continue

            event_material = (
                raw.get("_document_id")
                or raw.get("document_id")
                or raw.get("id")
                or "|".join(
                    [str(actor), action, occurred_at, str(raw.get("repo") or "")]
                )
            )
            event_id = self.privacy.pseudonymize(
                event_material, namespace="github-audit-event"
            )

            location = raw.get("actor_location")
            location = location if isinstance(location, dict) else {}
            network = self.privacy.minimize_ip(
                raw.get("actor_ip")
                or raw.get("ip_address")
                or location.get("ip_address")
            )
            user_agent_family = self.privacy.user_agent_family(
                raw.get("user_agent") or raw.get("user_agent_string")
            )
            country = str(location.get("country_code") or "").upper()[:2] or None
            attributes = {
                "matched_nhi": canonical is not None,
                "actor_kind": _actor_kind(raw),
                "network": network,
                "user_agent_family": user_agent_family,
                "country_code": country,
                "programmatic_access": _is_programmatic(raw),
            }
            attributes = {key: value for key, value in attributes.items() if value is not None}

            project = raw.get("repo") or raw.get("repository")
            resource = raw.get("team") or raw.get("org") or project
            result.events.append(
                UsageEvent(
                    event_id=event_id,
                    provider="github",
                    principal_id=principal_id,
                    action=action,
                    occurred_at=occurred_at,
                    source="organization_audit_log",
                    project=sanitize_security_text(project) if project else None,
                    resource=sanitize_security_text(resource) if resource else None,
                    success=None,
                    attributes=attributes,
                )
            )
        return result


def canonical_nhi_id(item: GitHubNHIInput) -> str:
    return f"github:{item.nhi_id}"


def aliases_for(item: GitHubNHIInput) -> List[str]:
    account = item.account if isinstance(item.account, dict) else {}
    values = [
        item.nhi_id,
        canonical_nhi_id(item),
        account.get("app_slug"),
    ]
    app_slug = str(account.get("app_slug") or "").strip()
    if app_slug:
        values.append(f"{app_slug}[bot]")
    installation_id = str(account.get("installation_id") or "").strip()
    if installation_id:
        values.extend((f"installation:{installation_id}", f"github-app-installation:{installation_id}"))
    app_id = str(account.get("app_id") or "").strip()
    if app_id:
        values.append(f"app:{app_id}")
    return sorted({_alias(value) for value in values if str(value or "").strip()})


def _identity_aliases(identities: Sequence[GitHubNHIInput]) -> Dict[str, Optional[str]]:
    aliases: Dict[str, Optional[str]] = {}
    for item in identities:
        canonical = canonical_nhi_id(item)
        for alias in aliases_for(item):
            if alias not in aliases:
                aliases[alias] = canonical
            elif aliases[alias] != canonical:
                aliases[alias] = None
    return aliases


def _match_identity(raw: Dict[str, Any], aliases: Dict[str, Optional[str]]) -> Optional[str]:
    candidates = [
        f"installation:{raw['installation_id']}" if raw.get("installation_id") else None,
        f"app:{raw['integration_id']}" if raw.get("integration_id") else None,
        f"app:{raw['app_id']}" if raw.get("app_id") else None,
        f"app:{raw['oauth_application_id']}" if raw.get("oauth_application_id") else None,
        raw.get("actor"),
    ]
    for value in candidates:
        key = _alias(value)
        if key and aliases.get(key):
            return aliases[key]
        if key.endswith("[bot]") and aliases.get(key[:-5]):
            return aliases[key[:-5]]
    return None


def _alias(value: object) -> str:
    return str(value or "").strip().lower()


def _audit_timestamp(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float)) or str(value).strip().isdigit():
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000.0
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return None
    parsed = parse_dt(str(value))
    return parsed.isoformat() if parsed else None


def _actor_kind(raw: Dict[str, Any]) -> str:
    if _is_programmatic(raw):
        return "application"
    return "human_or_unknown"


def _is_programmatic(raw: Dict[str, Any]) -> bool:
    actor = str(raw.get("actor") or "").lower()
    return bool(raw.get("programmatic_access_type")) or actor.endswith("[bot]")


__all__ = [
    "GitHubAuditNormalization",
    "GitHubAuditNormalizer",
    "aliases_for",
    "canonical_nhi_id",
]
