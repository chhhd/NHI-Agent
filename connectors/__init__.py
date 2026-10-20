"""외부 서비스 Connector 패키지."""

from typing import Callable, Dict, Optional

from connectors.base_connector import (
    AuthenticationError,
    BaseConnector,
    ConnectorError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)
from connectors.github_connector import (
    GitHubConnector,
    GitHubOrganizationDiscoveryResult,
    Repository,
)
from connectors.github_webhook import (
    GitHubWebhookHandler,
    WebhookEvent,
    WebhookVerificationError,
    parse_event,
    verify_signature,
)
from connectors.gitlab_connector import GitLabConnector
from connectors.google_workspace_connector import GoogleWorkspaceConnector
from connectors.huggingface_connector import HuggingFaceConnector
from connectors.microsoft_graph_connector import MicrosoftGraphConnector
from connectors.notion_connector import NotionConnector
from connectors.slack_connector import SlackConnector

#: provider 이름 → Connector 팩토리.
#: 토큰 재검증 시 탐지된 provider 에 맞는 Connector 를 골라 쓴다.
#: 추가 SaaS 연동은 BaseConnector 를 상속해 여기에 등록하면
#: CredentialVerifier 가 자동으로 해당 provider 를 검증한다.
CONNECTOR_REGISTRY: Dict[str, Callable[..., BaseConnector]] = {
    "github": GitHubConnector,
    "slack": SlackConnector,
    "gitlab": GitLabConnector,
    "notion": NotionConnector,
    "huggingface": HuggingFaceConnector,
    "microsoft": MicrosoftGraphConnector,
    "google_workspace": GoogleWorkspaceConnector,
}


def get_connector(provider: str, token: Optional[str] = None) -> Optional[BaseConnector]:
    """provider 에 해당하는 Connector 인스턴스. 미지원이면 None."""
    factory = CONNECTOR_REGISTRY.get(provider)
    if factory is None:
        return None
    return factory(token) if token else factory()


__all__ = [
    "AuthenticationError",
    "BaseConnector",
    "CONNECTOR_REGISTRY",
    "ConnectorError",
    "GitHubConnector",
    "GitHubOrganizationDiscoveryResult",
    "GitHubWebhookHandler",
    "GitLabConnector",
    "GoogleWorkspaceConnector",
    "HuggingFaceConnector",
    "MicrosoftGraphConnector",
    "NotFoundError",
    "NotionConnector",
    "PermissionDeniedError",
    "RateLimitError",
    "Repository",
    "SlackConnector",
    "WebhookEvent",
    "WebhookVerificationError",
    "get_connector",
    "parse_event",
    "verify_signature",
]
