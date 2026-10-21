"""GitHub·Slack·AWS 실제 변경을 수행하는 best-effort 실행기.

Change Control의 완료 기준은 내부 Inventory 상태다. 따라서 Provider 호출 결과는
감사 증적으로 남기되 실패를 예외로 올려 내부 적용을 취소하거나 자동 재시도하지 않는다.
롤백도 내부 Inventory 형상만 복원하며 Provider 역호출은 하지 않는다.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, Optional

from connectors.github_connector import GitHubConnector
from connectors.slack_connector import SlackConnector
from core.config import Settings, get_settings
from core.governance_models import ChangeRequest, ChangeType
from security.redaction import sanitize_security_text
from security.secret_store import AESGCMSecretMaterialStore, SecretMaterialError
from storage.base import Storage

logger = logging.getLogger(__name__)

_SUPPORTED_PROVIDERS = frozenset({"github", "slack", "aws"})
_EXTERNAL_CHANGE_TYPES = frozenset(
    {ChangeType.TOKEN_REVOKE, ChangeType.TOKEN_ROTATE, ChangeType.SCOPE_CHANGE}
)


class ProviderConfigurationError(RuntimeError):
    """Provider 변경을 실행하는 데 필요한 안전한 참조/식별자가 없다."""


class ProviderChangeExecutor:
    """Provider별 실제 변경을 시도하고 구조화된 결과만 반환한다."""

    name = "github-slack-aws"

    def __init__(
        self,
        storage: Storage,
        *,
        settings: Optional[Settings] = None,
        github_factory: Optional[Callable[..., GitHubConnector]] = None,
        slack_factory: Optional[Callable[..., SlackConnector]] = None,
        aws_client_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.storage = storage
        self.settings = settings or get_settings()
        self.github_factory = github_factory or GitHubConnector
        self.slack_factory = slack_factory or SlackConnector
        self.aws_client_factory = aws_client_factory or self._default_aws_client
        secret = self.settings.secret_storage
        self.material = (
            AESGCMSecretMaterialStore(
                storage,
                secret.master_key,
                key_id=secret.key_id,
                default_ttl_seconds=secret.ttl_seconds,
            )
            if secret.master_key
            else None
        )

    def apply(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        provider = self._provider(nhi)
        base: Dict[str, Any] = {
            "executor": self.name,
            "provider": provider,
            "provider_call": "skipped",
            "affects_completion": False,
        }
        if change.demo_workspace:
            return {**base, "reason": "synthetic_demo_workspace"}
        if provider not in _SUPPORTED_PROVIDERS:
            return {**base, "reason": "unsupported_provider"}
        if change.change_type not in _EXTERNAL_CHANGE_TYPES:
            return {**base, "reason": "internal_only_change_type"}

        try:
            detail = getattr(self, f"_{provider}")(change, nhi)
            result = {**base, "provider_call": "succeeded", **detail}
            event_type = "PROVIDER_CHANGE_SUCCEEDED"
        except Exception as exc:  # 외부 실패는 내부 APPLIED 판정을 바꾸지 않는다.
            logger.warning(
                "Provider 변경 실패(내부 상태는 유지) provider=%s change=%s: %s",
                provider,
                change.change_id,
                sanitize_security_text(exc),
            )
            result = {
                **base,
                "provider_call": "failed",
                "error_type": type(exc).__name__,
                "error": sanitize_security_text(exc),
            }
            event_type = "PROVIDER_CHANGE_FAILED"

        self.storage.append_audit_event(
            event_type,
            actor=change.approved_by or "change-control",
            target=change.change_id,
            detail={
                "nhi_id": change.nhi_id,
                "change_type": change.change_type.value,
                **result,
            },
        )
        return result

    def rollback(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "executor": self.name,
            "provider": self._provider(nhi),
            "provider_call": "not_attempted",
            "strategy": "inventory_only",
            "reason": "simple_rollback_policy",
        }

    # ------------------------------------------------------------------ GitHub
    def _github(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        options = self._options(change, nhi)
        if change.change_type is ChangeType.TOKEN_REVOKE:
            mode = str(options.get("revoke_mode") or "installation_token").lower()
            if mode == "organization_pat":
                organization = self._required(options, "organization")
                credential_id = int(self._required(options, "credential_id"))
                with self.github_factory(
                    token=self.settings.github.change_token,
                    fallback_to_default_token=False,
                    max_retries=0,
                ) as github:
                    github.revoke_org_personal_access_token(organization, credential_id)
                return {"operation": "revoke_organization_pat", "credential_id": credential_id}

            reference = self._credential_reference(nhi, options)
            with self._secret(reference, purpose="REVOKE", actor=change.approved_by) as token:
                with self.github_factory(
                    token=token, fallback_to_default_token=False, max_retries=0
                ) as github:
                    github.revoke_installation_token(token)
            return {"operation": "revoke_installation_token"}

        if change.change_type is ChangeType.TOKEN_ROTATE:
            reference = self._required(options, "refresh_token_ref")
            client_id = str(options.get("client_id") or self.settings.github.oauth_client_id)
            with self._secret(reference, purpose="ROTATE", actor=change.approved_by) as refresh:
                client_secret = self._client_secret(
                    options.get("client_secret_ref"),
                    self.settings.github.oauth_client_secret,
                    actor=change.approved_by,
                )
                with self.github_factory(
                    token="", fallback_to_default_token=False, max_retries=0
                ) as github:
                    payload = github.rotate_oauth_token(
                        refresh, client_id=client_id, client_secret=client_secret
                    )
            return {
                "operation": "rotate_oauth_token",
                **self._seal_rotation(change, payload, provider="github"),
            }

        installation_id = int(self._required(options, "installation_id"))
        add_ids = [int(item) for item in options.get("add_repository_ids") or []]
        remove_ids = [int(item) for item in options.get("remove_repository_ids") or []]
        if not add_ids and not remove_ids:
            raise ProviderConfigurationError(
                "GitHub 권한 변경에는 add_repository_ids 또는 remove_repository_ids가 필요합니다."
            )
        reference = self._credential_reference(nhi, options)
        with self._secret(reference, purpose="ROTATE", actor=change.approved_by) as token:
            with self.github_factory(
                token=token, fallback_to_default_token=False, max_retries=0
            ) as github:
                counts = github.update_installation_repositories(
                    installation_id,
                    add_repository_ids=add_ids,
                    remove_repository_ids=remove_ids,
                    token=token,
                )
        return {"operation": "update_installation_repositories", **counts}

    # ------------------------------------------------------------------- Slack
    def _slack(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        options = self._options(change, nhi)
        if change.change_type is ChangeType.TOKEN_REVOKE:
            reference = self._credential_reference(nhi, options)
            with self._secret(reference, purpose="REVOKE", actor=change.approved_by) as token:
                with self.slack_factory(token=token, max_retries=0) as slack:
                    slack.revoke_token(token)
            return {"operation": "auth.revoke"}

        if change.change_type is ChangeType.TOKEN_ROTATE:
            reference = self._required(options, "refresh_token_ref")
            client_id = str(options.get("client_id") or self.settings.slack.oauth_client_id)
            with self._secret(reference, purpose="ROTATE", actor=change.approved_by) as refresh:
                client_secret = self._client_secret(
                    options.get("client_secret_ref"),
                    self.settings.slack.oauth_client_secret,
                    actor=change.approved_by,
                )
                with self.slack_factory(
                    token="", fallback_to_default_token=False, max_retries=0
                ) as slack:
                    payload = slack.rotate_oauth_token(
                        refresh, client_id=client_id, client_secret=client_secret
                    )
            return {
                "operation": "oauth.v2.access",
                **self._seal_rotation(change, payload, provider="slack"),
            }

        raise ProviderConfigurationError(
            "Slack은 설치된 앱의 scope를 직접 수정하는 API가 없어 재설치가 필요합니다."
        )

    # --------------------------------------------------------------------- AWS
    def _aws(self, change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        options = self._options(change, nhi)
        user_name = str(options.get("user_name") or nhi.get("account") or "").strip()
        if not user_name:
            raise ProviderConfigurationError("AWS 변경에는 provider_options.user_name이 필요합니다.")
        iam = self.aws_client_factory()

        if change.change_type is ChangeType.TOKEN_REVOKE:
            access_key_id = str(options.get("access_key_id") or "").strip()
            if not access_key_id:
                reference = self._credential_reference(nhi, options, raw_type="AWS_ACCESS_KEY_ID")
                with self._secret(reference, purpose="REVOKE", actor=change.approved_by) as leased:
                    access_key_id = leased.strip()
            iam.update_access_key(
                UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
            )
            return {
                "operation": "deactivate_access_key",
                "access_key_id_suffix": access_key_id[-4:],
            }

        if change.change_type is ChangeType.TOKEN_ROTATE:
            response = iam.create_access_key(UserName=user_name)
            credential = response.get("AccessKey") or {}
            access_key_id = str(credential.get("AccessKeyId") or "")
            secret = str(credential.get("SecretAccessKey") or "")
            if not access_key_id or not secret:
                raise RuntimeError("AWS create_access_key 응답에 새 Credential이 없습니다.")
            sealed = self._seal_secret(
                secret,
                fingerprint=f"rotation:{change.change_id}:aws-secret",
            )
            return {
                "operation": "create_access_key",
                "new_access_key_id": access_key_id,
                "new_secret_ref": sealed,
            }

        attached = [str(item) for item in options.get("attach_policy_arns") or []]
        detached = [str(item) for item in options.get("detach_policy_arns") or []]
        for arn in attached:
            iam.attach_user_policy(UserName=user_name, PolicyArn=arn)
        for arn in detached:
            iam.detach_user_policy(UserName=user_name, PolicyArn=arn)
        if options.get("policy_document") is not None:
            document = options["policy_document"]
            if not isinstance(document, (dict, str)):
                raise ProviderConfigurationError("AWS policy_document는 JSON 객체 또는 문자열이어야 합니다.")
            iam.put_user_policy(
                UserName=user_name,
                PolicyName=str(options.get("policy_name") or f"NHIChange-{change.change_id[:8]}"),
                PolicyDocument=json.dumps(document) if isinstance(document, dict) else document,
            )
        elif not attached and not detached:
            raise ProviderConfigurationError(
                "AWS 권한 변경에는 attach/detach_policy_arns 또는 policy_document가 필요합니다."
            )
        return {
            "operation": "update_iam_user_policies",
            "policies_attached": len(attached),
            "policies_detached": len(detached),
            "inline_policy_updated": options.get("policy_document") is not None,
        }

    # ---------------------------------------------------------------- helpers
    def _default_aws_client(self) -> Any:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover - 배포 의존성 오류
            raise ProviderConfigurationError("AWS 변경 실행에는 boto3가 필요합니다.") from exc
        kwargs: Dict[str, Any] = {
            "config": Config(retries={"total_max_attempts": 1, "mode": "standard"})
        }
        if self.settings.aws.region_name:
            kwargs["region_name"] = self.settings.aws.region_name
        return boto3.client("iam", **kwargs)

    @staticmethod
    def _provider(nhi: Dict[str, Any]) -> str:
        raw = str(nhi.get("provider") or "unknown").strip().lower()
        return "aws" if raw in {"amazon", "amazon_web_services"} else raw

    @staticmethod
    def _options(change: ChangeRequest, nhi: Dict[str, Any]) -> Dict[str, Any]:
        inherited = nhi.get("provider_options") or nhi.get("provider_metadata") or {}
        requested = change.params.get("provider_options") or {}
        if not isinstance(inherited, dict) or not isinstance(requested, dict):
            raise ProviderConfigurationError("provider_options는 객체여야 합니다.")
        return {**inherited, **requested}

    @staticmethod
    def _required(options: Dict[str, Any], name: str) -> Any:
        value = options.get(name)
        if value in (None, ""):
            raise ProviderConfigurationError(f"provider_options.{name}이 필요합니다.")
        return value

    def _credential_reference(
        self,
        nhi: Dict[str, Any],
        options: Dict[str, Any],
        *,
        raw_type: Optional[str] = None,
    ) -> str:
        explicit = options.get("credential_ref")
        if explicit:
            return str(explicit)
        record = self.storage.get_nhi_record(nhi["nhi_id"]) or {}
        for credential in record.get("credentials") or []:
            observations = self.storage.list_observations(
                fingerprint=credential.get("fingerprint"), limit=20
            )
            for observation in observations:
                if raw_type and observation.raw_type != raw_type:
                    continue
                if observation.secret_ref:
                    return observation.secret_ref
        raise ProviderConfigurationError(
            "암호화된 대상 Credential 참조가 없습니다. 스캔 시 NHI_MASTER_KEY로 원문을 봉인하거나 "
            "provider_options.credential_ref를 지정하세요."
        )

    @contextmanager
    def _secret(
        self, reference: Any, *, purpose: str, actor: Optional[str]
    ) -> Iterator[str]:
        if self.material is None:
            raise ProviderConfigurationError("NHI_MASTER_KEY가 없어 Credential을 안전하게 읽을 수 없습니다.")
        with self.material.lease(
            str(reference), purpose=purpose, actor=actor or "change-control"
        ) as lease:
            yield lease.text

    def _client_secret(
        self, reference: Any, configured: str, *, actor: Optional[str]
    ) -> str:
        if reference:
            with self._secret(reference, purpose="ROTATE", actor=actor) as secret:
                return secret
        if not configured:
            raise ProviderConfigurationError("OAuth client secret 설정 또는 client_secret_ref가 필요합니다.")
        return configured

    def _seal_secret(self, value: str, *, fingerprint: str) -> str:
        if self.material is None:
            raise SecretMaterialError("새 Credential 저장에 NHI_MASTER_KEY가 필요합니다.")
        return str(
            self.material.seal(
                value,
                fingerprint=fingerprint,
                allowed_purposes=("VERIFY", "REVOKE", "ROTATE"),
            )
        )

    def _seal_rotation(
        self, change: ChangeRequest, payload: Dict[str, Any], *, provider: str
    ) -> Dict[str, Any]:
        access = str(payload.get("access_token") or "")
        if not access:
            raise RuntimeError(f"{provider} token 교체 응답에 access_token이 없습니다.")
        result: Dict[str, Any] = {
            "new_access_token_ref": self._seal_secret(
                access, fingerprint=f"rotation:{change.change_id}:{provider}:access"
            )
        }
        refresh = str(payload.get("refresh_token") or "")
        if refresh:
            result["new_refresh_token_ref"] = self._seal_secret(
                refresh, fingerprint=f"rotation:{change.change_id}:{provider}:refresh"
            )
        for source, target in (
            ("expires_in", "expires_in"),
            ("refresh_token_expires_in", "refresh_token_expires_in"),
            ("scope", "scope"),
        ):
            if payload.get(source) is not None:
                result[target] = payload[source]
        return result


__all__ = ["ProviderChangeExecutor", "ProviderConfigurationError"]
