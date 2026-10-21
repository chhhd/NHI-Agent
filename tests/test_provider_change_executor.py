"""GitHub·Slack·AWS Provider 변경과 Inventory 기준 완료/단순 롤백 테스트."""

from __future__ import annotations

import pytest

from backend.services.change_control_service import ChangeControlService
from backend.services.provider_change_executor import ProviderChangeExecutor
from core.config import Settings
from core.governance_models import ChangeStatus, ChangeType
from core.observation_models import CredentialObservation
from security.secret_store import AESGCMSecretMaterialStore
from storage.sqlite_store import SQLiteStorage
from tests.test_governance import make_nhi


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def provider_settings() -> Settings:
    settings = Settings()
    settings.secret_storage.master_key = AESGCMSecretMaterialStore.generate_key()
    settings.secret_storage.ttl_seconds = 3600
    return settings


def bind_secret(store, settings, nhi_id, provider, raw_type, plaintext):
    fingerprint = f"fp:{provider}:{nhi_id}"
    material = AESGCMSecretMaterialStore(
        store,
        settings.secret_storage.master_key,
        key_id=settings.secret_storage.key_id,
    )
    reference = material.seal(plaintext, fingerprint=fingerprint)
    store.save_observation(
        CredentialObservation(
            source_type="test",
            source_event_id=f"event:{nhi_id}",
            provider=provider,
            raw_type=raw_type,
            fingerprint=fingerprint,
            secret_ref=str(reference),
        )
    )
    store.bind_credential_to_nhi(fingerprint, nhi_id, confidence=1.0, evidence=["test"])


class FakeGitHub:
    revoked = []

    def __init__(self, token="", **_kwargs):
        self.token = token

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def revoke_installation_token(self, token):
        self.revoked.append(token)


class FakeSlack:
    revoked = []

    def __init__(self, token="", **_kwargs):
        self.token = token

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def revoke_token(self, token):
        self.revoked.append(token)


@pytest.mark.parametrize(
    ("provider", "raw_type", "token", "factory_name", "fake"),
    [
        ("github", "GITHUB_TOKEN", "ghp_provider_target_1234567890", "github_factory", FakeGitHub),
        ("slack", "SLACK_BOT_TOKEN", "xoxb-provider-target-1234567890", "slack_factory", FakeSlack),
    ],
)
def test_github_and_slack_revocation_are_called_but_inventory_decides_success(
    store, provider, raw_type, token, factory_name, fake
):
    fake.revoked.clear()
    settings = provider_settings()
    make_nhi(store, provider=provider)
    bind_secret(store, settings, "nhi-1", provider, raw_type, token)
    kwargs = {factory_name: fake}
    provider_executor = ProviderChangeExecutor(store, settings=settings, **kwargs)
    changes = ChangeControlService(store, provider_executor=provider_executor)

    change = changes.propose("nhi-1", ChangeType.TOKEN_REVOKE, requested_by="admin")
    applied = changes.approve(change.change_id, actor="admin")

    assert applied.status is ChangeStatus.APPLIED
    assert applied.apply_result["completion_basis"] == "inventory_state"
    assert applied.apply_result["provider"]["provider_call"] == "succeeded"
    assert fake.revoked == [token]
    assert token not in str(applied.apply_result)


class FakeIAM:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def update_access_key(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("simulated provider outage")


def test_aws_provider_failure_does_not_fail_inventory_and_rollback_is_internal_only(store):
    settings = provider_settings()
    make_nhi(store, provider="aws")
    iam = FakeIAM(fail=True)
    provider_executor = ProviderChangeExecutor(
        store, settings=settings, aws_client_factory=lambda: iam
    )
    changes = ChangeControlService(store, provider_executor=provider_executor)
    change = changes.propose(
        "nhi-1",
        ChangeType.TOKEN_REVOKE,
        requested_by="admin",
        params={"provider_options": {"user_name": "deploy-bot", "access_key_id": "AKIAEXAMPLE000000001"}},
    )

    applied = changes.approve(change.change_id, actor="admin")
    assert applied.status is ChangeStatus.APPLIED
    assert applied.apply_result["provider"]["provider_call"] == "failed"
    assert store.get_nhi_record("nhi-1")["credential_state"] == "REVOKED"
    assert len(iam.calls) == 1

    rolled = changes.rollback(change.change_id, actor="admin", reason="simple rollback")
    assert rolled.status is ChangeStatus.ROLLED_BACK
    assert rolled.apply_result["rollback"]["provider_call"] == "not_configured"
    assert store.get_nhi_record("nhi-1")["credential_state"] == "ACTIVE"
    assert len(iam.calls) == 1  # Provider 역호출 없음


def test_aws_revoke_uses_iam_update_access_key(store):
    settings = provider_settings()
    make_nhi(store, provider="aws")
    iam = FakeIAM()
    changes = ChangeControlService(
        store,
        provider_executor=ProviderChangeExecutor(
            store, settings=settings, aws_client_factory=lambda: iam
        ),
    )
    change = changes.propose(
        "nhi-1",
        ChangeType.TOKEN_REVOKE,
        requested_by="admin",
        params={"provider_options": {"user_name": "deploy-bot", "access_key_id": "AKIAEXAMPLE000000001"}},
    )
    applied = changes.approve(change.change_id, actor="admin")
    assert applied.apply_result["provider"]["provider_call"] == "succeeded"
    assert iam.calls == [
        {
            "UserName": "deploy-bot",
            "AccessKeyId": "AKIAEXAMPLE000000001",
            "Status": "Inactive",
        }
    ]
