"""수집 정규화·분석 영속화·암호화 Secret·조치 상태 테스트."""

from __future__ import annotations

import pytest

from agents.pipeline import NHIAnalysisPipeline
from core.action_models import ActionStatus
from core.models import CredentialStatus, SecretFinding
from core.nhi_models import AnalysisSignals
from normalization import observation_from_finding
from processing import ActionService, persist_analysis
from rescan.credential_verifier import CredentialVerifier
from security.secret_store import AESGCMSecretMaterialStore, SecretMaterialError
from storage.sqlite_store import SQLiteStorage
from tests.test_nhi_agents import make_finding

RAW_TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"


@pytest.fixture
def store():
    instance = SQLiteStorage(":memory:")
    yield instance
    instance.close()


def test_observation_is_idempotent(store):
    finding = make_finding()
    observation = observation_from_finding(
        finding,
        repository="acme/support",
        source_type="repository_manual",
        source_event_id="scan-001:path:1",
    )

    first = store.save_observation(observation)
    second = store.save_observation(observation)

    assert first == second
    saved = store.list_observations(fingerprint=finding.fingerprint)
    assert len(saved) == 1
    assert saved[0].evidence[0].source == "repository_manual"


def test_analysis_snapshot_creates_approval_actions(store):
    finding = make_finding(credential_active=True)
    analysis = NHIAnalysisPipeline().analyze_finding(
        finding,
        repository="acme/support",
        signals=AnalysisSignals(repository_public=True),
    )

    persisted = persist_analysis(store, analysis, input_revision="scan-001")

    snapshot = store.get_analysis(str(persisted["analysis_id"]))
    assert snapshot is not None
    assert snapshot["scoring_version"] == "1.0"
    assert snapshot["policy_version"] == "1.0"

    actions = store.list_actions()
    assert actions
    assert all(action.status is ActionStatus.PENDING_APPROVAL for action in actions)


def test_action_approval_state_transition(store):
    finding = make_finding(credential_active=True)
    analysis = NHIAnalysisPipeline().analyze_finding(
        finding,
        repository="acme/support",
        signals=AnalysisSignals(repository_public=True),
    )
    persist_analysis(store, analysis)
    action = store.list_actions()[0]

    approved = ActionService(store).approve(action.action_id, actor="security@example.com")

    assert approved.status is ActionStatus.APPROVED
    assert approved.approved_by == "security@example.com"
    with pytest.raises(ValueError):
        ActionService(store).approve(action.action_id, actor="second@example.com")


def test_secret_material_roundtrip_and_destroy(store):
    key = AESGCMSecretMaterialStore.generate_key()
    materials = AESGCMSecretMaterialStore(store, key, default_ttl_seconds=60)

    reference = materials.seal(
        RAW_TOKEN,
        fingerprint="sha256:test",
        allowed_purposes=("VERIFY",),
    )

    with materials.lease(reference, purpose="VERIFY", actor="test") as lease:
        assert lease.text == RAW_TOKEN

    with pytest.raises(SecretMaterialError):
        with materials.lease(reference, purpose="ROTATE", actor="test"):
            pass

    materials.destroy(reference, actor="test")
    with pytest.raises(SecretMaterialError):
        with materials.lease(reference, purpose="VERIFY", actor="test"):
            pass


def test_verifier_can_use_encrypted_reference(store, monkeypatch):
    materials = AESGCMSecretMaterialStore(
        store, AESGCMSecretMaterialStore.generate_key(), default_ttl_seconds=60
    )
    reference = materials.seal(
        RAW_TOKEN,
        fingerprint="sha256:encrypted-verifier",
        allowed_purposes=("VERIFY",),
    )
    finding = SecretFinding(
        secret_type="SLACK_BOT_TOKEN",
        provider="slack",
        masked_value="xoxb-****",
        fingerprint="sha256:encrypted-verifier",
        file_path=".env",
        line_number=1,
        secret_ref=str(reference),
    )
    verifier = CredentialVerifier(material_store=materials)

    def fake_call(provider, token):
        assert provider == "slack"
        assert token == RAW_TOKEN
        return CredentialStatus(provider=provider, active=True, raw_scopes=["chat:write"])

    monkeypatch.setattr(verifier, "_call_connector", fake_call)
    verifier.verify(finding)

    assert finding.credential_active is True
    assert finding.raw_scopes == ["chat:write"]
