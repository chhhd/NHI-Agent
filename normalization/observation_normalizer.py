"""기존 스캔·인벤토리 입력을 ``CredentialObservation`` 으로 정규화한다."""

from __future__ import annotations

import hashlib
import json
from typing import Optional

from core.inventory_models import GitHubNHIInput, SaaSNHIInput
from core.models import SecretFinding
from core.observation_models import CredentialObservation, Evidence


def observation_from_finding(
    finding: SecretFinding,
    *,
    repository: str,
    source_type: str,
    source_event_id: str,
) -> CredentialObservation:
    evidence = [
        Evidence(
            source=source_type,
            field="detector",
            value=finding.detector.value,
            confidence=1.0 if finding.detector.value == "regex" else 0.7,
        ),
        Evidence(
            source=source_type,
            field="location",
            value={"repository": repository, "path": finding.file_path, "line": finding.line_number},
        ),
    ]
    if finding.credential_active is not None:
        evidence.append(
            Evidence(
                source="credential_verifier",
                field="credential_active",
                value=finding.credential_active,
            )
        )
    return CredentialObservation(
        source_type=source_type,
        source_event_id=source_event_id,
        provider=finding.provider,
        raw_type=finding.secret_type,
        fingerprint=finding.fingerprint,
        repository=repository,
        path=finding.file_path,
        masked_value=finding.masked_value,
        secret_ref=finding.secret_ref,
        evidence=evidence,
        raw_metadata={
            "line_number": finding.line_number,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "raw_scopes": list(finding.raw_scopes),
        },
    )


def observation_from_inventory(
    nhi: GitHubNHIInput,
    *,
    source_event_id: Optional[str] = None,
) -> CredentialObservation:
    payload = nhi.model_dump(mode="json")
    revision = source_event_id or "inventory:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    fingerprint = f"nhi:{nhi.nhi_id}"
    return CredentialObservation(
        source_type="github_inventory",
        source_event_id=revision,
        provider="github",
        raw_type=nhi.nhi_type.value,
        fingerprint=fingerprint,
        masked_value="",
        evidence=[
            Evidence(source="github_inventory", field="nhi_id", value=nhi.nhi_id),
            Evidence(source="github_inventory", field="owner", value=nhi.owner),
            Evidence(
                source="github_inventory",
                field="environment",
                value=nhi.environment.value,
            ),
            Evidence(
                source="github_inventory",
                field="repositories",
                value=[repo.model_dump(mode="json") for repo in nhi.repositories],
            ),
            Evidence(
                source=nhi.collection_source,
                field="repository_selection",
                value={
                    "selection": nhi.repository_selection,
                    "repository_inventory_complete": nhi.repository_inventory_complete,
                    "inventory_is_complete": nhi.inventory_is_complete,
                },
            ),
        ],
        raw_metadata=payload,
    )


def observation_from_saas_inventory(
    nhi: SaaSNHIInput,
    *,
    source_event_id: Optional[str] = None,
) -> CredentialObservation:
    """Microsoft/Google Discovery 결과를 감사 가능한 Observation으로 만든다."""
    payload = nhi.model_dump(mode="json")
    revision = source_event_id or "inventory:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    provider = nhi.provider.strip().lower()
    fingerprint = f"nhi:{provider}:{nhi.nhi_id}"
    return CredentialObservation(
        source_type=f"{provider}_inventory",
        source_event_id=revision,
        provider=provider,
        raw_type=nhi.nhi_type.value,
        fingerprint=fingerprint,
        masked_value="",
        evidence=[
            Evidence(source=f"{provider}_api", field="nhi_id", value=nhi.nhi_id),
            Evidence(source=f"{provider}_api", field="owner", value=nhi.owner),
            Evidence(
                source=f"{provider}_api",
                field="raw_scopes",
                value=list(nhi.raw_scopes),
            ),
            Evidence(
                source=f"{provider}_api",
                field="resources",
                value=[resource.model_dump(mode="json") for resource in nhi.resources],
            ),
        ],
        raw_metadata=payload,
    )
