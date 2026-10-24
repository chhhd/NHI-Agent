"""읽기 전용 GitHub Audit Log action 분포 분석 도구 테스트.

실제 GitHub API를 호출하지 않는다 — 전부 합성(synthetic) 샘플 데이터로만 검증한다.
민감정보(원문 레코드·actor·토큰)가 출력에 섞이지 않는지, 정상적인 긴 action
이름이 더 이상 마스킹되지 않는지, 서로 다른 미검증 값이 같은 식별자로 뭉개지지
않는지를 중점적으로 확인한다.
"""

from __future__ import annotations

import json

from core.inventory_models import GitHubNHIInput, GitHubNHIType
from scripts.analyze_github_audit_action_distribution import _classify_action, analyze, main

_RECORDS = [
    {
        "action": "repo.access",
        "actor": "deploy-bot[bot]",
        "created_at": "2026-01-01T00:00:00Z",
        "repo": "acme/repo",
    },
    {
        "action": "repo.access",
        "actor": "deploy-bot[bot]",
        "created_at": "2026-01-02T00:00:00Z",
        "repo": "acme/repo2",
    },
    {
        # 알려지지 않은 사람 행위자 — 매칭되지 않음(식별자 매칭 전 단계에서 집계만 됨)
        "action": "org.update_member",
        "actor": "random-human",
        "created_at": "2026-01-03T00:00:00Z",
    },
    {
        # action 필드 자체가 없음
        "actor": "deploy-bot[bot]",
        "created_at": "2026-01-04T00:00:00Z",
    },
    {
        # created_at 이 없음 (타임스탬프 누락)
        "action": "team.add_member",
        "actor": "deploy-bot[bot]",
    },
    {
        # 매칭되지만 project/repo/team/org 가 전혀 없음 (자산 식별자 누락)
        "action": "hook.create",
        "actor": "deploy-bot[bot]",
        "created_at": "2026-01-05T00:00:00Z",
    },
]

_IDENTITIES = [
    GitHubNHIInput(
        nhi_id="deploy-bot-app",
        nhi_name="deploy-bot",
        nhi_type=GitHubNHIType.GITHUB_APP,
        account={"app_slug": "deploy-bot"},
    )
]


def test_action_distribution_counts_every_raw_record_including_unmatched():
    report = analyze(audit_records=_RECORDS, identities=_IDENTITIES)

    assert report["input_summary"]["raw_record_count"] == 6
    valid = report["format_valid_action_distribution"]
    assert valid["repo.access"] == 2
    assert valid["org.update_member"] == 1
    assert valid["team.add_member"] == 1
    assert valid["hook.create"] == 1
    assert report["no_action_field_count"] == 1
    assert report["action_name_summary"]["format_valid_distinct_count"] == 4


def test_timestamp_missing_ratio():
    report = analyze(audit_records=_RECORDS, identities=_IDENTITIES)

    assert report["input_summary"]["timestamp_missing_count"] == 1
    assert report["input_summary"]["timestamp_missing_ratio"] == round(1 / 6, 4)


def test_identity_matching_counts_only_valid_matched_events():
    report = analyze(audit_records=_RECORDS, identities=_IDENTITIES)

    matching = report["identity_matching"]
    assert matching["performed"] is True
    assert matching["matched_event_count"] == 3  # repo.access x2 + hook.create
    assert matching["matched_distinct_nhi_count"] == 1
    assert matching["unmatched_actor_event_count"] == 1  # random-human
    assert matching["invalid_event_count"] == 2  # action 없음 1건 + timestamp 없음 1건


def test_asset_identifier_coverage_only_counts_normalized_matched_events():
    report = analyze(audit_records=_RECORDS, identities=_IDENTITIES)

    coverage = report["asset_identifier_coverage"]
    assert coverage["normalized_event_count"] == 3
    assert coverage["missing_asset_identifier_count"] == 1  # hook.create 건
    assert coverage["missing_asset_identifier_ratio"] == round(1 / 3, 4)


def test_without_inventory_sample_identity_matching_is_explicitly_skipped():
    """--inventory-sample 을 안 주면 매칭을 '0건'으로 속이지 않고 수행하지 않았다고 밝힌다."""
    report = analyze(audit_records=_RECORDS, identities=None)

    assert report["identity_matching"]["performed"] is False
    assert "asset_identifier_coverage" in report
    assert "note" in report["asset_identifier_coverage"]


def test_output_never_contains_raw_actor_or_record_fields():
    """민감정보(원문 actor/레코드)가 출력에 섞이지 않는지 직접 확인한다."""
    report = analyze(audit_records=_RECORDS, identities=_IDENTITIES)
    serialized = json.dumps(report, ensure_ascii=False)

    assert "deploy-bot[bot]" not in serialized
    assert "random-human" not in serialized
    # 집계 필드명(unmatched_actor_event_count 등)은 허용하되, 원문 actor 값은 없어야 한다
    assert "deploy-bot" not in serialized


# --------------------------------------------------------------------------- 마스킹 수정 — 정상적인 긴 action 이름
_LONG_LEGITIMATE_ACTIONS = [
    "protected_branch.policy_override",
    "repository_secret.create",
    "oauth_authorization.create",
    "integration_installation.create",
    "business_advanced_security.enable",
]


def test_normal_long_action_names_are_not_masked():
    """핵심 회귀 테스트 — 20자 이상인 정상 GitHub action 이름이 더 이상 가려지지
    않아야 한다(이번 4차 작업의 목적)."""
    for action in _LONG_LEGITIMATE_ACTIONS:
        assert len(action) >= 20
        assert _classify_action(action) == "format_valid"

    records = [{"action": action, "created_at": "2026-01-01T00:00:00Z"} for action in _LONG_LEGITIMATE_ACTIONS]
    report = analyze(audit_records=records, identities=None)

    for action in _LONG_LEGITIMATE_ACTIONS:
        assert report["format_valid_action_distribution"][action] == 1
    assert report["unvalidated_action_distribution"] == {}


def test_short_action_names_still_pass_through_global_sanitizer_path():
    for action in ("org.update_member", "repo.access", "hook.create"):
        assert len(action) < 20
        assert _classify_action(action) == "format_valid"


# --------------------------------------------------------------------------- 충돌 방지 — 서로 다른 미검증 값
def test_different_unvalidated_values_get_distinct_opaque_ids_not_merged():
    """이전 버전에서는 여러 긴 action이 전부 같은 마스킹 문자열로 합쳐졌다.
    미검증 값들이 서로 구분되는지 확인한다."""
    records = [
        {"action": "Not A Valid Github Action Name!!", "created_at": "2026-01-01T00:00:00Z"},
        {"action": "ALSO-NOT-VALID-0123456789-TOO", "created_at": "2026-01-02T00:00:00Z"},
        {"action": "Not A Valid Github Action Name!!", "created_at": "2026-01-03T00:00:00Z"},  # 같은 값 재등장
    ]

    report = analyze(audit_records=records, identities=None)

    unvalidated = report["unvalidated_action_distribution"]
    assert len(unvalidated) == 2  # 서로 다른 원문 2종 -> opaque id 2개
    counts = sorted(entry["count"] for entry in unvalidated.values())
    assert counts == [1, 2]  # 같은 원문 재등장은 같은 id로 합산됨


def test_unvalidated_distribution_never_contains_raw_value():
    records = [{"action": "this is definitely not a github action format!!", "created_at": "2026-01-01T00:00:00Z"}]
    report = analyze(audit_records=records, identities=None)

    serialized = json.dumps(report, ensure_ascii=False)
    assert "this is definitely not a github action format" not in serialized
    assert list(report["unvalidated_action_distribution"].keys())[0].startswith("UNVALIDATED_ACTION_")


# --------------------------------------------------------------------------- 악의적인 action 문자열
def test_credential_shaped_action_is_not_treated_as_valid_even_with_dot_suffix():
    """형식 규칙(점 구분자)만 흉내 낸 자격증명 모양 문자열은 통과하면 안 된다."""
    malicious = "ghp_abcdefghijklmnopqrstuvwxyz0123456789.fake_action"
    assert _classify_action(malicious) == "format_invalid"

    records = [{"action": malicious, "created_at": "2026-01-01T00:00:00Z"}]
    report = analyze(audit_records=records, identities=None)
    serialized = json.dumps(report, ensure_ascii=False)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in serialized
    assert report["format_valid_action_distribution"] == {}


def test_extremely_long_action_string_is_rejected_without_regex_blowup():
    """100,000자짜리 입력도 정규식 재앙적 역추적 없이 즉시(길이 상한에서) 처리돼야 한다."""
    malicious = "a" * 100_000 + ".action"

    records = [{"action": malicious, "created_at": "2026-01-01T00:00:00Z"}]
    report = analyze(audit_records=records, identities=None)  # 타임아웃 없이 끝나야 통과

    assert report["format_valid_action_distribution"] == {}
    assert len(report["unvalidated_action_distribution"]) == 1


def test_assignment_and_auth_scheme_shaped_strings_are_rejected():
    for malicious in (
        "token=abcdefghijklmnopqrstuvwxyz.action",
        "secret:abcdefghijklmnopqrstuvwxyz.action",
    ):
        assert _classify_action(malicious) == "format_invalid"


# --------------------------------------------------------------------------- 참조 목록 일치 vs 형식만 검증
def test_known_actions_reference_list_marks_user_provided_match_separately():
    records = [
        {"action": "repository_secret.create", "created_at": "2026-01-01T00:00:00Z"},
        {"action": "org.update_member", "created_at": "2026-01-02T00:00:00Z"},
    ]

    report_without_reference = analyze(audit_records=records, identities=None)
    assert report_without_reference["user_provided_reference_match_distribution"] == {}
    assert report_without_reference["format_valid_action_distribution"] == {
        "repository_secret.create": 1,
        "org.update_member": 1,
    }
    assert "note" in report_without_reference["action_name_summary"]
    assert "known_actions_disclaimer" in report_without_reference["action_name_summary"]

    report_with_reference = analyze(
        audit_records=records, identities=None, known_actions={"repository_secret.create"}
    )
    assert report_with_reference["user_provided_reference_match_distribution"] == {
        "repository_secret.create": 1
    }
    # 참조 목록에 없는 건 형식만 맞아도 '참조 목록 일치'로 표시되지 않는다
    assert report_with_reference["format_valid_action_distribution"] == {"org.update_member": 1}


def test_reference_match_output_never_claims_official_github_verification():
    """officially_confirmed 같은 권위적인 표현이 다시 등장하지 않는지,
    목록 제공 시에도 출처 미검증 안내가 항상 포함되는지 확인한다."""
    records = [{"action": "repository_secret.create", "created_at": "2026-01-01T00:00:00Z"}]
    report = analyze(
        audit_records=records, identities=None, known_actions={"repository_secret.create"}
    )

    serialized = json.dumps(report, ensure_ascii=False)
    assert "officially_confirmed" not in serialized
    assert "공식 검증" not in serialized
    assert "공식 확인됨" not in serialized

    disclaimer = report["action_name_summary"]["known_actions_disclaimer"]
    assert "검증하지 않는다" in disclaimer
    assert "user_provided_reference_match" in disclaimer


# --------------------------------------------------------------------------- CLI
def test_cli_reads_local_sample_files_and_supports_known_actions(tmp_path, capsys):
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(_RECORDS), encoding="utf-8")
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(
            [{"nhi_id": "deploy-bot-app", "nhi_name": "deploy-bot", "nhi_type": "GITHUB_APP",
              "account": {"app_slug": "deploy-bot"}}]
        ),
        encoding="utf-8",
    )
    known_actions_path = tmp_path / "known_actions.json"
    known_actions_path.write_text(json.dumps(["repo.access"]), encoding="utf-8")

    exit_code = main(
        [
            "--audit-sample", str(audit_path),
            "--inventory-sample", str(inventory_path),
            "--known-actions", str(known_actions_path),
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["input_summary"]["raw_record_count"] == 6
    assert output["identity_matching"]["matched_distinct_nhi_count"] == 1
    assert output["user_provided_reference_match_distribution"] == {"repo.access": 2}


def test_cli_missing_file_exits_with_clear_error(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    try:
        main(["--audit-sample", str(missing)])
        assert False, "SystemExit를 기대했다"
    except SystemExit as exc:
        assert exc.code != 0
