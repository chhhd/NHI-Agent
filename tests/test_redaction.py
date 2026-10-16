"""security/redaction.py — sanitize_security_text / sanitize_security_value.

`preserve_top_level_keys` 회귀 테스트가 핵심이다: 구조화된 dataclass
필드명(예: `token_used_after_revocation`, 27자)이 `redact_unknown_tokens`
(20자 이상 토큰형 문자열 마스킹)에 걸려 손상되던 버그를 고정한다.
"""

from __future__ import annotations

from security.redaction import sanitize_security_text, sanitize_security_value

SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


# ---------------------------------------------------------------------------
# sanitize_security_text — 값(문자열) 레벨 마스킹, 기존 동작 그대로
# ---------------------------------------------------------------------------
def test_sanitize_security_text_masks_known_secret_prefix():
    assert SECRET not in sanitize_security_text(f"token={SECRET}")


def test_sanitize_security_text_masks_bearer_scheme():
    text = sanitize_security_text(f"Authorization: Bearer {SECRET}")
    assert SECRET not in text


def test_sanitize_security_text_truncates_to_max_length():
    # 공백으로 끊어 단일 토큰(20자+)으로 오인돼 마스킹되지 않게 한다 —
    # 이 테스트는 길이 제한만 검증한다.
    long_text = "word " * 200
    assert len(sanitize_security_text(long_text, max_length=50)) == 50


# ---------------------------------------------------------------------------
# sanitize_security_value — 기본 동작(키/값 모두 정리)은 그대로 유지
# ---------------------------------------------------------------------------
def test_default_behavior_sanitizes_both_keys_and_values():
    """기존 호출부(agent_runtime, usage_event_adapter, sqlite_store 등)가
    의존하는 기본 동작 — 변경하지 않았음을 고정한다."""
    long_key = "some_externally_supplied_long_header_name"  # 20자 이상
    result = sanitize_security_value({long_key: SECRET})

    assert long_key not in result
    assert SECRET not in str(result)


def test_default_behavior_masks_long_field_name_key_without_the_flag():
    """`preserve_top_level_keys`를 안 주면(기본값 False) 여전히 긴 키 이름도
    마스킹 대상이다 — 새 기능이 기존 동작을 바꾸지 않았음을 보인다."""
    result = sanitize_security_value({"token_used_after_revocation": True})

    assert "token_used_after_revocation" not in result


def test_nested_lists_and_depth_limit_still_work():
    nested = {"a": {"b": {"c": {"d": {"e": "too deep"}}}}}
    result = sanitize_security_value(nested)
    # depth>=4 에서 "<truncated>"로 끊긴다 — 기존 동작 유지.
    assert "<truncated>" in str(result)


# ---------------------------------------------------------------------------
# preserve_top_level_keys=True — 이번에 고친 동작
# ---------------------------------------------------------------------------
def test_preserve_top_level_keys_keeps_long_structured_field_names():
    result = sanitize_security_value(
        {
            "token_used_after_revocation": True,
            "token_replay_suspected": True,
            "token_binding_method": "DPoP",
            "declared_permissions": ["READ"],
            "exception_expires_at": "2026-12-31T00:00:00Z",
        },
        preserve_top_level_keys=True,
    )

    assert result["token_used_after_revocation"] is True
    assert result["token_replay_suspected"] is True
    assert result["token_binding_method"] == "DPoP"
    assert result["declared_permissions"] == ["READ"]
    assert result["exception_expires_at"] == "2026-12-31T00:00:00Z"


def test_preserve_top_level_keys_still_masks_values():
    """키는 보존해도 값에 포함된 민감정보는 그대로 마스킹된다."""
    result = sanitize_security_value(
        {"request_user_agent": f"curl Authorization: Bearer {SECRET}"},
        preserve_top_level_keys=True,
    )

    assert "request_user_agent" in result
    assert SECRET not in result["request_user_agent"]


def test_preserve_top_level_keys_only_applies_at_depth_zero():
    """최상위 키만 보존된다 — 한 단계 더 들어간 dict의 키는 여전히 정리된다."""
    long_nested_key = "some_externally_supplied_long_header_name"
    result = sanitize_security_value(
        {"extra": {long_nested_key: SECRET}},
        preserve_top_level_keys=True,
    )

    assert "extra" in result  # 최상위 키는 보존
    assert long_nested_key not in result["extra"]  # 중첩 키는 여전히 정리
    assert SECRET not in str(result["extra"])


def test_preserve_top_level_keys_short_keys_unaffected():
    """20자 미만인 키는 애초에 마스킹 대상이 아니므로 플래그 유무와 무관하다."""
    without_flag = sanitize_security_value({"owner": "platform-team"})
    with_flag = sanitize_security_value({"owner": "platform-team"}, preserve_top_level_keys=True)

    assert without_flag == with_flag == {"owner": "platform-team"}


def test_preserve_top_level_keys_on_non_dict_value_is_a_noop():
    """dict가 아닌 값(문자열/리스트)에는 top-level 키 개념이 없으므로 그대로 동작한다."""
    assert sanitize_security_value([SECRET], preserve_top_level_keys=True) == [
        sanitize_security_value(SECRET)
    ]
