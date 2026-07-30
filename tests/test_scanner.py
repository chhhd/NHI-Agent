"""Scanner 단위 테스트."""

from __future__ import annotations

import pytest

from core.models import DetectorType, ScanTarget
from scanner.entropy_scanner import EntropyScanner, shannon_entropy
from scanner.fingerprint import build_fingerprint, build_location_fingerprint
from scanner.masking import mask_line, mask_secret
from scanner.regex_scanner import RegexScanner, is_scannable_path
from scanner.scan_service import SecretScanService

SLACK_BOT_TOKEN = "xoxb-2154537424-2154537424-Ttk4L8xR2mQaZbYuVnW7pQ3d"
GITHUB_PAT = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLEX"[:20]


# ---------------------------------------------------------------------------
# masking
# ---------------------------------------------------------------------------
def test_mask_secret_keeps_prefix_and_suffix():
    masked = mask_secret(SLACK_BOT_TOKEN, keep_prefix=5)
    assert masked.startswith("xoxb-")
    assert masked.endswith(SLACK_BOT_TOKEN[-4:])
    assert SLACK_BOT_TOKEN not in masked


def test_mask_secret_short_value_fully_masked():
    assert mask_secret("abc123") == "******"


def test_mask_line_removes_raw_value():
    line = f'SLACK_TOKEN="{SLACK_BOT_TOKEN}"'
    masked = mask_line(line, [SLACK_BOT_TOKEN], keep_prefix=5)
    assert SLACK_BOT_TOKEN not in masked
    assert "SLACK_TOKEN" in masked


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------
def test_fingerprint_is_stable_and_location_independent():
    fp1 = build_fingerprint("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN)
    fp2 = build_fingerprint("SLACK_BOT_TOKEN", f'  "{SLACK_BOT_TOKEN}"  ')
    assert fp1 == fp2
    assert fp1.startswith("sha256:")
    assert SLACK_BOT_TOKEN not in fp1


def test_location_fingerprint_differs_by_location():
    a = build_location_fingerprint("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN, "a.env", 1)
    b = build_location_fingerprint("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN, "b.env", 1)
    assert a != b


# ---------------------------------------------------------------------------
# regex scanner
# ---------------------------------------------------------------------------
def test_regex_scanner_detects_slack_and_github():
    text = f"SLACK_BOT_TOKEN={SLACK_BOT_TOKEN}\nGITHUB_TOKEN={GITHUB_PAT}\n"
    found = {c.secret_type for c in RegexScanner().scan_text(text)}
    assert "SLACK_BOT_TOKEN" in found
    assert "GITHUB_PAT" in found


def test_regex_scanner_skips_placeholder():
    text = 'api_key = "your-api-key-here-placeholder"'
    assert RegexScanner().scan_text(text) == []


def test_regex_scanner_respects_ignore_marker():
    text = f"token = '{SLACK_BOT_TOKEN}'  # nhi:ignore"
    assert RegexScanner().scan_text(text) == []


@pytest.mark.parametrize(
    "path,expected",
    [
        ("config/slack.env", True),
        (".env.production", True),
        ("src/app.py", True),
        ("app/config.yaml", True),
        ("node_modules/pkg/index.js", False),
        ("package-lock.json", False),
        ("assets/logo.png", False),
        ("dist/bundle.min.js", False),
    ],
)
def test_is_scannable_path(path, expected):
    assert is_scannable_path(path) is expected


# ---------------------------------------------------------------------------
# entropy scanner
# ---------------------------------------------------------------------------
def test_shannon_entropy_random_higher_than_repeated():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < shannon_entropy("Xk3Lm9Qp2Zr7Vt1B")


def test_entropy_scanner_ignores_uuid_and_words():
    scanner = EntropyScanner()
    assert scanner.scan_line("id = 550e8400-e29b-41d4-a716-446655440000", 1) == []
    assert scanner.scan_line("some_long_variable_name_here", 1) == []


def test_entropy_scanner_detects_random_secret():
    scanner = EntropyScanner()
    found = scanner.scan_line("INTERNAL_KEY=Zq7Xv2Nk9Pw4Lm1Bt6Rd3Yh8Sc5Gf0J", 1)
    assert found, "고엔트로피 문자열이 탐지되어야 한다"


def test_entropy_scanner_ignores_pinned_action_sha():
    """GitHub Actions 는 `uses: owner/action@<commit sha>` 로 버전을 고정한다.

    커밋 SHA 는 순수 hex 40자라 엔트로피 임계값을 넘지만 자격 증명이 아니다.
    (실제 공개 저장소 스캔에서 CRITICAL 오탐을 만들었던 사례)
    """
    scanner = EntropyScanner()
    line = "      uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"
    assert scanner.scan_line(line, 23) == []


#: 40자 git commit SHA / 64자 SHA-256 digest 형태
COMMIT_SHA = "a5ac7e51b41094c92402da3b24376905380afc29"
SHA256_DIGEST = "3f9a1c7d4b8e2056af1d9c3e7b504a2681fd35c9e4b7a0182d6c5f3e9b1a4708"


def test_entropy_scanner_ignores_bare_git_sha_and_digest():
    scanner = EntropyScanner()

    assert scanner.scan_line(f"    pinned_ref = '{COMMIT_SHA}'", 1) == []
    assert scanner.scan_line(f"    baseline = '{SHA256_DIGEST}'", 2) == []


def test_entropy_scanner_keeps_hex_secret_with_credential_keyword():
    """같은 형태라도 자격 증명 키워드와 함께 있으면 후보로 남긴다."""
    scanner = EntropyScanner()
    found = scanner.scan_line(f"api_secret_key = '{SHA256_DIGEST}'", 1)
    assert found, "키워드가 있으면 hex 값도 탐지 대상이어야 한다"


# ---------------------------------------------------------------------------
# scan service
# ---------------------------------------------------------------------------
def test_scan_file_produces_masked_finding():
    target = ScanTarget(
        path="config/slack.env",
        content="# slack settings\nAPP_NAME=demo\n" f"SLACK_BOT_TOKEN={SLACK_BOT_TOKEN}\nDEBUG=1\n",
    )
    findings = SecretScanService().scan_file(target)
    slack = next(f for f in findings if f.secret_type == "SLACK_BOT_TOKEN")

    assert slack.provider == "slack"
    assert slack.line_number == 3
    assert slack.detector == DetectorType.REGEX
    assert SLACK_BOT_TOKEN not in slack.masked_value
    assert slack.context.before  # 앞 문맥이 추출됨
    assert SLACK_BOT_TOKEN not in slack.context.line

    payload = slack.to_dict()
    assert "_raw_value" not in payload
    assert SLACK_BOT_TOKEN not in str(payload)


def test_duplicate_secret_is_merged():
    targets = [
        ScanTarget(path="a.env", content=f"TOKEN={SLACK_BOT_TOKEN}"),
        ScanTarget(path="b.env", content=f"TOKEN={SLACK_BOT_TOKEN}"),
    ]
    result = SecretScanService().scan_targets(targets, repository="org/repo")
    slack = [f for f in result.findings if f.secret_type == "SLACK_BOT_TOKEN"]

    assert len(slack) == 1
    assert slack[0].occurrence_count == 2
    assert slack[0].duplicate_locations[0]["file_path"] == "b.env"


def test_unsupported_file_is_skipped():
    result = SecretScanService().scan_targets(
        [ScanTarget(path="logo.png", content="binary-ish")], repository="org/repo"
    )
    assert result.scanned_files == 0
    assert result.skipped_files[0]["reason"] == "unsupported_file_type"
