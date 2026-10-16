"""scripts/check_security.py — 배포 전 보안 위생 점검 스크립트.

이 프로젝트의 실제 `.env.example` 변수명과 `.gitignore` 패턴에 맞게 호환되는지,
값은 절대 출력하지 않는지(길이·존재 여부만), Windows 콘솔 인코딩에서 깨지지
않는지를 확인한다. 실제 프로젝트 `.env`/`.gitignore`는 건드리지 않고 임시
디렉터리에 합성 fixture 를 만들어 검증한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_security import Finding, parse_env, run_checks


def _write(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_parse_env_ignores_comments_and_strips_quotes(tmp_path):
    _write(tmp_path, ".env", '# comment\nNHI_ADMIN_API_KEY="abc123"\nEMPTY=\n')
    env = parse_env(tmp_path / ".env")
    assert env["NHI_ADMIN_API_KEY"] == "abc123"
    assert env["EMPTY"] == ""
    assert "comment" not in env


def test_missing_env_reports_info_only(tmp_path):
    findings = run_checks(tmp_path)
    assert any(f.code == "ENV_MISSING" for f in findings)
    assert not any(f.severity == "HIGH" for f in findings)


def test_weak_admin_key_is_high_severity(tmp_path):
    _write(tmp_path, ".env", "NHI_ADMIN_API_KEY=admin\n")
    findings = run_checks(tmp_path)
    assert any(f.code == "ADMIN_KEY_WEAK" and f.severity == "HIGH" for f in findings)


def test_missing_admin_key_is_high_severity(tmp_path):
    _write(tmp_path, ".env", "FINGERPRINT_SALT=x\n")
    findings = run_checks(tmp_path)
    assert any(f.code == "ADMIN_KEY_MISSING" and f.severity == "HIGH" for f in findings)


def test_strong_admin_key_does_not_trigger_weak_finding(tmp_path):
    _write(tmp_path, ".env", "NHI_ADMIN_API_KEY=" + "a" * 40 + "\n")
    findings = run_checks(tmp_path)
    assert not any(f.code in ("ADMIN_KEY_WEAK", "ADMIN_KEY_MISSING") for f in findings)


def test_verified_admin_limitation_is_always_reported_not_configurable(tmp_path):
    """이 프로젝트는 개인별 인증 기반 관리자 신원 체계가 아예 없다 — 환경변수로
    끄고 켤 수 있는 토글이 아니라 항상 적용되는 한계라서, .env 내용과 무관하게
    항상 보고돼야 한다(팀원 원본의 조건부 체크를 우리 실제 상태에 맞게 바꾼 부분)."""
    _write(tmp_path, ".env", "NHI_ADMIN_API_KEY=" + "a" * 40 + "\n")
    findings = run_checks(tmp_path)
    assert any(f.code == "VERIFIED_ADMIN_NOT_IMPLEMENTED" for f in findings)


def test_never_prints_actual_secret_values(tmp_path):
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    _write(tmp_path, ".env", f"NHI_ADMIN_API_KEY={secret}\nGITHUB_TOKEN={secret}\n")
    findings = run_checks(tmp_path)
    for finding in findings:
        assert secret not in finding.message


def test_gitignore_gap_detection_matches_this_projects_patterns(tmp_path):
    _write(tmp_path, ".gitignore", "*.pyc\n")
    findings = run_checks(tmp_path)
    gaps = {f.message for f in findings if f.code == "GITIGNORE_GAP"}
    assert any(".env" in g for g in gaps)
    assert any("개인키" in g for g in gaps)
    assert any("DB" in g for g in gaps)


def test_gitignore_matching_this_projects_actual_patterns_has_no_gap(tmp_path):
    actual_gitignore = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8")
    _write(tmp_path, ".gitignore", actual_gitignore)
    findings = run_checks(tmp_path)
    assert not any(f.code == "GITIGNORE_GAP" for f in findings)


def test_db_file_is_reported_as_info_without_reading_contents(tmp_path):
    _write(tmp_path, "nhi_scanner.db", "binary-ish-content")
    findings = run_checks(tmp_path)
    db_findings = [f for f in findings if f.code == "DB_FILE"]
    assert len(db_findings) == 1
    assert "nhi_scanner.db" in db_findings[0].message


def test_main_exits_nonzero_only_when_high_severity_present(tmp_path):
    from scripts.check_security import main

    _write(tmp_path, ".env", "NHI_ADMIN_API_KEY=" + "a" * 40 + "\n")
    _write(tmp_path, ".gitignore", (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8"))
    exit_code = main(["--root", str(tmp_path)])
    assert exit_code == 0

    _write(tmp_path, ".env", "NHI_ADMIN_API_KEY=weak\n")
    exit_code = main(["--root", str(tmp_path)])
    assert exit_code == 1
