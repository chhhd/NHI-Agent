"""보안 위생 점검 스크립트 테스트 — 값은 출력하지 않고 설정 약점만 보고하는지 본다."""

from __future__ import annotations

from pathlib import Path

from scripts.check_security import Finding, main, run_checks

SECRET = "super-secret-value-0123456789"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"


def codes(findings):
    return {f.code for f in findings}


def project(tmp_path: Path, env: str, gitignore: str = ".env\n*.pem\n*.db\n") -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".env").write_text(env, encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")
    return root


def test_weak_admin_key_and_empty_salt_are_reported_without_leaking_values(tmp_path, capsys):
    root = project(tmp_path, f"NHI_ADMIN_API_KEY=short14chars!!\nFINGERPRINT_SALT=\nGITHUB_TOKEN={SECRET}\n")
    findings = run_checks(root)
    assert {"ADMIN_KEY_WEAK", "FINGERPRINT_SALT_EMPTY", "TOKENS_IN_ENV"} <= codes(findings)

    assert main(["--root", str(root)]) == 1  # HIGH 존재
    output = capsys.readouterr().out
    assert SECRET not in output and "short14chars" not in output


def test_strong_configuration_has_no_high_findings(tmp_path):
    root = project(
        tmp_path,
        "NHI_ADMIN_API_KEY=" + "a" * 40 + "\nFINGERPRINT_SALT=" + "b" * 32 + "\n"
        "NHI_RUNTIME_TOKEN_SIGNING_KEY=" + "c" * 40 + "\n",
    )
    assert not [f for f in run_checks(root) if f.severity == "HIGH"]
    assert main(["--root", str(root)]) == 0


def test_signing_key_must_differ_from_admin_key(tmp_path):
    key = "k" * 40
    root = project(tmp_path, f"NHI_ADMIN_API_KEY={key}\nNHI_RUNTIME_TOKEN_SIGNING_KEY={key}\n")
    assert "SIGNING_KEY_WEAK" in codes(run_checks(root))


def test_private_key_next_to_project_is_found_and_gitignore_gap_reported(tmp_path):
    root = project(tmp_path, "NHI_ADMIN_API_KEY=" + "a" * 40 + "\n", gitignore="# empty\n")
    (tmp_path / "app.private-key.pem").write_text(PEM, encoding="utf-8")
    found = codes(run_checks(root))
    assert "PRIVATE_KEY_FILE" in found and "GITIGNORE_GAP" in found


def test_synced_folder_with_tokens_is_high(tmp_path):
    root = tmp_path / "OneDrive" / "proj"
    root.mkdir(parents=True)
    (root / ".env").write_text(f"NHI_ADMIN_API_KEY={'a' * 40}\nSLACK_BOT_TOKEN={SECRET}\n", encoding="utf-8")
    (root / ".gitignore").write_text(".env\n*.pem\n*.db\n", encoding="utf-8")
    synced = [f for f in run_checks(root) if f.code == "SYNCED_FOLDER"]
    assert synced and synced[0].severity == "HIGH"
    assert isinstance(synced[0], Finding)
