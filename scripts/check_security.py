"""배포·공유 전 보안 위생 점검.

`.env` 의 약한 설정, 프로젝트 근처에 놓인 개인키, 클라우드 동기화 폴더 위치,
`.gitignore` 누락을 찾는다. **값은 절대 출력하지 않는다** — 길이와 존재 여부만 보고한다.

    python scripts/check_security.py            # 현재 프로젝트
    python scripts/check_security.py --root .   # 경로 지정

HIGH 항목이 있으면 종료 코드 1.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

# Windows 콘솔 기본 코드페이지(cp949 등)는 "—" 같은 유니코드 구두점을 인코딩하지
# 못해 UnicodeEncodeError로 죽는다 — 이 스크립트는 환경변수 설정 없이 바로
# 실행되는 걸 전제하므로, 호출부가 PYTHONIOENCODING을 맞춰주길 기대하지 않고
# 여기서 직접 utf-8로 맞춘다.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SYNC_FOLDER_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "box sync")
WEAK_VALUES = {"changeme", "change-me", "password", "admin", "secret", "test", "1234", "12345678"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
TOKEN_VARIABLES = (
    "GITHUB_TOKEN",
    "GITHUB_INVENTORY_TOKEN",
    "SLACK_BOT_TOKEN",
    "GITLAB_TOKEN",
    "NOTION_TOKEN",
    "HUGGINGFACE_TOKEN",
    "MICROSOFT_CLIENT_SECRET",
    "MICROSOFT_GRAPH_ACCESS_TOKEN",
    "GOOGLE_WORKSPACE_ACCESS_TOKEN",
)
GITIGNORE_REQUIRED = {
    ".env": (".env",),
    "개인키(*.pem)": ("*.pem", "*private-key*", "*.key"),
    "DB(*.db)": ("*.db",),
}


@dataclass(frozen=True)
class Finding:
    severity: str  # HIGH / MEDIUM / INFO
    code: str
    message: str


def parse_env(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
        if match and not line.lstrip().startswith("#"):
            values[match.group(1)] = match.group(2).strip().strip('"').strip("'")
    return values


def _private_key_files(root: Path, levels_up: int = 2) -> Iterable[Path]:
    """프로젝트와 그 상위 폴더(기본 2단계)의 개인키 파일. node_modules/venv 등은 건너뛴다."""
    base = root
    for _ in range(levels_up):
        if base.parent != base:
            base = base.parent
    skip = {"node_modules", ".git", "venv", ".venv", "__pycache__", "site-packages"}
    stack = [base]
    seen = 0
    while stack and seen < 5000:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in skip:
                    stack.append(entry)
                continue
            seen += 1
            if entry.suffix.lower() in {".pem", ".key", ".p12", ".pfx"} or "private-key" in entry.name:
                try:
                    head = entry.read_text(encoding="utf-8", errors="ignore")[:4096]
                except OSError:
                    continue
                if PRIVATE_KEY_RE.search(head):
                    yield entry


def run_checks(root: Path) -> List[Finding]:
    root = root.resolve()
    findings: List[Finding] = []
    env = parse_env(root / ".env")

    if not env:
        findings.append(Finding("INFO", "ENV_MISSING", ".env 가 없어 환경 설정 점검을 건너뜁니다."))
    else:
        admin = env.get("NHI_ADMIN_API_KEY", "")
        if not admin:
            findings.append(Finding("HIGH", "ADMIN_KEY_MISSING", "NHI_ADMIN_API_KEY 가 비어 있어 승인·Credential API 가 비활성입니다."))
        elif len(admin) < 32 or admin.lower() in WEAK_VALUES:
            findings.append(Finding("HIGH", "ADMIN_KEY_WEAK", f"NHI_ADMIN_API_KEY 가 {len(admin)}자입니다. 32자 이상 무작위 값으로 바꾸세요."))

        # 이 프로젝트는 개인별 인증 기반 관리자 신원 체계(예: /admin/principals)를
        # 아직 구현하지 않았다 — 설정으로 켜고 끌 수 있는 토글이 아니라 항상
        # 적용되는 한계다. Change Control의 직무분리(requested_by != approved_by)는
        # 자유 텍스트 이름 비교일 뿐 실제 사용자 신원을 확인하지 않는다.
        findings.append(Finding(
            "INFO", "VERIFIED_ADMIN_NOT_IMPLEMENTED",
            "개인별 인증 기반 관리자 신원 체계가 아직 없습니다 — requested_by/approved_by는 자유 "
            "텍스트이고 공용 NHI_ADMIN_API_KEY 하나로만 보호됩니다. 직무 분리는 이름 문자열이 "
            "다른지만 확인하므로, 같은 키를 가진 사람이 두 역할을 모두 자처할 수 있습니다.",
        ))

        signing = env.get("NHI_RUNTIME_TOKEN_SIGNING_KEY", "")
        if signing and (len(signing) < 32 or signing == admin):
            findings.append(Finding("HIGH", "SIGNING_KEY_WEAK", "NHI_RUNTIME_TOKEN_SIGNING_KEY 는 32자 이상이고 관리자 키와 달라야 합니다."))

        if not env.get("FINGERPRINT_SALT"):
            findings.append(Finding("MEDIUM", "FINGERPRINT_SALT_EMPTY", "FINGERPRINT_SALT 가 비어 있습니다. 실데이터를 넣기 전에 정하세요 — 나중에 바꾸면 과거 fingerprint 와 대조할 수 없습니다."))
        if not env.get("NHI_MASTER_KEY"):
            findings.append(Finding("INFO", "MASTER_KEY_EMPTY", "NHI_MASTER_KEY 가 비어 있어 Secret material 보관(persist_secret_material)이 비활성입니다."))

        secret = env.get("GITHUB_WEBHOOK_SECRET", "")
        if secret and (len(secret) < 20 or secret.lower() in WEAK_VALUES):
            findings.append(Finding("MEDIUM", "WEBHOOK_SECRET_WEAK", f"GITHUB_WEBHOOK_SECRET 가 {len(secret)}자입니다. 20자 이상 무작위 값을 권장합니다."))

        present = [name for name in TOKEN_VARIABLES if env.get(name)]
        if present:
            findings.append(Finding("INFO", "TOKENS_IN_ENV", f".env 에 실제 토큰 {len(present)}개가 있습니다({', '.join(present)}). 이 폴더가 동기화·공유됐다면 회전하세요."))

    lowered = str(root).lower()
    marker = next((m for m in SYNC_FOLDER_MARKERS if m in lowered), None)
    if marker:
        severity = "HIGH" if env and any(env.get(n) for n in TOKEN_VARIABLES) else "MEDIUM"
        findings.append(Finding(severity, "SYNCED_FOLDER", f"프로젝트가 클라우드 동기화 폴더({marker}) 안에 있습니다. .env 와 DB 가 클라우드에 복제됩니다."))

    for key_file in _private_key_files(root):
        try:
            rel = key_file.relative_to(root)
        except ValueError:
            rel = key_file
        in_sync = any(m in str(key_file).lower() for m in SYNC_FOLDER_MARKERS)
        findings.append(Finding("HIGH" if in_sync else "MEDIUM", "PRIVATE_KEY_FILE", f"개인키 파일: {rel}" + (" (동기화 폴더 안)" if in_sync else "") + " — 프로젝트·동기화 폴더 밖의 권한 제한 위치로 옮기세요."))

    gitignore = root / ".gitignore"
    patterns = set()
    if gitignore.is_file():
        patterns = {
            line.strip() for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        }
    for label, options in GITIGNORE_REQUIRED.items():
        if not any(option in patterns for option in options):
            findings.append(Finding("MEDIUM", "GITIGNORE_GAP", f".gitignore 에 {label} 패턴이 없습니다."))

    for db in root.glob("*.db"):
        findings.append(Finding("INFO", "DB_FILE", f"{db.name} ({db.stat().st_size // 1024}KB) — 감사 로그·분석 결과가 들어 있으니 zip·저장소에 포함하지 마세요."))

    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args(argv)
    findings = run_checks(Path(args.root))
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    for item in sorted(findings, key=lambda f: order[f.severity]):
        print(f"[{item.severity:<6}] {item.code}: {item.message}")
    if not findings:
        print("문제를 찾지 못했습니다.")
    return 1 if any(f.severity == "HIGH" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
