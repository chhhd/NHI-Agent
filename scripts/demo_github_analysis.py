"""GitHub API → Secret 탐지 → NHI 분석 → 위험 점수화 전 과정 실행 스크립트.

실제 GitHub REST API 를 호출한다. 토큰이 없으면 공개 Repository 에 대해
비인증(시간당 60회 제한)으로 동작하므로, 검사 파일 수를 제한한다.

    python scripts/demo_github_analysis.py --repo octocat/Hello-World
    python scripts/demo_github_analysis.py --repo psf/requests --max-files 15
    python scripts/demo_github_analysis.py --repo acme/app --verify-credentials

`--verify-credentials` 는 탐지된 토큰을 해당 서비스 API 로 재검증한다(읽기 전용
호출만 사용). 기본값은 꺼져 있다. 스캔 결과에 남은 문자열을 외부로 보내는 동작이므로
필요할 때만 명시적으로 켠다.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional, Sequence

# 프로젝트 루트를 import 경로에 넣는다 (스크립트를 직접 실행할 수 있게).
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from agents.pipeline import NHIAnalysisPipeline  # noqa: E402
from connectors.base_connector import ConnectorError  # noqa: E402
from connectors.github_connector import GitHubConnector, Repository  # noqa: E402
from core.config import get_settings  # noqa: E402
from core.models import ScanTarget, ScanTrigger, SecretFinding  # noqa: E402
from core.nhi_models import (  # noqa: E402
    AnalysisSignals,
    AnalysisSource,
    Environment,
    NHIAnalysis,
    NHIAnalysisReport,
)
from rescan.credential_verifier import CredentialVerifier  # noqa: E402
from scanner.scan_service import SecretScanService  # noqa: E402

#: 자격 증명이 들어 있을 가능성이 높은 경로 키워드 (검사 우선순위)
PRIORITY_HINTS = (
    ".env", "env.", "secret", "credential", "token", "key", "auth", "config",
    "settings", "docker", "deploy", ".github/workflows", "terraform", "example",
    "test", "conftest",
)

#: 한 파일당 내용 조회 1회를 쓰므로 큰 파일은 건너뛴다.
MAX_FILE_BYTES = 200_000


def log(message: str = "") -> None:
    print(message, flush=True)


def section(title: str) -> None:
    log()
    log("=" * 78)
    log(f"  {title}")
    log("=" * 78)


def select_paths(files: Sequence[Dict[str, Any]], limit: int) -> List[str]:
    """검사할 파일을 고른다.

    API 호출 예산(파일 1개 = 호출 1회)이 제한되므로 자격 증명이 있을 만한 경로를
    먼저 채우고, 같은 순위에서는 내용이 많은 파일을 먼저 본다.
    전체 스캔에는 이런 선별이 필요 없다 — 토큰이 있으면 저장소 전체를 검사한다.
    """
    candidates = [
        f for f in files if 100 <= f.get("size", 0) <= MAX_FILE_BYTES
    ]

    def score(item: Dict[str, Any]) -> tuple:
        path = item["path"].lower()
        hits = sum(1 for hint in PRIORITY_HINTS if hint in path)
        return (-hits, -item.get("size", 0))

    ranked = sorted(candidates, key=score)
    return [item["path"] for item in ranked[:limit]]


def fetch_targets(
    github: GitHubConnector, repo: Repository, limit: int
) -> tuple[List[ScanTarget], List[Dict[str, Any]]]:
    files = github.list_files(repo.full_name, ref=repo.default_branch)
    paths = select_paths(files, limit)
    log(f"  스캔 대상 후보 {len(files)}개 중 {len(paths)}개 조회 (API 호출 예산 고려)")
    targets = github.build_scan_targets(repo.full_name, paths, ref=repo.default_branch)
    return targets, files


def print_repository(repo: Repository) -> None:
    log(f"  repository        : {repo.full_name}")
    log(f"  default branch    : {repo.default_branch}")
    log(f"  visibility        : {'private' if repo.private else 'public'}")
    log(f"  stars / forks     : {repo.raw.get('stargazers_count')} / {repo.raw.get('forks_count')}")
    log(f"  pushed_at         : {repo.raw.get('pushed_at')}")
    log(f"  url               : {repo.html_url}")


def print_findings(findings: Sequence[SecretFinding]) -> None:
    if not findings:
        log("  탐지된 Secret 없음.")
        log("  (검사한 파일 범위에서 알려진 패턴과 고엔트로피 문자열이 발견되지 않았다.)")
        return

    log(f"  {'유형':<28} {'severity':<9} {'검출기':<8} 위치")
    log(f"  {'-' * 28} {'-' * 9} {'-' * 8} {'-' * 30}")
    for finding in findings:
        log(
            f"  {finding.secret_type:<28} {finding.severity.value:<9} "
            f"{finding.detector.value:<8} {finding.file_path}:{finding.line_number}"
        )
        log(f"      마스킹된 값 : {finding.masked_value}")
        if finding.entropy is not None:
            log(f"      entropy    : {finding.entropy}")
        if finding.occurrence_count > 1:
            log(f"      중복 노출  : {finding.occurrence_count}곳")


def print_analysis(analysis: NHIAnalysis, *, index: int) -> None:
    data = analysis.to_dict()
    log()
    log(f"  [{index}] {data['nhi_name']}  ({data['nhi_type']})")
    log(f"      위험 점수     : {data['risk_score']}/100  →  {data['risk_level']}")
    if analysis.risk.forced_critical:
        rules = ", ".join(rule["rule_id"] for rule in analysis.risk.forced_rules)
        log(f"      강제 Critical : {rules} (원점수 {analysis.risk.base_score})")
    log(f"      Owner         : {data['owner'] or '미지정'}")
    log(f"      환경 / 민감도 : {data['environment']} / {analysis.context.data_sensitivity.value}")
    log(f"      권한          : {', '.join(data['permissions']) or '확인 불가'}"
        + ("  (Scope 미확인 — 유형 기준 가정)" if analysis.permissions.assumed else ""))
    if analysis.source is AnalysisSource.CODE_SCAN:
        log(f"      탐지 위치     : {data['file_path']}:{data['line_number']}")
    else:
        log(f"      입력 경로     : NHI 인벤토리 (접근 저장소 "
            f"{len(analysis.blast_radius.resource_samples)}개)")

    log("      ── 점수 구성 ──")
    for factor in analysis.risk.factors:
        log(f"        {factor.label:<24} {factor.score:>3}/{factor.max_score:<3} "
            f"{'; '.join(factor.reasons[:2])}")

    policy = analysis.policy
    log(f"      정책 판정     : {policy.outcome.value} "
        f"(위반 {len(policy.violations)}건"
        + (f": {', '.join(v.policy_id for v in policy.violations)}" if policy.violations else "")
        + ")")
    log(f"      조치 권고     : {data['recommended_action']}")
    for rec in analysis.recommendations[:3]:
        log(f"        {rec.priority}. {rec.action.value:<24} {rec.rationale[:70]}")

    blast = analysis.blast_radius
    log(f"      영향 범위     : impact {blast.impact_score}/100, "
        f"서비스 {', '.join(blast.connected_services)}, 자원 {blast.accessible_resources}개, "
        f"외부 전송 {'가능' if blast.external_transfer_possible else '불가'}")


def print_report(report: NHIAnalysisReport) -> None:
    summary = report.summary()
    log(f"  분석 대상        : {summary['total']}건")
    log(f"  위험 등급 분포   : {summary['by_risk_level']}")
    log(f"  최고 위험 점수   : {summary['max_risk_score']}")
    log(f"  NHI 식별 실패    : {summary['unknown_nhi']}건")
    log(f"  사람 검토 필요   : {summary['human_review_required']}건")

    for index, analysis in enumerate(report.analyses, start=1):
        print_analysis(analysis, index=index)

    if report.graph:
        stats = report.graph.get("stats", {})
        log()
        log(f"  관계 그래프      : 노드 {report.graph.get('node_count')}개 / "
            f"엣지 {report.graph.get('edge_count')}개  {stats}")


def analyze_repository(
    full_name: str, *, max_files: int, verify: bool, pipeline: NHIAnalysisPipeline
) -> Optional[NHIAnalysisReport]:
    section(f"1. GitHub API 연동 — {full_name}")

    with GitHubConnector() as github:
        repo = github.register_repository(full_name)
        print_repository(repo)
        targets, all_files = fetch_targets(github, repo, max_files)

        section(f"2. Secret 탐지 — {full_name}")
        result = SecretScanService().scan_targets(
            targets,
            repository=full_name,
            trigger=ScanTrigger.MANUAL,
        )
        log(f"  검사한 파일      : {result.scanned_files}개 "
            f"(저장소 전체 스캔 대상 {len(all_files)}개 중)")
        if result.skipped_files:
            log(f"  건너뛴 파일      : {len(result.skipped_files)}개 "
                f"({result.skipped_files[0]['reason']} 등)")
        log(f"  탐지 건수        : {len(result.findings)}건")
        log()
        print_findings(result.findings)

        if verify and result.findings:
            log()
            log("  외부 API 재검증 실행 (읽기 전용 호출)")
            CredentialVerifier().verify_all(result.findings)
            for finding in result.findings:
                log(f"    {finding.secret_type}: active={finding.credential_active} "
                    f"revoked={finding.credential_revoked} scopes={finding.raw_scopes}")

    if not result.findings:
        return None

    section(f"3. NHI 분석 및 위험 점수화 — {full_name}")
    report = pipeline.analyze_findings(
        result.findings,
        repository=full_name,
        # 공개 Repository 여부는 GitHub API 응답에서 그대로 가져온 사실이다.
        default_signals=AnalysisSignals(repository_public=not repo.private),
    )
    print_report(report)
    return report


def analyze_own_token(pipeline: NHIAnalysisPipeline) -> None:
    """설정된 GITHUB_TOKEN 자체를 NHI 로 보고 분석한다 (인벤토리 경로).

    토큰의 Scope·계정·접근 가능 Repository 를 GitHub API 에서 실제로 조회한 뒤,
    그 값으로 인벤토리 입력을 만들어 같은 채점 엔진에 넣는다.
    """
    from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo

    section("4. 사용 중인 GitHub Token 자체를 NHI 로 분석 (인벤토리 경로)")
    with GitHubConnector() as github:
        status = github.validate_credential()

    if status.active is not True:
        log(f"  토큰 검증 실패 — {status.error or '유효하지 않음'}")
        return

    account = status.account
    log(f"  계정             : {account.get('login')} ({account.get('type')})")
    log(f"  부여된 Scope     : {', '.join(status.raw_scopes) or '(fine-grained PAT — 헤더 없음)'}")
    log(f"  접근 가능 repo   : {len(status.accessible_resources)}개 (표본)")

    nhi = GitHubNHIInput(
        nhi_id=f"pat-{account.get('id')}",
        nhi_name=f"{account.get('login')}-pat",
        nhi_type=GitHubNHIType.PERSONAL_ACCESS_TOKEN,
        owner=account.get("name") or None,
        active=True,
        repositories=[
            RepositoryInfo(
                name=item["full_name"],
                visibility="private" if item.get("private") else "public",
            )
            for item in status.accessible_resources
        ],
        raw_permissions={scope: "write" for scope in status.raw_scopes} or {},
    )
    analysis = pipeline.analyze_github_nhi(nhi)
    print_analysis(analysis, index=1)


def run_agent_on_repository(
    full_name: str, *, assumed_permissions: Dict[str, str], allow_scan: bool
) -> Optional[NHIAnalysis]:
    """실제 저장소 메타데이터로 인벤토리 레코드를 만들고 Agent 를 실행한다.

    저장소 이름·공개 범위·마지막 푸시 시각은 GitHub API 응답에서 가져온 사실이고,
    NHI 의 권한은 **가정값**이다(비인증 상태에서는 App 설치 권한을 조회할 수 없다).
    실제 운영에서는 Installation API 로 채워야 하는 자리다.
    """
    from agent_runtime import NHIAgentRequest, run_nhi_agent
    from core.inventory_models import GitHubNHIInput, GitHubNHIType, RepositoryInfo

    section(f"4. Agent 실행 — {full_name}")

    with GitHubConnector() as github:
        repo = github.get_repository(full_name)

    nhi = GitHubNHIInput(
        nhi_id=f"actions-{repo.full_name.replace('/', '-')}",
        nhi_name=f"{repo.name}-ci-credential",
        nhi_type=GitHubNHIType.ACTIONS_CREDENTIAL,
        owner=None,  # 인벤토리에 담당자 정보가 없는 상태를 그대로 표현한다
        environment=Environment.PRODUCTION,
        active=True,
        repositories=[
            RepositoryInfo(
                name=repo.full_name,
                visibility="private" if repo.private else "public",
                is_sensitive=False,
            )
        ],
        raw_permissions=assumed_permissions,
        last_used_at=None,
    )
    log(f"  입력 (API 사실)  : repo={repo.full_name}, "
        f"visibility={'private' if repo.private else 'public'}")
    log(f"  입력 (가정값)    : permissions={assumed_permissions}, owner=미지정")
    log(f"  허용 옵션        : secret_scan={allow_scan}, policy_evaluation=True")

    state = run_nhi_agent(
        NHIAgentRequest(
            nhi=nhi,
            goal="CI 자격 증명의 위험을 분석하고 필요한 추가 검사를 수행한다.",
            allow_secret_scan=allow_scan,
            allow_policy_evaluation=True,
            scan_repository_limit=1,
        )
    )

    log()
    log(f"  최종 상태        : {state.status.value} (재계획 {state.replan_count}회)")
    log("  실행 계획        :")
    for action in state.plan:
        mark = "완료" if action.completed else ("실패" if action.failed else "대기")
        log(f"    {action.step}. {action.action_type.value:<18} [{mark}] "
            f"({action.created_by.value}) {action.reason[:60]}")

    if state.analysis is not None:
        print_analysis(state.analysis, index=1)

    if state.secret_scan_result is not None:
        scan = state.secret_scan_result
        log()
        if scan.get("scan_executed"):
            log(f"  Secret 스캔      : 검사 {scan['scanned_files']}개 파일, "
                f"탐지 {scan['finding_count']}건")
            for entry in scan["repositories_scanned"]:
                log(f"    {entry['repository']}: {entry['finding_count']}건 "
                    f"{entry.get('nhi_analysis') or ''}")
        else:
            log(f"  Secret 스캔      : 실행하지 않음 — {scan['reason']}")

    if state.policy_evaluation_result is not None:
        policy = state.policy_evaluation_result
        log()
        log(f"  정책 평가        : {policy.get('outcome')} "
            f"(위반 {policy.get('violation_count')}건, "
            f"평가 정책 {len(policy.get('evaluated_policies', []))}종)")

    return state.analysis


def parse_permissions(raw: str) -> Dict[str, str]:
    """`contents:write,actions:read` → {"contents": "write", "actions": "read"}."""
    permissions: Dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        resource, _, level = item.partition(":")
        permissions[resource.strip()] = (level or "read").strip()
    return permissions


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo", action="append", default=None, help="분석할 owner/repo (여러 번 지정 가능)"
    )
    parser.add_argument("--max-files", type=int, default=12, help="저장소별 최대 검사 파일 수")
    parser.add_argument(
        "--verify-credentials",
        action="store_true",
        help="탐지된 토큰을 외부 API 로 재검증한다 (읽기 전용)",
    )
    parser.add_argument(
        "--analyze-own-token",
        action="store_true",
        help="설정된 GITHUB_TOKEN 자체를 NHI 로 분석한다",
    )
    parser.add_argument(
        "--run-agent",
        action="store_true",
        help="첫 저장소를 대상으로 Agent 실행 계층까지 돌린다",
    )
    parser.add_argument(
        "--assume-permissions",
        default="contents:write,actions:write,administration:write",
        help="Agent 실행 시 NHI 에 가정할 GitHub 권한 (예: contents:write,actions:read)",
    )
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):  # Windows 콘솔 한글 출력
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    repositories = args.repo or ["octocat/Hello-World"]
    token = get_settings().github.token
    log(f"인증 상태: {'GITHUB_TOKEN 사용' if token else '비인증 (공개 저장소 / 시간당 60회 제한)'}")

    pipeline = NHIAnalysisPipeline()
    reports: List[NHIAnalysisReport] = []
    extra_analyses: List[NHIAnalysis] = []

    for full_name in repositories:
        try:
            report = analyze_repository(
                full_name,
                max_files=args.max_files,
                verify=args.verify_credentials,
                pipeline=pipeline,
            )
        except ConnectorError as exc:
            log(f"\n[{full_name}] GitHub 연동 실패: {exc.message} (status={exc.status_code})")
            continue
        if report is not None:
            reports.append(report)

    if args.analyze_own_token:
        if not token:
            log("\nGITHUB_TOKEN 이 없어 토큰 자체 분석은 건너뛴다.")
        else:
            try:
                analyze_own_token(pipeline)
            except ConnectorError as exc:
                log(f"\n토큰 분석 실패: {exc.message}")

    if args.run_agent:
        try:
            analysis = run_agent_on_repository(
                repositories[0],
                assumed_permissions=parse_permissions(args.assume_permissions),
                allow_scan=bool(token),
            )
        except ConnectorError as exc:
            log(f"\nAgent 실행 실패: {exc.message}")
        else:
            if analysis is not None:
                extra_analyses.append(analysis)

    section("실행 요약")
    analyses = [a for report in reports for a in report.analyses] + extra_analyses
    log(f"  분석된 NHI       : {len(analyses)}건")
    if analyses:
        worst = max(analyses, key=lambda a: a.risk.score)
        log(f"  최고 위험        : {worst.profile.nhi_name} "
            f"{worst.risk.score}점 ({worst.risk.level.value}) → "
            f"{worst.recommended_action.value}")
        log(f"  영향 범위 합산   : {NHIAnalysisPipeline.blast_radius_summary(analyses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
