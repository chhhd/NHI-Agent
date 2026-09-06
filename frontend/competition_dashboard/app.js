/* 공모전 시연 화면 전용 표현 계층. 데이터 수집과 조치 API는 운영 Dashboard와 공유한다. */

const competitionStatusLabels = {
  NEW: "신규",
  TRIAGED: "분류 완료",
  ASSIGNED: "담당 지정",
  REMEDIATION_IN_PROGRESS: "조치 진행 중",
  CREDENTIAL_REVOKED: "Credential 폐기",
  RESCAN_PENDING: "재검사 대기",
  RESOLVED: "조치 완료",
  REOPENED: "재검토",
  RECURRENCE: "재발",
  FALSE_POSITIVE: "오탐",
  EXCEPTION: "예외 승인",
  NEEDS_REVIEW: "검토 필요",
  SLA_OVERDUE: "SLA 초과",
  ACCEPTED_RISK: "위험 수용",
  PROPOSED: "조치 제안",
  PENDING_APPROVAL: "승인 대기",
  APPROVED: "승인 완료",
  EXECUTING: "조치 실행 중",
  SUCCEEDED: "조치 성공",
  FAILED: "조치 실패",
  VERIFYING: "결과 확인 중",
  VERIFIED: "검증 완료",
  CANCELLED: "조치 취소",
};

const competitionViewTitles = {
  overview: "보안 운영 현황",
  findings: "위험 탐지 및 조치",
  "finding-detail": "Decision Flow",
  reviews: "보안 조치 승인 대기열",
  audit: "시스템 감사 이력",
};

const competitionActionLabels = {
  TOKEN_ROTATION: "Credential 교체",
  SCOPE_REDUCTION: "권한 범위 축소",
  OWNER_ASSIGNMENT: "Owner 지정",
  TOKEN_REVOCATION: "Credential 폐기",
  TOKEN_SEPARATION: "공유 Credential 분리",
  REQUEST_REAPPROVAL: "권한 재승인 요청",
};

function competitionActionLabel(actionType) {
  return competitionActionLabels[actionType] || String(actionType || "조치 미확인");
}

let competitionQuickFilter = "ALL";
let competitionFocusedFindingId = null;

function competitionRiskLevel(finding) {
  return finding.risk_level || finding.severity?.toUpperCase() || "UNKNOWN";
}

function competitionSortedFindings(items) {
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  return [...items].sort((left, right) => {
    const levelDelta = (rank[competitionRiskLevel(right)] || 0)
      - (rank[competitionRiskLevel(left)] || 0);
    if (levelDelta) return levelDelta;
    return Number(right.risk_score || 0) - Number(left.risk_score || 0);
  });
}

function competitionStatusLabel(status) {
  return competitionStatusLabels[status] || String(status || "미확인");
}

function competitionDate(value) {
  if (!value) return "기한 미설정";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "시간 미확인";
  return new Intl.DateTimeFormat("ko-KR", {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

function competitionIsOverdue(finding) {
  const closed = new Set(["RESOLVED", "FALSE_POSITIVE", "EXCEPTION", "ACCEPTED_RISK"]);
  if (closed.has(finding.status)) return false;
  return finding.status === "SLA_OVERDUE"
    || Boolean(finding.sla_due_at && new Date(finding.sla_due_at).getTime() < Date.now());
}

function competitionStatusBadge(status) {
  return `<span class="badge status-label ${escapeHtml(status || "")}">${escapeHtml(competitionStatusLabel(status))}</span>`;
}

function competitionScore(finding) {
  const raw = finding.risk_score;
  const score = raw === null || raw === undefined ? null : Math.max(0, Math.min(Number(raw), 100));
  const width = score === null || Number.isNaN(score) ? 0 : score;
  const value = score === null || Number.isNaN(score) ? "—" : Math.round(score);
  const level = competitionRiskLevel(finding);
  return `<div class="score-cell"><span class="score-number">${value}<small> / 100</small></span><span class="score-track" aria-hidden="true"><i class="${escapeHtml(level)}" style="width:${width}%"></i></span></div>`;
}

function competitionSla(finding) {
  const overdue = competitionIsOverdue(finding);
  return `<div class="sla-cell ${overdue ? "sla-overdue" : ""}"><span class="sla-date">${escapeHtml(competitionDate(finding.sla_due_at))}</span>${overdue ? '<span class="overdue-label">기한 초과</span>' : ""}</div>`;
}

findingRows = function competitionFindingRows(items, interactive = false) {
  if (!items.length) return emptyRow(7, "현재 조건에 해당하는 Finding이 없습니다.");
  const sorted = competitionSortedFindings(items);
  const firstCritical = sorted.findIndex((finding) => competitionRiskLevel(finding) === "CRITICAL");
  return sorted.map((finding, index) => {
    const level = competitionRiskLevel(finding);
    const rowClasses = [
      index === firstCritical && level === "CRITICAL" ? "priority-critical" : "",
      finding.finding_id === competitionFocusedFindingId ? "focused-row" : "",
    ].filter(Boolean).join(" ");
    const statusControl = interactive
      ? `<select class="status-select" aria-label="${escapeHtml(finding.secret_type)} 조치 상태" onclick="event.stopPropagation()" onkeydown="event.stopPropagation()" onchange="updateFindingStatus('${finding.finding_id}', this.value, '${finding.status}')">${findingStatuses.map((status) => `<option value="${status}" ${status === finding.status ? "selected" : ""}>${escapeHtml(competitionStatusLabel(status))}</option>`).join("")}</select>`
      : competitionStatusBadge(finding.status);
    return `
      <tr class="${rowClasses} finding-row" tabindex="0" title="${escapeHtml(finding.secret_type)} 상세 분석 열기" onclick="openCompetitionFinding('${finding.finding_id}')" onkeydown="if(event.key === 'Enter' || event.key === ' '){event.preventDefault();openCompetitionFinding('${finding.finding_id}')} ">
        <td><span class="badge risk-badge ${escapeHtml(level)}">${escapeHtml(level)}</span></td>
        <td><button class="secret-link" title="${escapeHtml(finding.secret_type)}" onclick="event.stopPropagation();openCompetitionFinding('${finding.finding_id}')">${escapeHtml(finding.secret_type)}</button><span class="sub secret-meta" title="${escapeHtml(finding.provider)} · ${escapeHtml(finding.masked_value)}">${escapeHtml(finding.provider)} · ${escapeHtml(finding.masked_value)}</span></td>
        <td><span class="primary" title="${escapeHtml(finding.repository)}">${escapeHtml(finding.repository)}</span><span class="sub" title="${escapeHtml(finding.file_path)}:${finding.line_number}">${escapeHtml(finding.file_path)}:${finding.line_number}</span></td>
        <td><span class="primary">${escapeHtml(finding.nhi_name || "NHI 미식별")}</span><span class="sub">${escapeHtml(finding.owner || "소유자 미지정")}</span></td>
        <td>${competitionScore(finding)}</td>
        <td>${statusControl}</td>
        <td>${competitionSla(finding)}</td>
      </tr>`;
  }).join("");
};

function competitionAnalysisFor(finding) {
  return state.analyses.find((analysis) =>
    analysis.fingerprint === finding.fingerprint
    && (!analysis.repository || analysis.repository === finding.repository));
}

async function ensureCompetitionAnalysis(finding = null, analysisId = null) {
  let matched = analysisId
    ? state.analyses.find((analysis) => analysis.analysis_id === analysisId)
    : (finding ? competitionAnalysisFor(finding) : null);
  if (matched) return matched;
  try {
    const response = await api("/analyses?limit=500");
    const merged = new Map(state.analyses.map((analysis) => [analysis.analysis_id, analysis]));
    (response.analyses || []).forEach((analysis) => merged.set(analysis.analysis_id, analysis));
    state.analyses = [...merged.values()];
    matched = analysisId
      ? state.analyses.find((analysis) => analysis.analysis_id === analysisId)
      : (finding ? competitionAnalysisFor(finding) : null);
  } catch (error) {
    showError(`상세 분석 근거를 불러오지 못했습니다: ${error.message}`);
  }
  return matched || null;
}

function competitionNhiFor(finding, analysis = {}) {
  const nhiId = finding.nhi_id || analysis.discovery?.nhi_id;
  return state.nhi.find((item) => item.nhi_id === nhiId)
    || state.nhi.find((item) => item.nhi_name === finding.nhi_name)
    || analysis.discovery
    || {};
}

function competitionActionFor(finding, analysis = {}) {
  return state.actions.find((action) => action.analysis_id === analysis.analysis_id)
    || state.actions.find((action) => action.credential_fingerprint === finding.fingerprint)
    || null;
}

function competitionAuditFor(finding, analysis = {}, action = null) {
  const needles = [
    finding.finding_id, finding.fingerprint, finding.repository, finding.nhi_name,
    analysis.analysis_id, action?.action_id,
  ].filter(Boolean).map((item) => String(item).toLowerCase());
  const related = state.audit.filter((event) => {
    const searchable = [event.target, event.actor, event.event_type, JSON.stringify(event.detail || {})]
      .filter(Boolean).join(" ").toLowerCase();
    const sameDemoWorkspace = finding.repository?.startsWith("nhi-sentinel-demo/")
      && event.detail?.demo_workspace === "nhi-sentinel-demo-v1";
    return sameDemoWorkspace || needles.some((needle) => searchable.includes(needle));
  });
  return related.slice(0, 3);
}

function competitionList(items, emptyText) {
  return items.length
    ? `<div class="journey-list">${items.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>`
    : `<span class="journey-empty">${escapeHtml(emptyText)}</span>`;
}

function competitionFacts(items) {
  return `<dl class="journey-facts">${items.map(([label, value]) => `
    <div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value ?? "미확인")}</dd></div>`).join("")}</dl>`;
}

function competitionJourneyCard({ index, key, title, subtitle, tone = "neutral", status, body, action = "" }) {
  return `<article id="journey-${key}" class="journey-card ${escapeHtml(tone)}">
    <header><span class="journey-index">${String(index).padStart(2, "0")}</span><div><h3>${escapeHtml(title)}</h3><p>${escapeHtml(subtitle)}</p></div><span class="journey-state ${escapeHtml(tone)}">${escapeHtml(status)}</span></header>
    <details class="journey-details"><summary>Evidence 펼치기</summary><div class="journey-card-body">${body}</div></details>${action ? `<footer>${action}</footer>` : ""}
  </article>`;
}

function renderSelectedNhiSummary(finding, analysis, nhi) {
  const container = document.querySelector("#selected-nhi-summary");
  const permissions = analysis.permissions || nhi.permissions || [];
  const usage = analysis.usage_analysis || {};
  container.innerHTML = `<article class="selected-nhi-card panel">
    <div class="selected-nhi-identity"><span>SELECTED IDENTITY</span><strong>${escapeHtml(finding.nhi_name || nhi.nhi_name || "NHI 미식별")}</strong><small>${escapeHtml(nhi.provider || finding.provider)} · ${escapeHtml(nhi.nhi_type || analysis.nhi_type || "UNKNOWN")}</small></div>
    ${competitionFacts([
      ["Owner", finding.owner || nhi.owner || "소유자 미지정"],
      ["Project", finding.repository || analysis.repository || "미확인"],
      ["Permissions", permissions.join(", ") || "미확인"],
      ["Risk", `${finding.risk_score ?? analysis.risk_score ?? "—"} / 100`],
      ["Last usage", usage.last_used_at ? competitionDate(usage.last_used_at) : "미확인"],
      ["Credential", competitionStatusLabel(finding.status)],
      ["Environment", nhi.environment || analysis.environment || "미확인"],
      ["Linked AI Agent", nhi.linked_ai_agent || analysis.discovery?.linked_ai_agent || "연결 정보 없음"],
    ])}
  </article>`;
}

function renderFindingDrilldown({ refreshDecision = true } = {}) {
  let finding = state.findings.find((item) => item.finding_id === competitionFocusedFindingId);
  if (!finding) finding = competitionSortedFindings(state.findings)[0];
  if (!finding) return;
  competitionFocusedFindingId = finding.finding_id;

  const analysis = competitionAnalysisFor(finding) || {};
  const nhi = competitionNhiFor(finding, analysis);
  const permission = analysis.permission_detail || {};
  const usage = analysis.usage_analysis || {};
  const events = analysis.security_events || [];
  const scenarios = analysis.scenario_matches || [];
  const blast = analysis.blast_radius || nhi.blast_radius || {};
  const action = competitionActionFor(finding, analysis);
  const auditEvents = competitionAuditFor(finding, analysis, action);
  const permissions = analysis.permissions || permission.permissions || nhi.permissions || [];
  const rawScopes = permission.raw_scopes || nhi.raw_scopes || [];
  const riskReasons = analysis.risk_reasons || analysis.risk_detail?.reasons || [];
  const level = competitionRiskLevel(finding);
  const reviewPending = action?.status === "PENDING_APPROVAL";

  document.querySelector("#finding-detail-title").textContent = finding.secret_type;
  document.querySelector("#finding-detail-subtitle").textContent = `${finding.nhi_name || "NHI 미식별"} · ${finding.provider} · ${finding.masked_value} · ${finding.repository} · ${finding.file_path}:${finding.line_number}`;
  document.querySelector("#finding-detail-summary").innerHTML = `
    <span class="badge risk-badge ${escapeHtml(level)}">${escapeHtml(level)}</span>
    <span class="detail-score"><b>${finding.risk_score ?? "—"}</b> / 100</span>
    ${competitionStatusBadge(finding.status)}`;

  const approvedPermissions = usage.declared_permissions || permissions;
  const observedPermissions = usage.observed_permissions || [];
  const observedActions = usage.observed_actions || [];
  const unexpectedPermissions = usage.unexpected_permissions || [];
  const comparisonComplete = Boolean(usage.permission_comparison_complete && usage.data_complete);
  const comparisonTone = !comparisonComplete ? "warning" : (unexpectedPermissions.length ? "critical" : "good");
  const comparisonResult = !comparisonComplete
    ? "판정 보류 · Usage telemetry가 불완전합니다."
    : unexpectedPermissions.length
      ? `승인 범위 초과 · ${unexpectedPermissions.join(", ")} 권한이 관측되었습니다.`
      : "승인 범위 내 사용 · 노출 위치, 권한 강도, 소유자 등 다른 위험 근거를 함께 평가합니다.";
  document.querySelector("#permission-usage-comparison").innerHTML = `
    <article class="comparison-card panel ${comparisonTone}">
      <header><div><span>PERMISSION vs USAGE</span><strong>승인된 권한과 실제 행동 비교</strong></div><b class="comparison-result ${comparisonTone}">${escapeHtml(comparisonResult)}</b></header>
      <div class="comparison-grid">
        <div><span>APPROVED PERMISSION</span><strong>${escapeHtml(approvedPermissions.join(", ") || "미확인")}</strong><small>${escapeHtml(rawScopes.join(", ") || "원본 Scope 미수집")}</small></div>
        <i aria-hidden="true">→</i>
        <div><span>OBSERVED USAGE</span><strong>${escapeHtml(observedPermissions.join(", ") || "미관측")}</strong><small>${escapeHtml(observedActions.join(", ") || "관측 Action 없음")}</small></div>
      </div>
    </article>`;

  const affectedRepositories = new Set([finding.repository, ...(blast.affected_projects || [])].filter(Boolean));
  document.querySelector("#impact-summary").innerHTML = [
    ["Affected identities", finding.nhi_name || nhi.nhi_name ? 1 : 0],
    ["Repositories", affectedRepositories.size],
    ["Services", (blast.connected_services || []).length],
    ["Unknown owners", finding.owner || nhi.owner ? 0 : 1],
  ].map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`).join("");

  renderSelectedNhiSummary(finding, analysis, nhi);
  if (analysis.analysis_id) state.selectedAnalysisId = analysis.analysis_id;
  if (refreshDecision) renderDecisionIntelligence();

  const stageDefinitions = [
    ["identity", "Identity"], ["permission", "Permission"], ["usage", "Usage"],
    ["event", "Event"], ["scenario", "Scenario"], ["decision", "Decision"],
    ["relationship", "Relationship impact"], ["review", "Human Review"], ["audit", "Audit"],
  ];
  document.querySelector("#finding-journey-steps").innerHTML = stageDefinitions.map(([key, label], index) => `
    <button data-journey-target="${key}"><span>${String(index + 1).padStart(2, "0")}</span><b>${escapeHtml(label)}</b></button>${index < stageDefinitions.length - 1 ? '<i aria-hidden="true">→</i>' : ""}`
  ).join("");

  const eventBody = events.length
    ? `<div class="journey-records">${events.slice(0, 4).map((event) => `<div><span>${escapeHtml(event.severity || "UNKNOWN")}</span><strong>${escapeHtml(event.title || event.event_type)}</strong><small>${escapeHtml(event.detail || "근거 설명 없음")}</small></div>`).join("")}</div>`
    : competitionList([], usage.data_complete ? "관측 범위에서 생성된 보안 이벤트가 없습니다." : "Usage telemetry가 불완전해 이벤트 부재를 안전으로 판정하지 않습니다.");
  const scenarioBody = scenarios.length
    ? `<div class="journey-records">${scenarios.slice(0, 4).map((scenario) => `<div><span>${escapeHtml(scenario.scenario_id || "SCENARIO")}</span><strong>${escapeHtml(scenario.name || "Matched scenario")}</strong><small>${escapeHtml(scenario.reason || "판정 이유 없음")}</small></div>`).join("")}</div>`
    : competitionList([], "현재 근거와 일치하는 위험 시나리오가 없습니다.");
  const relationshipResources = blast.resource_samples || [];
  const auditBody = auditEvents.length
    ? `<div class="journey-records audit-records">${auditEvents.map((event) => `<div><span>${escapeHtml(competitionDate(event.occurred_at))}</span><strong>${escapeHtml(event.event_type)}</strong><small>${escapeHtml(event.actor || "system")} · ${escapeHtml(event.target || "대상 미확인")}</small></div>`).join("")}</div>`
    : competitionList([], "아직 연결된 감사 이벤트가 없습니다.");

  const cards = [
    competitionJourneyCard({
      index: 1, key: "identity", title: "Identity", subtitle: "이 Credential을 사용하는 주체는 누구인가",
      tone: finding.owner || nhi.owner ? "good" : "critical", status: finding.owner || nhi.owner ? "식별 완료" : "Owner 필요",
      body: competitionFacts([
        ["NHI", finding.nhi_name || nhi.nhi_name || "미식별"],
        ["Type", nhi.nhi_type || analysis.nhi_type || "UNKNOWN"],
        ["Owner", finding.owner || nhi.owner || "소유자 미지정"],
        ["AI Agent", nhi.linked_ai_agent || analysis.discovery?.linked_ai_agent || "연결 정보 없음"],
      ]),
      action: '<button class="text-button" data-open-detail-tab="evidence">NHI 상세 보기 →</button>',
    }),
    competitionJourneyCard({
      index: 2, key: "permission", title: "Permission", subtitle: "부여된 Scope를 공통 권한으로 변환",
      tone: permissions.includes("ADMIN") || permissions.includes("DELETE") ? "critical" : "warning",
      status: permission.assumed ? "추정 권한" : "수집 권한",
      body: `${competitionFacts([["Highest", permission.highest_permission || permissions.at(-1) || "미확인"], ["Baseline", usage.permission_baseline_source || "미확인"]])}${competitionList(permissions, "권한 정보 미수집")}${competitionList(rawScopes, "원본 Scope 미수집")}`,
    }),
    competitionJourneyCard({
      index: 3, key: "usage", title: "Usage", subtitle: "승인 권한과 실제 사용 행위를 비교",
      tone: usage.data_complete ? "good" : "warning", status: usage.data_complete ? "관측 완료" : "Telemetry 불완전",
      body: `${competitionFacts([["Activity", usage.activity_status || "unknown"], ["Last used", usage.last_used_at ? competitionDate(usage.last_used_at) : "미확인"], ["Observed", `${(usage.observed_permissions || []).length} permissions`], ["Unused", `${(usage.unused_permissions || []).length} permissions`]])}${competitionList(usage.observed_actions || [], "관측된 Action 없음")}`,
    }),
    competitionJourneyCard({
      index: 4, key: "event", title: "Event", subtitle: "관측 사실과 통제 공백을 보안 이벤트로 추출",
      tone: events.some((event) => event.severity === "CRITICAL") ? "critical" : (events.length ? "warning" : "neutral"), status: `${events.length} events`, body: eventBody,
    }),
    competitionJourneyCard({
      index: 5, key: "scenario", title: "Scenario", subtitle: "이벤트 조합을 실제 공격·오남용 시나리오에 매핑",
      tone: scenarios.length ? "critical" : "neutral", status: `${scenarios.length} matches`, body: scenarioBody,
    }),
    competitionJourneyCard({
      index: 6, key: "decision", title: "Decision", subtitle: "Risk, Policy, Recommendation을 하나의 판단으로 결합",
      tone: ["CRITICAL", "HIGH"].includes(level) ? "critical" : "warning", status: `${level} · ${finding.risk_score ?? "—"}/100`,
      body: `${competitionFacts([["Policy", analysis.policy?.outcome || "미평가"], ["Recommended action", analysis.recommended_action || "MONITOR"]])}${competitionList(riskReasons, "저장된 위험 이유 없음")}`,
      action: '<button class="text-button" data-open-detail-tab="decision">전체 판단 근거 보기 →</button>',
    }),
    competitionJourneyCard({
      index: 7, key: "relationship", title: "Relationship impact", subtitle: "탈취·오남용 시 접근 가능한 서비스와 리소스",
      tone: blast.sensitive_data_access || blast.cross_project_impact ? "critical" : "warning", status: `Impact ${blast.impact_score ?? "—"}/100`,
      body: `${competitionFacts([["Services", (blast.connected_services || []).join(", ") || "미확인"], ["Resources", blast.accessible_resources ?? "미확인"], ["Write / Delete", `${blast.can_write ? "가능" : "불가"} / ${blast.can_delete ? "가능" : "불가"}`], ["External transfer", blast.external_transfer_possible ? "가능" : "미확인 또는 불가"]])}${competitionList(relationshipResources, "Resource sample 미수집")}`,
      action: '<button class="text-button" data-open-detail-tab="relationship">관계 그래프 보기 →</button>',
    }),
    competitionJourneyCard({
      index: 8, key: "review", title: "Human Review", subtitle: "고위험 자동 조치 전에 사람이 근거를 검토",
      tone: reviewPending ? "warning" : (action ? "good" : "neutral"), status: action ? competitionStatusLabel(action.status) : "Action 미생성",
      body: action ? competitionFacts([["Action", competitionActionLabel(action.action_type)], ["Target", action.target], ["Status", competitionStatusLabel(action.status)], ["Requires approval", action.requires_approval ? "예" : "아니오"]]) : '<span class="journey-empty">연결된 조치 요청이 없습니다.</span>',
      action: '<button class="text-button" data-primary-view="reviews">Review에서 검토 →</button>',
    }),
    competitionJourneyCard({
      index: 9, key: "audit", title: "Audit", subtitle: "수집·분석·승인·상태 변경을 증적화",
      tone: auditEvents.length ? "good" : "neutral", status: `${auditEvents.length} related logs`, body: auditBody,
      action: '<button class="text-button" data-primary-view="audit">전체 감사 이력 보기 →</button>',
    }),
  ];
  document.querySelector("#finding-journey").innerHTML = cards.join('<i class="journey-connector" aria-hidden="true">↓</i>');
}

renderGraph = function renderCompetitionGraph() {
  const fullGraph = state.graph || { nodes: [], edges: [] };
  const finding = state.findings.find((item) => item.finding_id === competitionFocusedFindingId);
  let nodes = fullGraph.nodes || [];
  let edges = fullGraph.edges || [];
  const startId = finding ? `credential:${finding.fingerprint}` : null;

  if (startId && nodes.some((node) => node.id === startId)) {
    const connected = new Set([startId]);
    let changed = true;
    while (changed) {
      changed = false;
      edges.forEach((edge) => {
        if (connected.has(edge.source) && !connected.has(edge.target)) {
          connected.add(edge.target); changed = true;
        }
        if (connected.has(edge.target) && !connected.has(edge.source)) {
          connected.add(edge.source); changed = true;
        }
      });
    }
    nodes = nodes.filter((node) => connected.has(node.id));
    edges = edges.filter((edge) => connected.has(edge.source) && connected.has(edge.target));
  }

  const graphTypes = ["AI_AGENT", "NHI", "CREDENTIAL", "PERMISSION", "SERVICE", "RESOURCE"];
  const stats = Object.fromEntries(graphTypes.map((type) => [type, nodes.filter((node) => node.type === type).length]));
  document.querySelector("#graph-stats").innerHTML = Object.entries(stats)
    .filter(([, count]) => count)
    .map(([type, count]) => `<span class="badge">${escapeHtml(type)} · ${count}</span>`).join("");
  const container = document.querySelector("#relationship-graph");
  if (!nodes.length) {
    container.innerHTML = '<div class="empty-state">선택한 Finding의 관계 경로 데이터가 없습니다.</div>';
    return;
  }
  const colors = {
    AI_AGENT: "#a58bff", NHI: "#68e0c1", CREDENTIAL: "#ff5d7a",
    PERMISSION: "#f5cc5f", SERVICE: "#4da3ff", RESOURCE: "#54d69d",
  };
  const positions = new Map();
  graphTypes.forEach((type, column) => {
    const typedNodes = nodes.filter((node) => node.type === type);
    typedNodes.forEach((node, index) => positions.set(node.id, {
      x: 85 + column * 175,
      y: 58 + (index + 1) * (390 / (typedNodes.length + 1)),
    }));
  });
  const edgeSvg = edges.map((edge) => {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    if (!source || !target) return "";
    const middle = (source.x + target.x) / 2;
    return `<path class="graph-edge selected-path" d="M${source.x},${source.y} C${middle},${source.y} ${middle},${target.y} ${target.x},${target.y}"><title>${escapeHtml(edge.type)}</title></path>`;
  }).join("");
  const nodeSvg = nodes.map((node) => {
    const point = positions.get(node.id);
    if (!point) return "";
    const label = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;
    const focusClass = node.id === startId ? " focus-node" : "";
    return `<g class="graph-node selected-node${focusClass}" transform="translate(${point.x},${point.y})"><circle r="18" fill="${colors[node.type] || "#8ca0b8"}"></circle><text y="34">${escapeHtml(label)}</text><text class="node-type" y="-28">${escapeHtml(node.type)}</text><title>${escapeHtml(node.label)}</title></g>`;
  }).join("");
  container.innerHTML = `<svg viewBox="0 0 980 480" role="img" aria-label="선택한 Finding의 관계 경로">${edgeSvg}${nodeSvg}</svg>`;
};

let competitionLastReviewResult = null;

renderReviews = function renderCompetitionReviews() {
  const pending = state.actions.filter((item) => item.status === "PENDING_APPROVAL");
  const resultPanel = document.querySelector("#review-result");
  if (competitionLastReviewResult) {
    const completed = ["SUCCEEDED", "VERIFIED"].includes(competitionLastReviewResult.status);
    resultPanel.hidden = false;
    resultPanel.innerHTML = `<i>✓</i><div><strong>${escapeHtml(competitionLastReviewResult.approved ? "조치 승인 완료" : "조치 거부 기록 완료")}</strong><p>${escapeHtml(completed ? "조치 실행과 검증이 완료되었습니다." : competitionLastReviewResult.approved ? "승인 기록이 저장되었습니다. 외부 Credential 조치는 아직 실행 전입니다." : "거부 사유와 상태 변경이 저장되었습니다.")}</p><small>${escapeHtml(competitionLastReviewResult.actionType)} · ${escapeHtml(competitionStatusLabel(competitionLastReviewResult.status))} · Audit event recorded</small></div><button class="text-button" onclick="setView('audit')">Audit 확인 →</button>`;
  } else {
    resultPanel.hidden = true;
  }

  document.querySelector("#review-list").innerHTML = pending.length
    ? pending.map((action) => {
      const finding = state.findings.find((item) => item.fingerprint === action.credential_fingerprint);
      const analysis = state.analyses.find((item) => item.analysis_id === action.analysis_id);
      const nhiName = finding?.nhi_name || analysis?.nhi_name || "NHI 미식별";
      const secretName = finding?.secret_type || analysis?.discovery?.secret_name || action.target;
      const riskScore = finding?.risk_score ?? analysis?.risk_score;
      const evidence = [
        analysis?.policy?.outcome ? `Policy ${analysis.policy.outcome}` : null,
        analysis?.security_events?.length ? `${analysis.security_events.length} security events` : null,
        analysis?.scenario_matches?.length ? `${analysis.scenario_matches.length} scenario matches` : null,
      ].filter(Boolean);
      return `<article class="review-card competition-review-card">
        <div class="review-main">
          <div class="review-title-row"><div>${badge(action.risk_level)}<span class="review-label">RECOMMENDED ACTION</span></div><strong title="${escapeHtml(action.action_type)}">${escapeHtml(competitionActionLabel(action.action_type))}</strong></div>
          <div class="review-subject"><strong>${escapeHtml(secretName)}</strong><span>${escapeHtml(nhiName)} · ${escapeHtml(action.provider)}</span></div>
          <p>${escapeHtml(action.rationale)}</p>
          <div class="review-evidence">${evidence.length ? evidence.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : '<span>상세 분석에서 Evidence 확인</span>'}</div>
          <div class="review-meta"><span>Target · ${escapeHtml(action.target)}</span><span>Risk · ${riskScore ?? "—"} / 100</span><span>Created · ${fmtDate(action.created_at)}</span></div>
        </div>
        <div class="review-actions">
          ${action.analysis_id ? `<button class="secondary-button" onclick="openAnalysis('${action.analysis_id}')">Evidence</button>` : ""}
          <button class="danger-button" onclick="decideReview('${action.action_id}', false)">Reject</button><button class="primary-button" onclick="decideReview('${action.action_id}', true)">Approve</button>
        </div>
      </article>`;
    }).join("")
    : '<div class="empty-state panel">현재 승인 대기 중인 조치가 없습니다.</div>';
};

decideReview = async function decideCompetitionReview(actionId, approve) {
  const action = state.actions.find((item) => item.action_id === actionId);
  const isDemo = Boolean(action?.demo_workspace);
  const key = isDemo ? "" : sessionStorage.getItem("nhiAdminKey") || prompt("관리자 API Key를 입력하세요.");
  if (!isDemo && !key) return;
  if (!isDemo) sessionStorage.setItem("nhiAdminKey", key);
  const reason = approve ? "Competition dashboard review approved" : prompt("거부 사유를 입력하세요.") || "Rejected";
  try {
    const prefix = isDemo ? "/demo/reviews" : "/reviews";
    const result = await api(`${prefix}/${actionId}/${approve ? "approve" : "reject"}`, {
      method: "POST",
      headers: isDemo ? {} : { "X-NHI-Admin-Key": key },
      body: JSON.stringify({ actor: "competition-dashboard-admin", reason }),
    });
    competitionLastReviewResult = {
      approved: approve,
      status: result.status,
      actionType: competitionActionLabel(result.action_type),
    };
    await loadDashboard();
    await loadCompetitionAnalysisCatalog();
    render();
    showSuccess(approve
      ? "조치 승인이 기록되었습니다. 실제 외부 조치 실행·검증은 다음 단계에서 수행됩니다."
      : "조치 거부와 사유가 감사 로그에 기록되었습니다.");
  } catch (error) {
    showError(error.message);
  }
};

renderAudit = function renderCompetitionAudit() {
  document.querySelector("#audit-list").innerHTML = state.audit.length
    ? state.audit.map((event) => {
      const occurredAt = new Date(event.occurred_at);
      const hasValidTime = !Number.isNaN(occurredAt.getTime());
      const detail = event.detail && typeof event.detail === "object" ? event.detail : {};
      const detailText = [
        detail.action_type ? competitionActionLabel(detail.action_type) : null,
        detail.status ? competitionStatusLabel(detail.status) : null,
        detail.reason || detail.repository || null,
      ].filter(Boolean).join(" · ");
      return `<article class="audit-event-row">
        <time title="${escapeHtml(event.occurred_at || "시간 미확인")}"><strong>${hasValidTime ? escapeHtml(new Intl.DateTimeFormat("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(occurredAt)) : "—"}</strong><span>${hasValidTime ? escapeHtml(new Intl.DateTimeFormat("ko-KR", { month: "2-digit", day: "2-digit" }).format(occurredAt)) : "시간 미확인"}</span></time>
        <i class="audit-node"></i>
        <div><strong title="${escapeHtml(event.event_type)}">${escapeHtml(event.event_type)}</strong><span title="${escapeHtml(event.target || "대상 미확인")}">대상 · ${escapeHtml(event.target || "대상 미확인")}${detailText ? ` · ${escapeHtml(detailText)}` : ""}</span></div>
        <span class="audit-actor" title="${escapeHtml(event.actor || "system")}">Actor · ${escapeHtml(event.actor || "system")}</span>
      </article>`;
    }).join("")
    : '<div class="empty-state">아직 기록된 Audit event가 없습니다.</div>';
};

function renderTopCriticalFinding() {
  const container = document.querySelector("#top-finding");
  const levelBadge = document.querySelector("#top-finding-level");
  const finding = competitionSortedFindings(state.findings)[0];
  if (!finding) {
    levelBadge.hidden = true;
    container.innerHTML = '<div class="empty-state">분석할 Finding이 없습니다.</div>';
    return;
  }

  const level = competitionRiskLevel(finding);
  const analysis = competitionAnalysisFor(finding) || {};
  const blast = analysis.blast_radius || {};
  const reasons = (analysis.risk_reasons || analysis.risk_detail?.reasons || []).slice(0, 3);
  if (!reasons.length) reasons.push(`${finding.repository}에서 ${finding.secret_type} 노출이 탐지되었습니다.`);
  const resourceNames = (blast.resource_samples || []).slice(0, 3);
  const serviceNames = blast.connected_services || [];
  const impactParts = [];
  if (serviceNames.length) impactParts.push(serviceNames.join(", "));
  if (blast.accessible_resources) impactParts.push(`접근 가능 리소스 ${blast.accessible_resources}개`);
  if (resourceNames.length) impactParts.push(resourceNames.join(", "));
  if (blast.cross_project_impact) impactParts.push("프로젝트 간 영향 가능");
  const affectedRepositories = (blast.affected_projects || []).length || (finding.repository ? 1 : 0);
  impactParts.unshift(`Repository ${affectedRepositories}개`);
  const impact = impactParts.join(" · ") || `${finding.repository} 및 연결된 리소스`;

  levelBadge.hidden = false;
  levelBadge.className = `badge risk-badge ${escapeHtml(level)}`;
  levelBadge.textContent = level;
  container.innerHTML = `
    <div class="top-finding-lead">
      <div class="top-secret"><span>${escapeHtml(finding.provider)} credential</span><strong>${escapeHtml(finding.secret_type)}</strong><small>${escapeHtml(finding.masked_value)}</small></div>
      <div class="top-score"><span>Risk score</span><strong>${finding.risk_score ?? "—"}</strong><small>/ 100</small></div>
    </div>
    <div class="top-finding-evidence">
      <div class="evidence-block"><span>Why flagged</span><ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul></div>
      <div class="evidence-block"><span>영향 범위</span><p>${escapeHtml(impact)}</p></div>
    </div>
    <div class="top-finding-footer"><span>NHI · <b>${escapeHtml(finding.nhi_name || "미식별")}</b> &nbsp; Project · <b>${escapeHtml(finding.repository)}</b></span><button class="primary-button" onclick="openCompetitionFinding('${finding.finding_id}')">Investigate →</button></div>`;
}

function renderProtectedScopeSummary() {
  const connectors = state.connectors || [];
  const connected = connectors.filter((connector) => connector.status === "CONNECTED");
  const providers = [...new Set(connected.map((connector) => connector.provider).filter(Boolean))];
  const providerLabel = {
    github: "GitHub", slack: "Slack", microsoft: "Microsoft 365",
    google_workspace: "Google Workspace",
  };
  document.querySelector("#protected-scope-summary").innerHTML = `
    <div class="scope-metrics">
      <div><strong>${state.projects.length}</strong><span>Projects</span></div>
      <div><strong>${state.nhi.length}</strong><span>NHI</span></div>
      <div><strong>${state.summary.credential_count || 0}</strong><span>Credentials</span></div>
      <div><strong>${connected.length}</strong><span>Connected sources</span></div>
    </div>
    <div class="connected-sources"><span>CONNECTED</span>${providers.length
      ? providers.map((provider) => `<b><i></i>${escapeHtml(providerLabel[provider] || provider)}</b>`).join("")
      : '<small>현재 연결 완료된 Source가 없습니다.</small>'}</div>`;
}

function renderReviewSummary() {
  const pending = state.actions.filter((action) => action.status === "PENDING_APPROVAL");
  const counts = pending.reduce((result, action) => {
    result[action.action_type] = (result[action.action_type] || 0) + 1;
    return result;
  }, {});
  const breakdown = Object.entries(counts).sort((left, right) => right[1] - left[1]);
  document.querySelector("#review-summary").innerHTML = `
    <div class="review-total"><span>PENDING ACTIONS</span><strong>${pending.length}</strong><small>실행 전 사람의 승인이 필요합니다.</small></div>
    <div class="review-breakdown">${breakdown.length
      ? breakdown.map(([type, count]) => `<div><span>${escapeHtml(competitionActionLabel(type))}</span><b>${count}</b></div>`).join("")
      : '<div class="empty-state">현재 승인 대기 중인 조치가 없습니다.</div>'}</div>`;
}

const competitionBaseRenderSummary = renderSummary;
renderSummary = function competitionRenderSummary() {
  competitionBaseRenderSummary();
  document.querySelector("#kpi-pending-reviews").textContent =
    state.actions.filter((action) => action.status === "PENDING_APPROVAL").length;
  renderTopCriticalFinding();
  renderProtectedScopeSummary();
  renderReviewSummary();
  const systemStatus = document.querySelector("#system-status");
  const connected = Boolean(Object.keys(state.summary || {}).length);
  systemStatus.classList.toggle("connected", connected);
  systemStatus.innerHTML = `<i></i> ${connected ? "API 연결됨" : "API 연결 확인 필요"}`;
};

const competitionBaseRenderProjects = renderProjects;
renderProjects = function competitionRenderProjects() {
  competitionBaseRenderProjects();
  document.querySelector("#overview-projects").innerHTML = projectRows(state.projects);
};

renderFindings = function competitionRenderFindings() {
  const risk = document.querySelector("#finding-risk-filter").value;
  const status = document.querySelector("#finding-status-filter").value;
  const term = document.querySelector("#finding-search").value.trim().toLowerCase();
  const filtered = state.findings.filter((item) => {
    const searchable = [
      item.secret_type, item.provider, item.masked_value, item.repository,
      item.file_path, item.nhi_name, item.owner,
    ].filter(Boolean).join(" ").toLowerCase();
    const quickMatch = competitionQuickFilter === "ALL"
      || (competitionQuickFilter === "CRITICAL" && competitionRiskLevel(item) === "CRITICAL")
      || (competitionQuickFilter === "HIGH" && competitionRiskLevel(item) === "HIGH")
      || (competitionQuickFilter === "NEEDS_REVIEW" && item.status === "NEEDS_REVIEW")
      || (competitionQuickFilter === "RESOLVED" && item.status === "RESOLVED");
    return quickMatch
      && (!risk || competitionRiskLevel(item) === risk)
      && (!status || item.status === status)
      && (!term || searchable.includes(term));
  });

  document.querySelector("#overview-findings").innerHTML = findingRows(competitionSortedFindings(state.findings).slice(0, 6));
  document.querySelector("#all-findings").innerHTML = findingRows(filtered, true);
  document.querySelector("#quick-critical-count").textContent = state.findings.filter((item) => competitionRiskLevel(item) === "CRITICAL").length;
  document.querySelector("#quick-high-count").textContent = state.findings.filter((item) => competitionRiskLevel(item) === "HIGH").length;
  document.querySelector("#quick-review-count").textContent = state.findings.filter((item) => item.status === "NEEDS_REVIEW").length;
  document.querySelector("#quick-resolved-count").textContent = state.findings.filter((item) => item.status === "RESOLVED").length;
};

function activateCompetitionQuickFilter(value) {
  competitionQuickFilter = value;
  competitionFocusedFindingId = null;
  document.querySelector("#finding-risk-filter").value = "";
  document.querySelector("#finding-status-filter").value = "";
  document.querySelector("#finding-search").value = "";
  document.querySelectorAll(".quick-filter").forEach((button) => {
    const active = button.dataset.quickFilter === value;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  renderFindings();
}

function activateCompetitionDetailTab(name) {
  document.querySelectorAll(".detail-tab").forEach((button) => {
    const active = button.dataset.detailTab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".drill-tab").forEach((panel) =>
    panel.classList.toggle("active", panel.dataset.drillTab === name));
  if (name === "decision") renderDecisionIntelligence();
  if (name === "relationship") renderGraph();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

window.openCompetitionFinding = async function openCompetitionFinding(findingId, detailTab = "summary") {
  const finding = state.findings.find((item) => item.finding_id === findingId)
    || competitionSortedFindings(state.findings)[0];
  if (!finding) return;
  competitionFocusedFindingId = finding.finding_id;
  const analysis = await ensureCompetitionAnalysis(finding);
  if (analysis?.analysis_id) state.selectedAnalysisId = analysis.analysis_id;
  renderFindingDrilldown();
  activateCompetitionDetailTab(detailTab);
  setView("finding-detail");
};

openAnalysis = async function openCompetitionAnalysis(analysisId) {
  const analysis = await ensureCompetitionAnalysis(null, analysisId);
  const finding = state.findings.find((item) =>
    item.fingerprint === analysis?.fingerprint
    && (!analysis?.repository || item.repository === analysis.repository));
  if (finding) competitionFocusedFindingId = finding.finding_id;
  state.selectedAnalysisId = analysisId;
  renderFindingDrilldown();
  activateCompetitionDetailTab("decision");
  setView("finding-detail");
};

const competitionBaseSetView = setView;
setView = function competitionSetView(name, updateHash = true) {
  competitionBaseSetView(name, updateHash);
  document.querySelector("#page-title").textContent = competitionViewTitles[name] || "NHI Sentinel";
  if (name === "finding-detail" && !competitionFocusedFindingId && state.findings.length) {
    competitionFocusedFindingId = competitionSortedFindings(state.findings)[0].finding_id;
    renderFindingDrilldown();
  }
};

const competitionBaseRender = render;
render = function competitionRender() {
  competitionBaseRender();
  const detailIsActive = document.querySelector('[data-view="finding-detail"]').classList.contains("active");
  if ((competitionFocusedFindingId || detailIsActive) && state.findings.length) {
    if (!competitionFocusedFindingId) {
      competitionFocusedFindingId = competitionSortedFindings(state.findings)[0].finding_id;
    }
    renderFindingDrilldown({ refreshDecision: false });
  }
};

document.querySelectorAll(".detail-tab").forEach((button) => {
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", String(button.classList.contains("active")));
  button.addEventListener("click", () => activateCompetitionDetailTab(button.dataset.detailTab));
});

document.querySelector("#finding-detail-back").addEventListener("click", () => setView("findings"));
document.querySelector("[data-decision-navigation]").addEventListener("click", () => {
  const finding = state.findings.find((item) => item.finding_id === competitionFocusedFindingId)
    || competitionSortedFindings(state.findings)[0];
  if (finding) openCompetitionFinding(finding.finding_id, "decision");
});
document.querySelector("[data-select-top-finding]").addEventListener("click", () => {
  const finding = competitionSortedFindings(state.findings)[0];
  if (finding) openCompetitionFinding(finding.finding_id);
});

document.querySelector("#finding-journey-steps").addEventListener("click", (event) => {
  const button = event.target.closest("[data-journey-target]");
  if (!button) return;
  document.querySelector(`#journey-${button.dataset.journeyTarget}`)?.scrollIntoView({ block: "start", behavior: "smooth" });
});

document.querySelector("#finding-journey").addEventListener("click", (event) => {
  const detailButton = event.target.closest("[data-open-detail-tab]");
  if (detailButton) {
    activateCompetitionDetailTab(detailButton.dataset.openDetailTab);
    return;
  }
  const primaryButton = event.target.closest("[data-primary-view]");
  if (primaryButton) setView(primaryButton.dataset.primaryView);
});

document.querySelectorAll("[data-secondary-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const target = button.dataset.secondaryTarget;
    if (target === "projects") {
      setView("overview");
      const details = document.querySelector(".scope-details");
      details.open = true;
      requestAnimationFrame(() => details.scrollIntoView({ block: "center", behavior: "smooth" }));
      return;
    }
    const finding = state.findings.find((item) => item.finding_id === competitionFocusedFindingId)
      || competitionSortedFindings(state.findings)[0];
    if (finding) openCompetitionFinding(finding.finding_id, target === "identity" ? "evidence" : "relationship");
  });
});

const competitionBaseDiscoverGitHubOrganization = discoverGitHubOrganization;
const competitionGitHubButton = document.querySelector("#github-discover-button");
const competitionGitHubButtonClone = competitionGitHubButton.cloneNode(true);
competitionGitHubButton.replaceWith(competitionGitHubButtonClone);
competitionGitHubButtonClone.addEventListener("click", async () => {
  await competitionBaseDiscoverGitHubOrganization();
  setView("finding-detail");
  activateCompetitionDetailTab("evidence");
});

document.querySelectorAll(".quick-filter").forEach((button) => {
  button.setAttribute("aria-pressed", String(button.classList.contains("active")));
  button.addEventListener("click", () => activateCompetitionQuickFilter(button.dataset.quickFilter));
});

document.querySelectorAll("#finding-status-filter option").forEach((option) => {
  if (option.value) option.textContent = competitionStatusLabel(option.value);
});

["#finding-risk-filter", "#finding-status-filter", "#finding-search"].forEach((selector) => {
  document.querySelector(selector).addEventListener(selector === "#finding-search" ? "input" : "change", () => {
    competitionQuickFilter = "ALL";
    competitionFocusedFindingId = null;
    document.querySelectorAll(".quick-filter").forEach((button) => {
      const active = button.dataset.quickFilter === "ALL";
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    renderFindings();
  });
});

async function loadCompetitionConnectors() {
  try {
    const response = await api("/connectors/status");
    state.connectors = response.connectors || [];
  } catch (_) {
    state.connectors = [];
  }
  renderProtectedScopeSummary();
}

async function loadCompetitionAnalysisCatalog() {
  try {
    const response = await api("/analyses?limit=500");
    const merged = new Map(state.analyses.map((analysis) => [analysis.analysis_id, analysis]));
    (response.analyses || []).forEach((analysis) => merged.set(analysis.analysis_id, analysis));
    state.analyses = [...merged.values()];
  } catch (error) {
    showError(`분석 근거를 모두 불러오지 못했습니다: ${error.message}`);
  }
}

const competitionBaseSeedDemoWorkspace = seedDemoWorkspace;
seedDemoWorkspace = async function competitionSeedDemoWorkspace() {
  await competitionBaseSeedDemoWorkspace();
  await Promise.all([loadCompetitionConnectors(), loadCompetitionAnalysisCatalog()]);
  render();
};

const competitionBaseResetDemoWorkspace = resetDemoWorkspace;
resetDemoWorkspace = async function competitionResetDemoWorkspace() {
  await competitionBaseResetDemoWorkspace();
  await Promise.all([loadCompetitionConnectors(), loadCompetitionAnalysisCatalog()]);
  render();
};

const competitionDemoWorkspaceButton = document.querySelector("#demo-workspace-button");
const competitionDemoWorkspaceButtonClone = competitionDemoWorkspaceButton.cloneNode(true);
competitionDemoWorkspaceButton.replaceWith(competitionDemoWorkspaceButtonClone);
competitionDemoWorkspaceButtonClone.addEventListener("click", seedDemoWorkspace);

const competitionDemoResetButton = document.querySelector("#demo-reset-button");
const competitionDemoResetButtonClone = competitionDemoResetButton.cloneNode(true);
competitionDemoResetButton.replaceWith(competitionDemoResetButtonClone);
competitionDemoResetButtonClone.addEventListener("click", resetDemoWorkspace);

const competitionRefreshButton = document.querySelector("#refresh-button");
const competitionRefreshButtonClone = competitionRefreshButton.cloneNode(true);
competitionRefreshButton.replaceWith(competitionRefreshButtonClone);
competitionRefreshButtonClone.addEventListener("click", async () => {
  competitionRefreshButtonClone.disabled = true;
  try {
    await loadDashboard();
    await Promise.all([loadCompetitionConnectors(), loadCompetitionAnalysisCatalog()]);
    render();
  } finally {
    competitionRefreshButtonClone.disabled = false;
  }
});

const competitionInitialView = window.location.hash.slice(1) || "overview";
document.querySelector("#page-title").textContent = competitionViewTitles[competitionInitialView] || competitionViewTitles.overview;
queueMicrotask(async () => {
  await loadDashboard();
  await Promise.all([loadCompetitionConnectors(), loadCompetitionAnalysisCatalog()]);
  render();
});
