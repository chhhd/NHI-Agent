const state = {
  summary: {},
  projects: [],
  findings: [],
  nhi: [],
  analyses: [],
  selectedAnalysisId: null,
  historyComparisons: {},
  actions: [],
  audit: [],
  graph: { nodes: [], edges: [], stats: {} },
};

const findingStatuses = [
  "NEW", "TRIAGED", "ASSIGNED", "REMEDIATION_IN_PROGRESS",
  "CREDENTIAL_REVOKED", "RESCAN_PENDING", "RESOLVED", "REOPENED",
  "RECURRENCE", "FALSE_POSITIVE", "EXCEPTION", "NEEDS_REVIEW",
  "SLA_OVERDUE", "ACCEPTED_RISK",
];

async function api(path, options = {}) {
  const { headers = {}, ...requestOptions } = options;
  const response = await fetch(path, {
    ...requestOptions,
    headers: { "Content-Type": "application/json", ...headers },
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { message = (await response.json()).detail || message; } catch (_) {}
    throw new Error(message);
  }
  return response.json();
}

const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;").replaceAll('"', "&quot;");

const fmtDate = (value) => value
  ? new Intl.DateTimeFormat("ko-KR", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date(value))
  : "Not scanned";

const badge = (value) => `<span class="badge ${escapeHtml(value || "")}">${escapeHtml(value || "UNKNOWN")}</span>`;
const emptyRow = (columns, text) => `<tr class="empty-row"><td colspan="${columns}">${text}</td></tr>`;

async function loadDashboard() {
  const banner = document.querySelector("#error-banner");
  banner.hidden = true;
  try {
    const [summary, projects, findings, nhi, analyses, actions, audit, graph] = await Promise.all([
      api("/dashboard/summary"),
      api("/projects"),
      api("/findings?limit=100"),
      api("/nhi?limit=100"),
      api("/analyses?limit=100"),
      api("/actions?limit=100"),
      api("/audit?limit=50"),
      api("/graph?limit=100"),
    ]);
    Object.assign(state, {
      summary,
      projects: projects.projects,
      findings: findings.findings,
      nhi: nhi.nhi,
      analyses: analyses.analyses,
      actions: actions.actions,
      audit: audit.events,
      graph,
    });
    render();
    document.querySelector("#last-updated").textContent =
      `UPDATED ${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" })}`;
  } catch (error) {
    banner.textContent = `Dashboard 데이터를 불러오지 못했습니다: ${error.message}`;
    banner.hidden = false;
  }
}

function render() {
  renderDemoState();
  renderSummary();
  renderProjects();
  renderFindings();
  renderNhi();
  renderGitHubRun();
  renderDecisionIntelligence();
  renderReviews();
  renderAudit();
  renderGraph();
  document.querySelector("#nav-finding-count").textContent =
    state.summary.critical_high_findings || 0;
  document.querySelector("#nav-review-count").textContent =
    state.actions.filter((item) => item.status === "PENDING_APPROVAL").length;
  document.querySelector("#nav-scenario-count").textContent =
    latestAnalyses().reduce(
      (sum, item) => sum + (item.scenario_matches || []).filter(
        (scenario) => isForcedScenario(scenario, item),
      ).length,
      0,
    );
}

function latestAnalyses() {
  const seen = new Set();
  return state.analyses.filter((analysis) => {
    const key = analysis.discovery?.nhi_id || analysis.fingerprint || analysis.analysis_id;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isForcedScenario(scenario, analysis = null) {
  if (typeof scenario.forced_critical === "boolean") return scenario.forced_critical;
  const forcedIds = new Set(
    (analysis?.risk_detail?.forced_rules || []).map((item) => item.rule_id),
  );
  return forcedIds.has(scenario.scenario_id);
}

function hasDemoWorkspace() {
  return state.projects.some((project) =>
    project.metadata?.demo_workspace === "nhi-sentinel-demo-v1");
}

function renderDemoState() {
  const active = hasDemoWorkspace();
  const button = document.querySelector("#demo-workspace-button");
  button.textContent = active ? "데모 데이터 새로 만들기" : "데모 데이터 생성";
  document.querySelector("#demo-notice").hidden = !active;
}

function renderSummary() {
  const s = state.summary;
  document.querySelector("#kpi-critical").textContent = s.critical_high_findings || 0;
  document.querySelector("#kpi-projects").textContent = s.project_count || 0;
  document.querySelector("#kpi-nhi").textContent = s.nhi_count || 0;
  document.querySelector("#kpi-ownerless").textContent = s.ownerless_nhi_count || 0;
  document.querySelector("#kpi-credentials").textContent = s.credential_count || 0;
  document.querySelector("#kpi-unrotated").textContent = s.long_unrotated_token_count || 0;

  const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const colors = {
    CRITICAL: "var(--critical)", HIGH: "var(--high)", MEDIUM: "var(--medium)",
    LOW: "var(--low)", UNKNOWN: "var(--line)",
  };
  const distribution = s.risk_distribution || {};
  const total = Object.values(distribution).reduce((sum, value) => sum + value, 0);
  document.querySelector("#risk-total").textContent = total;
  let cursor = 0;
  const segments = levels.map((level) => {
    const amount = total ? ((distribution[level] || 0) / total) * 100 : 0;
    const start = cursor; cursor += amount;
    return `${colors[level]} ${start}% ${cursor}%`;
  });
  document.querySelector("#risk-donut").style.background =
    total ? `conic-gradient(${segments.join(",")})` : "var(--line)";
  document.querySelector("#risk-legend").innerHTML = levels.slice(0, 4).map((level) => `
    <div class="legend-row"><i style="background:${colors[level]}"></i><span>${level}</span><b>${distribution[level] || 0}</b></div>
  `).join("");

  const trend = s.recent_finding_trend || [];
  const max = Math.max(...trend.map((item) => item.count), 1);
  document.querySelector("#trend-chart").innerHTML = trend.length
    ? trend.map((item) => `
        <div class="trend-column" title="${escapeHtml(item.date)} · ${item.count}">
          <div class="trend-bar" style="height:${Math.max(5, item.count / max * 100)}%"></div>
          <small>${escapeHtml(item.date.slice(5))}</small>
        </div>`).join("")
    : `<div class="empty-state">아직 추세를 계산할 Finding이 없습니다.</div>`;
}

function projectRows(items) {
  return items.length ? items.map((project) => `
    <tr>
      <td><span class="primary">${escapeHtml(project.name)}</span><span class="sub">${escapeHtml(project.repository)}</span></td>
      <td><span class="status-dot ${project.connector_status === "CONNECTED" ? "good" : "warn"}"></span>${escapeHtml(project.connector_status)}</td>
      <td>${fmtDate(project.last_scan_at)}</td>
      <td>${project.policy_enabled ? badge("ENABLED") : badge("DISABLED")}</td>
      <td><span class="primary">${project.finding_count || 0}</span></td>
      <td>${project.metadata?.demo_workspace
        ? `<button class="text-button" onclick="seedDemoWorkspace()">Demo refresh →</button>`
        : `<button class="text-button" onclick="scanProject('${project.project_id}')">Scan →</button>`}</td>
    </tr>`).join("") : emptyRow(6, "등록된 Project가 없습니다.");
}

function renderProjects() {
  document.querySelector("#overview-projects").innerHTML = projectRows(state.projects.slice(0, 5));
  document.querySelector("#project-cards").innerHTML = state.projects.length
    ? state.projects.map((project) => `
      <article class="entity-card">
        <header><div><h3>${escapeHtml(project.name)}</h3><p>${escapeHtml(project.repository)}</p></div>${badge(project.status)}</header>
        <dl>
          <div><dt>Connector</dt><dd>${escapeHtml(project.connector_status)}</dd></div>
          <div><dt>Findings</dt><dd>${project.finding_count || 0}</dd></div>
          <div><dt>Last scan</dt><dd>${fmtDate(project.last_scan_at)}</dd></div>
          <div><dt>Policy</dt><dd>${project.policy_enabled ? "Enabled" : "Disabled"}</dd></div>
        </dl>
        <footer>${project.metadata?.demo_workspace
          ? `<button class="secondary-button" onclick="seedDemoWorkspace()">Refresh demo</button>`
          : `<button class="primary-button" onclick="scanProject('${project.project_id}')">Run scan</button>`}</footer>
      </article>`).join("")
    : `<div class="empty-state">Project를 등록하면 커버리지와 Scan 상태가 표시됩니다.</div>`;
}

function findingRows(items, interactive = false) {
  return items.length ? items.map((finding) => `
    <tr>
      <td>${badge(finding.risk_level || finding.severity?.toUpperCase())}</td>
      <td><span class="primary">${escapeHtml(finding.secret_type)}</span><span class="sub">${escapeHtml(finding.provider)} · ${escapeHtml(finding.masked_value)}</span></td>
      <td><span class="primary">${escapeHtml(finding.repository)}</span><span class="sub">${escapeHtml(finding.file_path)}:${finding.line_number}</span></td>
      <td><span class="primary">${escapeHtml(finding.nhi_name || "Unresolved NHI")}</span><span class="sub">${escapeHtml(finding.owner || "Owner not assigned")}</span></td>
      <td><span class="primary">${finding.risk_score ?? "—"}</span><span class="sub">/ 100</span></td>
      <td>${interactive
        ? `<select class="status-select" onchange="updateFindingStatus('${finding.finding_id}', this.value, '${finding.status}')">${findingStatuses.map((status) => `<option ${status === finding.status ? "selected" : ""}>${status}</option>`).join("")}</select>`
        : badge(finding.status)}</td>
      <td>${fmtDate(finding.sla_due_at)}</td>
    </tr>`).join("") : emptyRow(7, "현재 조건에 해당하는 Finding이 없습니다.");
}

function renderFindings() {
  const risk = document.querySelector("#finding-risk-filter").value;
  const status = document.querySelector("#finding-status-filter").value;
  const term = document.querySelector("#finding-search").value.trim().toLowerCase();
  const filtered = state.findings.filter((item) => {
    const searchable = [
      item.secret_type, item.provider, item.repository, item.file_path,
      item.nhi_name, item.owner,
    ].filter(Boolean).join(" ").toLowerCase();
    return (!risk || item.risk_level === risk)
      && (!status || item.status === status)
      && (!term || searchable.includes(term));
  });
  document.querySelector("#overview-findings").innerHTML = findingRows(state.findings.slice(0, 6));
  document.querySelector("#all-findings").innerHTML = findingRows(filtered, true);
}

function renderNhi() {
  const analyses = latestAnalyses();
  document.querySelector("#nhi-cards").innerHTML = state.nhi.length
    ? state.nhi.map((item) => {
      const analysis = analyses.find((candidate) =>
        candidate.discovery?.nhi_id === item.nhi_id);
      const eventCount = analysis?.security_events?.length || 0;
      const scenarioCount = analysis?.scenario_matches?.length || 0;
      return `
      <article class="entity-card">
        <header><div><h3>${escapeHtml(item.nhi_name)}</h3><p>${escapeHtml(item.provider)} · ${escapeHtml(item.nhi_type)}</p></div>${badge(item.identified ? "IDENTIFIED" : "UNKNOWN")}</header>
        <dl>
          <div><dt>Owner</dt><dd>${escapeHtml(item.owner || "Not assigned")}</dd></div>
          <div><dt>Confidence</dt><dd>${Math.round((item.confidence || 0) * 100)}%</dd></div>
          <div><dt>Risk</dt><dd>${badge(item.risk_level || "UNKNOWN")} ${item.risk_score ?? "—"}</dd></div>
          <div><dt>Environment</dt><dd>${escapeHtml(item.environment || "unknown")}</dd></div>
          <div><dt>Permissions</dt><dd>${escapeHtml((item.permissions || []).join(", ") || "Unknown")}</dd></div>
          <div><dt>AI Agent</dt><dd>${escapeHtml(item.linked_ai_agent || "—")}</dd></div>
        </dl>
        ${analysis ? `<div class="evidence-mini"><span>Usage ${analysis.usage_analysis?.data_complete ? "complete" : "unknown"}</span><span>Events ${eventCount}</span><span>Scenarios ${scenarioCount}</span></div>
        <footer><button class="text-button" onclick="openAnalysis('${analysis.analysis_id}')">판단 근거 보기 →</button></footer>` : ""}
      </article>`;
    }).join("")
    : `<div class="empty-state">분석된 NHI가 없습니다. Scan 또는 Inventory 분석을 실행하세요.</div>`;
}

function renderGitHubRun() {
  const event = state.audit.find((item) =>
    item.event_type === "GITHUB_INVENTORY_AGENT_COMPLETED"
    && item.detail?.kind === "github_inventory_agent_run");
  const empty = document.querySelector("#github-run-empty");
  const content = document.querySelector("#github-run-content");
  if (!event) {
    empty.hidden = false;
    content.hidden = true;
    document.querySelector("#github-run-status").innerHTML = badge("UNKNOWN");
    document.querySelector("#github-run-time").textContent = "실행 기록 없음";
    return;
  }

  const run = event.detail;
  const collection = run.collection || {};
  const repositories = run.repository_coverage || {};
  const scan = run.secret_scan || {};
  empty.hidden = true;
  content.hidden = false;
  document.querySelector("#github-run-status").innerHTML = badge(run.status || "UNKNOWN");
  document.querySelector("#github-run-time").textContent = `${run.organization} · ${fmtDate(event.occurred_at)} · replan ${run.replan_count || 0}`;

  const collectionTone = collection.inventory_complete ? "good" : "warn";
  const collectionValue = collection.total_count == null
    ? `${collection.count ?? 0} / total unknown`
    : `${collection.count ?? 0} / ${collection.total_count}`;
  const repositoryUnknown = (repositories.incomplete_count || 0) > 0;
  let scanLabel = "미계획";
  let scanDetail = "Agent가 Secret Scan을 계획하지 않음";
  let scanTone = "neutral";
  if (scan.scan_executed === false) {
    scanLabel = "미평가";
    scanDetail = scan.reason || "실행되지 않음";
    scanTone = "warn";
  } else if (scan.scan_executed === true && !scan.scan_complete) {
    scanLabel = "부분 검사";
    scanDetail = `${scan.scanned || 0} scanned · ${scan.failed || 0} failed · ${scan.skipped || 0} skipped`;
    scanTone = "warn";
  } else if (scan.scan_executed === true) {
    scanLabel = scan.finding_count === 0 ? "범위 내 0건" : `${scan.finding_count || 0} findings`;
    scanDetail = `${scan.scanned || 0} repositories · complete`;
    scanTone = "good";
  }
  const metrics = [
    ["Installation coverage", collectionValue, collection.inventory_complete ? "전체 목록 완료" : `불완전 · failure ${collection.failure_count || 0}`, collectionTone],
    ["Repository coverage", repositoryUnknown ? "UNKNOWN" : `${repositories.complete_count || 0} complete`, repositoryUnknown ? `${repositories.incomplete_count || 0} installation 범위 미수집` : "접근 저장소 범위 확인", repositoryUnknown ? "warn" : "good"],
    ["Secret scan coverage", scanLabel, scanDetail, scanTone],
  ];
  document.querySelector("#github-coverage-metrics").innerHTML = metrics.map((metric) => `
    <div class="collection-metric ${metric[3]}"><span>${escapeHtml(metric[0])}</span><strong>${escapeHtml(metric[1])}</strong><small>${escapeHtml(metric[2])}</small></div>
  `).join("");

  document.querySelector("#github-run-plan").innerHTML = (run.plan || []).map((step, index) => {
    const status = step.failed ? "failed" : step.completed ? "completed" : "pending";
    const symbol = step.failed ? "!" : step.completed ? "✓" : "·";
    return `<article class="run-step ${status}"><div class="run-step-index">${symbol}</div><div><span>${String(step.step).padStart(2, "0")} · ${escapeHtml(step.action_type)}</span><strong>${escapeHtml(step.created_by)}</strong><p>${escapeHtml(step.error_message || step.reason)}</p></div>${index < run.plan.length - 1 ? `<i>→</i>` : ""}</article>`;
  }).join("");
  document.querySelector("#github-run-notes").innerHTML = (run.replan_notes || []).length
    ? `<strong>Replanner observations</strong>${run.replan_notes.map((note) => `<p>${escapeHtml(note)}</p>`).join("")}`
    : `<p>추가 재계획 관측 메모가 없습니다.</p>`;
}

function renderDecisionIntelligence() {
  const analyses = latestAnalyses();
  const completeUsage = analyses.filter((item) => item.usage_analysis?.data_complete === true).length;
  const eventCount = analyses.reduce((sum, item) => sum + (item.security_events || []).length, 0);
  const criticalEvents = analyses.reduce(
    (sum, item) => sum + (item.security_events || []).filter((event) => event.severity === "CRITICAL").length,
    0,
  );
  const scenarioCount = analyses.reduce((sum, item) => sum + (item.scenario_matches || []).length, 0);
  const forcedCount = analyses.reduce(
    (sum, item) => sum + (item.scenario_matches || []).filter((scenario) => isForcedScenario(scenario, item)).length,
    0,
  );
  const reviews = state.actions.filter((item) => item.status === "PENDING_APPROVAL").length;

  document.querySelector("#intel-usage").textContent = `${completeUsage} / ${analyses.length}`;
  document.querySelector("#intel-usage-note").textContent = analyses.length
    ? `완전 ${completeUsage} · 미확인 ${analyses.length - completeUsage}`
    : "분석 없음";
  document.querySelector("#intel-events").textContent = eventCount;
  document.querySelector("#intel-event-note").textContent = `Critical ${criticalEvents} · 관측/파생 구분`;
  document.querySelector("#intel-scenarios").textContent = scenarioCount;
  document.querySelector("#intel-scenario-note").textContent = `강제 Critical ${forcedCount}건`;
  document.querySelector("#intel-reviews").textContent = reviews;

  const selector = document.querySelector("#analysis-selector");
  const empty = document.querySelector("#decision-empty");
  const content = document.querySelector("#decision-content");
  empty.hidden = analyses.length > 0;
  content.hidden = analyses.length === 0;
  selector.disabled = analyses.length === 0;
  if (!analyses.length) {
    selector.innerHTML = `<option>분석 없음</option>`;
    return;
  }

  if (!analyses.some((item) => item.analysis_id === state.selectedAnalysisId)) {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
    state.selectedAnalysisId = analyses.reduce((selected, item) =>
      (rank[item.risk_level] || 0) > (rank[selected.risk_level] || 0) ? item : selected,
    ).analysis_id;
  }
  selector.innerHTML = analyses.map((item) => `
    <option value="${escapeHtml(item.analysis_id)}">${escapeHtml(item.risk_level)} · ${escapeHtml(item.nhi_name || item.discovery?.nhi_name || "Unknown NHI")} · ${escapeHtml(item.repository || "inventory")}</option>
  `).join("");
  selector.value = state.selectedAnalysisId;

  const analysis = analyses.find((item) => item.analysis_id === state.selectedAnalysisId) || analyses[0];
  const usage = analysis.usage_analysis || {};
  const permission = analysis.permission_detail || {};
  const events = analysis.security_events || [];
  const scenarios = analysis.scenario_matches || [];
  const forcedScenarioIds = new Set(
    scenarios.filter((item) => isForcedScenario(item, analysis)).map((item) => item.scenario_id),
  );
  const forcedRuleIds = new Set(
    (analysis.risk_detail?.forced_rules || []).map((item) => item.rule_id),
  );
  const canonicalKnown = Boolean(analysis.risk_detail) && Array.isArray(analysis.scenario_matches);
  const canonicalAligned = forcedScenarioIds.size === forcedRuleIds.size
    && [...forcedScenarioIds].every((id) => forcedRuleIds.has(id));
  const permissionComplete = usage.permission_comparison_complete === true;
  const assumedPermission = permission.assumed === true
    || usage.permission_baseline_source === "assumed_scope";

  const coverage = [
    {
      tone: usage.data_complete === true ? "good" : "",
      title: usage.data_complete === true ? "Usage evidence complete" : "Usage evidence incomplete",
      detail: usage.data_complete === true
        ? `${Math.round((usage.confidence || 0) * 100)}% confidence · ${(usage.sources || []).join(", ") || "source recorded"}`
        : "이벤트 0건을 안전으로 해석하지 않습니다.",
    },
    {
      tone: permissionComplete && !assumedPermission ? "good" : "",
      title: permissionComplete ? "Permission comparison available" : "Permission comparison unknown",
      detail: assumedPermission
        ? "권한이 추정값이므로 승인 기준으로 사용하지 않습니다."
        : `Baseline · ${usage.permission_baseline_source || "unavailable"}`,
    },
    {
      tone: canonicalKnown && canonicalAligned ? "good" : "critical",
      title: canonicalKnown && canonicalAligned ? "Scenario ↔ policy IDs aligned" : "Canonical mapping needs review",
      detail: canonicalKnown
        ? `${forcedScenarioIds.size} forced scenario · ${forcedRuleIds.size} forced rule`
        : "이 분석에는 canonical scenario 데이터가 없습니다.",
    },
  ];
  document.querySelector("#decision-coverage").innerHTML = coverage.map((item) => `
    <div class="coverage-note ${item.tone}"><i></i><div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></div></div>
  `).join("");

  const observedPermissions = usage.observed_permissions || [];
  const criticalEventCount = events.filter((item) => item.severity === "CRITICAL").length;
  const forcedScenarioCount = scenarios.filter((item) => isForcedScenario(item, analysis)).length;
  const stages = [
    ["01 · IDENTITY", analysis.nhi_name || analysis.discovery?.nhi_name || "Unknown NHI", `${analysis.nhi_type || analysis.discovery?.nhi_type || "UNKNOWN"} · owner ${analysis.owner || "미지정"}`, analysis.source || "analysis"],
    ["02 · PERMISSION", (analysis.permissions || []).join(", ") || "Unknown", `승인 기준 ${usage.permission_baseline_source || "unavailable"}`, permissionComplete ? "비교 가능" : "비교 불가"],
    ["03 · USAGE", usage.data_complete ? `관측 ${observedPermissions.length}개 · 미사용 ${(usage.unused_permissions || []).length}개` : "Telemetry unknown", (usage.observed_actions || []).slice(0, 3).join(", ") || "관측 action 없음", usage.activity_status || (usage.data_complete ? `${Math.round((usage.confidence || 0) * 100)}% confidence` : "미수집 ≠ 안전")],
    ["04 · EVENT", `${events.length} security event`, `Critical ${criticalEventCount} · observed/derived/control gap`, events.length ? "근거 생성" : "현재 근거 없음"],
    ["05 · SCENARIO", `${scenarios.length} matched`, `강제 Critical ${forcedScenarioCount}`, scenarios.length ? "정책 ID 연결" : "현재 일치 없음"],
    ["06 · DECISION", `${analysis.risk_level || "UNKNOWN"} · ${analysis.risk_score ?? "—"}/100`, `Policy ${analysis.policy?.outcome || "unknown"}`, analysis.recommended_action || "MONITOR"],
  ];
  document.querySelector("#decision-flow").innerHTML = stages.map((stage, index) => `
    <div class="decision-stage"><span class="stage-index">${escapeHtml(stage[0])}</span><strong>${escapeHtml(stage[1])}</strong><small>${escapeHtml(stage[2])}</small><em>${escapeHtml(stage[3])}</em></div>
    ${index < stages.length - 1 ? `<i class="stage-arrow">→</i>` : ""}
  `).join("");
  document.querySelector("#decision-risk-badge").innerHTML = badge(analysis.risk_level || "UNKNOWN");

  document.querySelector("#event-count").textContent = `${events.length} EVENTS`;
  document.querySelector("#event-timeline").innerHTML = events.length
    ? events.map((event) => `
      <article class="event-item ${event.severity === "CRITICAL" ? "CRITICAL" : ""}">
        <header><strong>${escapeHtml(event.title || event.event_type)}</strong>${badge(event.severity)}</header>
        <p>${escapeHtml(event.detail || "근거 설명 없음")}</p>
        <small class="origin">${escapeHtml(event.origin || "unknown origin")} · 권한 ${escapeHtml(event.access_level || "미확인")} · ${Math.round((event.confidence ?? 0) * 100)}% · ${escapeHtml(event.source || "source unavailable")}</small>
      </article>
    `).join("")
    : `<div class="empty-state evidence-empty">${usage.data_complete ? "수집 범위에서 생성된 보안 이벤트가 없습니다." : "Usage telemetry가 불완전해 이벤트 부재를 안전으로 판정할 수 없습니다."}</div>`;

  document.querySelector("#scenario-count").textContent = `${scenarios.length} MATCHES`;
  document.querySelector("#scenario-list").innerHTML = scenarios.length
    ? scenarios.map((scenario) => `
      <article class="scenario-item ${isForcedScenario(scenario, analysis) ? "forced" : ""}">
        <header><code>${escapeHtml(scenario.scenario_id)}</code>${badge(scenario.severity)}</header>
        <strong>${escapeHtml(scenario.name || "Matched scenario")}</strong>
        <p>${escapeHtml(scenario.reason || "판정 이유 없음")}</p>
        <small class="origin">${escapeHtml(scenario.category || "usage_anomaly")} · ${Math.round((scenario.confidence ?? 0) * 100)}%${isForcedScenario(scenario, analysis) ? " · FORCED CRITICAL" : ""}</small>
      </article>
    `).join("")
    : `<div class="empty-state evidence-empty">현재 근거와 일치하는 시나리오가 없습니다. 이는 위험이 0이라는 뜻이 아닙니다.</div>`;

  const factors = analysis.risk_detail?.factors || [];
  document.querySelector("#risk-factor-list").innerHTML = factors.length
    ? factors.map((factor) => {
      const maxScore = Math.max(Number(factor.max_score) || 0, 1);
      const score = Math.max(Number(factor.score) || 0, 0);
      return `<div class="risk-factor" title="${escapeHtml((factor.reasons || []).join(" · "))}"><label>${escapeHtml(factor.label || factor.area)}</label><span class="factor-track"><i style="width:${Math.min(score / maxScore * 100, 100)}%"></i></span><b>${score} / ${maxScore}</b></div>`;
    }).join("")
    : (analysis.risk_reasons || []).map((reason) => `<div class="risk-reason">${escapeHtml(reason)}</div>`).join("")
      || `<div class="empty-state evidence-empty">저장된 위험 요인 세부값이 없습니다.</div>`;
  document.querySelector("#decision-action").textContent = `권고 · ${analysis.recommended_action || "MONITOR"}`;
  loadHistoryComparison(analysis);
}

async function loadHistoryComparison(analysis) {
  const container = document.querySelector("#history-comparison");
  const trend = document.querySelector("#history-trend");
  const nhiId = analysis.discovery?.nhi_id;
  const analysisId = analysis.analysis_id;
  if (!nhiId || !analysisId) {
    trend.textContent = "비교 불가";
    trend.className = "chip";
    container.innerHTML = `<div class="empty-state">NHI ID 또는 저장 분석 ID가 없어 이력을 비교할 수 없습니다.</div>`;
    return;
  }

  const cached = state.historyComparisons[analysisId];
  if (cached) {
    renderHistoryComparison(cached);
    return;
  }
  trend.textContent = "비교 중";
  trend.className = "chip";
  container.innerHTML = `<div class="empty-state">직전 분석과 결정 근거를 비교하고 있습니다.</div>`;
  try {
    const result = await api(`/nhi/${encodeURIComponent(nhiId)}/history/compare?target_analysis_id=${encodeURIComponent(analysisId)}`);
    state.historyComparisons[analysisId] = result;
  } catch (error) {
    state.historyComparisons[analysisId] = { error: error.message };
  }
  if (state.selectedAnalysisId === analysisId) {
    renderHistoryComparison(state.historyComparisons[analysisId]);
  }
}

function renderHistoryComparison(result) {
  const container = document.querySelector("#history-comparison");
  const trend = document.querySelector("#history-trend");
  if (result.error) {
    trend.textContent = "최초 기준선";
    trend.className = "chip";
    container.innerHTML = `<div class="empty-state">비교할 이전 분석이 없습니다. 다음 분석부터 위험·권한·정책 변화가 표시됩니다.</div>`;
    return;
  }

  const comparison = result.comparison || {};
  const risk = comparison.risk || {};
  const direction = risk.trend || "UNKNOWN";
  const delta = Number(risk.score_delta || 0);
  trend.textContent = direction === "IMPROVED" ? "개선" : direction === "DEGRADED" ? "악화" : direction === "UNCHANGED" ? "변화 없음" : "확인 필요";
  trend.className = `chip ${direction}`;
  const deltaText = delta > 0 ? `+${delta}` : `${delta}`;
  const changes = [
    ["Risk score", `${risk.before_score ?? "—"} → ${risk.after_score ?? "—"}`, `변화 ${deltaText} · ${risk.before_level || "UNKNOWN"} → ${risk.after_level || "UNKNOWN"}`],
    ["Permissions", `${(comparison.permissions?.added || []).length} 추가 · ${(comparison.permissions?.removed || []).length} 제거`, historyDeltaText(comparison.permissions)],
    ["Policy / Rules", `${(comparison.policy_violations?.added || []).length + (comparison.forced_critical_rules?.added || []).length} 신규 · ${(comparison.policy_violations?.removed || []).length + (comparison.forced_critical_rules?.removed || []).length} 해소`, `${historyDeltaText(comparison.policy_violations)} ${historyDeltaText(comparison.forced_critical_rules)}`],
    ["Recommended actions", `${(comparison.recommendations?.added || []).length} 추가 · ${(comparison.recommendations?.removed || []).length} 제거`, historyDeltaText(comparison.recommendations)],
  ];
  container.innerHTML = changes.map(([label, value, detail]) => `
    <div class="history-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><p>${detail || "변경 없음"}</p></div>
  `).join("");
}

function historyDeltaText(delta) {
  const added = delta?.added || [];
  const removed = delta?.removed || [];
  const parts = [];
  if (added.length) parts.push(`<span class="added">+ ${escapeHtml(added.join(", "))}</span>`);
  if (removed.length) parts.push(`<span class="removed">− ${escapeHtml(removed.join(", "))}</span>`);
  return parts.join("<br>") || "변경 없음";
}

function openAnalysis(analysisId) {
  state.selectedAnalysisId = analysisId;
  renderDecisionIntelligence();
  setView("decisions");
}

function renderGraph() {
  const graph = state.graph || { nodes: [], edges: [], stats: {} };
  const stats = graph.stats || {};
  document.querySelector("#graph-stats").innerHTML = Object.entries(stats)
    .filter(([, count]) => count)
    .map(([type, count]) => `<span class="badge">${escapeHtml(type)} · ${count}</span>`).join("");
  const container = document.querySelector("#relationship-graph");
  if (!graph.nodes?.length) {
    container.innerHTML = `<div class="empty-state">분석이 저장되면 NHI 관계와 Attack Path가 표시됩니다.</div>`;
    return;
  }
  const layers = ["AI_AGENT", "NHI", "CREDENTIAL", "PERMISSION", "SERVICE", "RESOURCE"];
  const colors = {
    AI_AGENT: "#a58bff", NHI: "#68e0c1", CREDENTIAL: "#ff5d7a",
    PERMISSION: "#f5cc5f", SERVICE: "#4da3ff", RESOURCE: "#54d69d",
  };
  const positions = new Map();
  layers.forEach((type, column) => {
    const nodes = graph.nodes.filter((node) => node.type === type);
    nodes.forEach((node, index) => {
      positions.set(node.id, {
        x: 85 + column * 175,
        y: 58 + (index + 1) * (390 / (nodes.length + 1)),
      });
    });
  });
  const edges = graph.edges.map((edge) => {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    if (!source || !target) return "";
    const mid = (source.x + target.x) / 2;
    return `<path class="graph-edge" d="M${source.x},${source.y} C${mid},${source.y} ${mid},${target.y} ${target.x},${target.y}"><title>${escapeHtml(edge.type)}</title></path>`;
  }).join("");
  const nodes = graph.nodes.map((node) => {
    const point = positions.get(node.id);
    if (!point) return "";
    const label = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;
    return `<g class="graph-node" transform="translate(${point.x},${point.y})"><circle r="17" fill="${colors[node.type] || "#8ca0b8"}"></circle><text y="33">${escapeHtml(label)}</text><text class="node-type" y="-27">${escapeHtml(node.type)}</text><title>${escapeHtml(node.label)}</title></g>`;
  }).join("");
  container.innerHTML = `<svg viewBox="0 0 980 480" role="img" aria-label="NHI relationship graph">${edges}${nodes}</svg>`;
}

function renderReviews() {
  const pending = state.actions.filter((item) => item.status === "PENDING_APPROVAL");
  document.querySelector("#review-list").innerHTML = pending.length
    ? pending.map((action) => `
      <article class="review-card">
        <div>
          <h3>${badge(action.risk_level)} ${escapeHtml(action.action_type)}</h3>
          <p>${escapeHtml(action.rationale)}</p>
          <div class="review-meta"><span>Target · ${escapeHtml(action.target)}</span><span>Provider · ${escapeHtml(action.provider)}</span><span>Created · ${fmtDate(action.created_at)}</span></div>
        </div>
        <div class="review-actions">
          ${action.analysis_id ? `<button class="secondary-button" onclick="openAnalysis('${action.analysis_id}')">Evidence</button>` : ""}
          <button class="danger-button" onclick="decideReview('${action.action_id}', false)">Reject</button><button class="primary-button" onclick="decideReview('${action.action_id}', true)">Approve</button>
        </div>
      </article>`).join("")
    : `<div class="empty-state">대기 중인 Review가 없습니다.</div>`;
}

function renderAudit() {
  document.querySelector("#audit-list").innerHTML = state.audit.length
    ? state.audit.map((event) => `
      <div class="audit-item"><i class="audit-node"></i><time>${fmtDate(event.occurred_at)}</time><div><span class="primary">${escapeHtml(event.event_type)}</span><small> · ${escapeHtml(event.target)}</small></div><small>${escapeHtml(event.actor)}</small></div>
    `).join("")
    : `<div class="empty-state">Audit event가 없습니다.</div>`;
}

function setView(name, updateHash = true) {
  document.querySelectorAll(".view").forEach((view) =>
    view.classList.toggle("active", view.dataset.view === name));
  document.querySelectorAll(".nav-item").forEach((item) =>
    item.classList.toggle("active", item.dataset.viewTarget === name));
  const labels = {
    overview: "Executive overview", projects: "Project coverage", findings: "Finding lifecycle",
    nhi: "NHI inventory", decisions: "Explainable decision flow", graph: "Relationship graph",
    reviews: "Review queue", audit: "System audit",
  };
  document.querySelector("#page-title").textContent = labels[name] || "NHI Sentinel";
  if (updateHash && window.location.hash !== `#${name}`) {
    history.replaceState(null, "", `#${name}`);
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function scanProject(projectId) {
  if (!confirm("이 Project의 GitHub Repository를 지금 검사할까요?")) return;
  try {
    await api(`/projects/${projectId}/scan`, { method: "POST" });
    await loadDashboard();
  } catch (error) { showError(error.message); }
}

async function discoverGitHubOrganization() {
  const organization = prompt("수집할 GitHub organization 이름을 입력하세요.");
  if (!organization) return;
  const key = sessionStorage.getItem("nhiAdminKey") || prompt("관리자 API Key를 입력하세요.");
  if (!key) return;
  sessionStorage.setItem("nhiAdminKey", key);
  const button = document.querySelector("#github-discover-button");
  button.disabled = true;
  button.textContent = "수집 중…";
  try {
    const result = await api("/integrations/github/discover", {
      method: "POST",
      headers: { "X-NHI-Admin-Key": key },
      body: JSON.stringify({
        organization: organization.trim(),
        analyze: true,
        allow_policy_evaluation: true,
        allow_secret_scan: false,
      }),
    });
    await loadDashboard();
    showSuccess(`${organization} 수집 완료 · ${result.run_summary?.collection?.count || 0} installations · replan ${result.run_summary?.replan_count || 0}`);
    setView("nhi");
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "GitHub 조직 수집";
  }
}

async function decideReview(actionId, approve) {
  const action = state.actions.find((item) => item.action_id === actionId);
  const isDemo = Boolean(action?.demo_workspace);
  const key = isDemo
    ? ""
    : sessionStorage.getItem("nhiAdminKey") || prompt("관리자 API Key를 입력하세요.");
  if (!isDemo && !key) return;
  if (!isDemo) sessionStorage.setItem("nhiAdminKey", key);
  const reason = approve ? "Dashboard security review approved" : prompt("거부 사유를 입력하세요.") || "Rejected";
  try {
    const prefix = isDemo ? "/demo/reviews" : "/reviews";
    await api(`${prefix}/${actionId}/${approve ? "approve" : "reject"}`, {
      method: "POST",
      headers: isDemo ? {} : { "X-NHI-Admin-Key": key },
      body: JSON.stringify({ actor: "dashboard-admin", reason }),
    });
    await loadDashboard();
  } catch (error) { showError(error.message); }
}

async function updateFindingStatus(findingId, status, previous) {
  if (status === previous) return;
  try {
    await api(`/findings/${findingId}/status`, {
      method: "PATCH",
      body: JSON.stringify({
        status,
        actor: "dashboard-admin",
        note: "Dashboard lifecycle update",
      }),
    });
    await loadDashboard();
  } catch (error) {
    showError(error.message);
    await loadDashboard();
  }
}

function showError(message) {
  const banner = document.querySelector("#error-banner");
  banner.classList.remove("success");
  banner.textContent = message; banner.hidden = false;
}

function showSuccess(message) {
  const banner = document.querySelector("#error-banner");
  banner.classList.add("success");
  banner.textContent = message; banner.hidden = false;
}

async function seedDemoWorkspace() {
  const button = document.querySelector("#demo-workspace-button");
  button.disabled = true;
  button.textContent = "생성 중…";
  try {
    const result = await api("/demo/workspace", { method: "POST" });
    await loadDashboard();
    showSuccess(
      `안전한 합성 데이터가 생성되었습니다: Project ${result.project_count}, Finding ${result.finding_count}, NHI ${result.nhi_count}`,
    );
    setView("overview");
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
  }
}

async function resetDemoWorkspace() {
  if (!confirm("합성 데모 데이터만 초기화할까요? 직접 등록한 Project와 Finding은 유지됩니다.")) return;
  const button = document.querySelector("#demo-reset-button");
  button.disabled = true;
  try {
    await api("/demo/workspace", { method: "DELETE" });
    await loadDashboard();
    showSuccess("데모 데이터가 초기화되었습니다. 직접 등록한 데이터는 유지되었습니다.");
  } catch (error) {
    showError(error.message);
  } finally {
    button.disabled = false;
  }
}

document.querySelectorAll("[data-view-target]").forEach((button) =>
  button.addEventListener("click", () => setView(button.dataset.viewTarget)));
document.querySelectorAll("[data-view-link]").forEach((button) =>
  button.addEventListener("click", () => setView(button.dataset.viewLink)));
document.querySelector("#refresh-button").addEventListener("click", loadDashboard);
document.querySelector("#demo-workspace-button").addEventListener("click", seedDemoWorkspace);
document.querySelector("#demo-reset-button").addEventListener("click", resetDemoWorkspace);
document.querySelector("#github-discover-button").addEventListener("click", discoverGitHubOrganization);
document.querySelector("#admin-key-button").addEventListener("click", () => {
  const key = prompt("세션에만 보관할 관리자 API Key를 입력하세요.");
  if (key) sessionStorage.setItem("nhiAdminKey", key);
});

const dialog = document.querySelector("#project-dialog");
document.querySelector("#new-project-button").addEventListener("click", () => dialog.showModal());
document.querySelector("#project-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api("/projects", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"), repository: form.get("repository"),
        description: form.get("description"),
        policy_enabled: form.get("policy_enabled") === "on",
      }),
    });
    dialog.close(); event.currentTarget.reset(); await loadDashboard();
  } catch (error) { showError(error.message); }
});

const statusFilter = document.querySelector("#finding-status-filter");
statusFilter.innerHTML += findingStatuses.map((status) => `<option>${status}</option>`).join("");
statusFilter.addEventListener("change", renderFindings);
document.querySelector("#finding-risk-filter").addEventListener("change", renderFindings);
document.querySelector("#finding-search").addEventListener("input", renderFindings);
document.querySelector("#analysis-selector").addEventListener("change", (event) => {
  state.selectedAnalysisId = event.target.value;
  renderDecisionIntelligence();
});

const initialView = window.location.hash.slice(1);
const knownViews = new Set(
  [...document.querySelectorAll(".view")].map((view) => view.dataset.view),
);
if (knownViews.has(initialView)) {
  setView(initialView, false);
}
loadDashboard();
