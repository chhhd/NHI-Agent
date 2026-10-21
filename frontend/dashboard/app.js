const state = {
  summary: {},
  projects: [],
  findings: [],
  nhi: [],
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
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
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
    const [summary, projects, findings, nhi, actions, audit, graph] = await Promise.all([
      api("/dashboard/summary"),
      api("/projects"),
      api("/findings?limit=100"),
      api("/nhi?limit=100"),
      api("/actions?limit=100"),
      api("/audit?limit=50"),
      api("/graph?limit=100"),
    ]);
    Object.assign(state, {
      summary,
      projects: projects.projects,
      findings: findings.findings,
      nhi: nhi.nhi,
      actions: actions.actions,
      audit: audit.events,
      graph,
    });
    render();
    document.querySelector("#last-updated").textContent =
      `UPDATED ${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" })}`;
    if (typeof loadGovernance === "function") await loadGovernance();
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
  renderReviews();
  renderAudit();
  renderGraph();
  document.querySelector("#nav-finding-count").textContent =
    state.summary.critical_high_findings || 0;
  document.querySelector("#nav-review-count").textContent =
    state.actions.filter((item) => item.status === "PENDING_APPROVAL").length;
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
    <tr data-search="${escapeHtml([finding.secret_type, finding.provider, finding.repository, finding.file_path, finding.nhi_name, finding.owner].join(" ").toLowerCase())}">
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
  const filtered = state.findings.filter((item) =>
    (!risk || item.risk_level === risk) && (!status || item.status === status));
  document.querySelector("#overview-findings").innerHTML = findingRows(state.findings.slice(0, 6));
  document.querySelector("#all-findings").innerHTML = findingRows(filtered, true);
}

function renderNhi() {
  document.querySelector("#nhi-cards").innerHTML = state.nhi.length
    ? state.nhi.map((item) => `
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
      </article>`).join("")
    : `<div class="empty-state">분석된 NHI가 없습니다. Scan 또는 Inventory 분석을 실행하세요.</div>`;
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
        <div class="review-actions"><button class="danger-button" onclick="decideReview('${action.action_id}', false)">Reject</button><button class="primary-button" onclick="decideReview('${action.action_id}', true)">Approve</button></div>
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

function setView(name) {
  document.querySelectorAll(".view").forEach((view) =>
    view.classList.toggle("active", view.dataset.view === name));
  document.querySelectorAll(".nav-item").forEach((item) =>
    item.classList.toggle("active", item.dataset.viewTarget === name));
  const labels = {
    overview: "Executive overview", projects: "Project coverage", findings: "Finding lifecycle",
    nhi: "NHI inventory", graph: "Relationship graph", reviews: "Review queue", audit: "Audit log",
    lifecycle: "NHI lifecycle", changes: "Change control", control: "Real-time control",
  };
  document.querySelector("#page-title").textContent = labels[name] || "NHI Sentinel";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function scanProject(projectId) {
  if (!confirm("이 Project의 GitHub Repository를 지금 검사할까요?")) return;
  try {
    await api(`/projects/${projectId}/scan`, { method: "POST" });
    await loadDashboard();
  } catch (error) { showError(error.message); }
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
    const actor = "dashboard-admin";
    await api(`${prefix}/${actionId}/${approve ? "approve" : "reject"}`, {
      method: "POST",
      headers: isDemo ? {} : { "X-NHI-Admin-Key": key },
      body: JSON.stringify({ actor, reason }),
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
        schedule_enabled: form.get("schedule_enabled") === "on",
      }),
    });
    dialog.close(); event.currentTarget.reset(); await loadDashboard();
  } catch (error) { showError(error.message); }
});

const statusFilter = document.querySelector("#finding-status-filter");
statusFilter.innerHTML += findingStatuses.map((status) => `<option>${status}</option>`).join("");
statusFilter.addEventListener("change", renderFindings);
document.querySelector("#finding-risk-filter").addEventListener("change", renderFindings);
document.querySelector("#global-search").addEventListener("input", (event) => {
  const term = event.target.value.trim().toLowerCase();
  document.querySelectorAll("tr[data-search]").forEach((row) => {
    row.hidden = term && !row.dataset.search.includes(term);
  });
});

loadDashboard();
