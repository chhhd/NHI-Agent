/* NHI 거버넌스 화면 — 생명주기(DAS) · 변경 승인 · 실시간 통제.
 * app.js 의 api / escapeHtml / badge / fmtDate / showError / showSuccess / loadDashboard 를 재사용한다. */

const STAGES = [
  ["REGISTERED", "등록"], ["ACTIVE", "사용"],
  ["DEACTIVATED", "사용 중지"], ["DECOMMISSIONED", "폐기 완료"],
];
const CHANGE_LABELS = {
  TOKEN_REVOKE: "Token 폐기", TOKEN_ROTATE: "Token 교체", SCOPE_CHANGE: "권한 변경",
  TOKEN_DISPOSE: "Token 파기", QUARANTINE: "격리",
};
const STATUS_LABELS = {
  PENDING_APPROVAL: "승인 대기", APPLIED: "적용됨", REJECTED: "거부됨",
  ROLLED_BACK: "롤백됨", FAILED: "실패",
};
const gov = {
  lifecycle: { stages: [], items: [], alerts: [], policy: {} },
  changes: [],
  control: { status: null, events: [], lastSeq: 0 },
  stageFilter: "",
  changeFilter: "PENDING_APPROVAL",
  openChange: null,
  poller: null,
};

const actorName = () => localStorage.getItem("nhiActor") || "dashboard-admin";
const stageLabel = (stage) => (STAGES.find(([key]) => key === stage) || [, stage])[1];
const chip = (text, cls = "") => `<span class="perm-chip ${cls}">${escapeHtml(text)}</span>`;
const verdictBadge = (verdict) => `<span class="badge verdict-${escapeHtml(verdict)}">${escapeHtml(verdict)}</span>`;

function adminHeaders(demo) {
  if (demo) return {};
  const key = sessionStorage.getItem("nhiAdminKey") || prompt("관리자 API Key를 입력하세요.");
  if (!key) throw new Error("관리자 API Key가 필요합니다.");
  sessionStorage.setItem("nhiAdminKey", key);
  return { "X-NHI-Admin-Key": key };
}

async function govPost(path, body, demo) {
  const headers = adminHeaders(demo);
  const verified = demo ? null : await verifiedAdminId(headers["X-NHI-Admin-Key"]);
  // 개인 키면 서버가 키의 관리자 ID 를 actor 로 쓰므로 화면에서 입력한 이름 대신 그 ID 를 보낸다.
  const payload = verified
    ? { ...body, ...("actor" in body ? { actor: verified } : {}), ...("requested_by" in body ? { requested_by: verified } : {}) }
    : body;
  return api(path, { method: "POST", headers, body: JSON.stringify(payload) });
}

async function loadGovernance() {
  try {
    const [lifecycle, changes, status, events] = await Promise.all([
      api("/lifecycle"), api("/changes?limit=200"), api("/control/status"),
      api("/control/events?limit=40"),
    ]);
    gov.lifecycle = lifecycle;
    gov.changes = changes.changes;
    gov.control.status = status;
    gov.control.events = events.events;
    gov.control.lastSeq = events.last_seq || 0;
    renderGovernance();
  } catch (error) {
    showError(`거버넌스 데이터를 불러오지 못했습니다: ${error.message}`);
  }
}

function renderGovernance() {
  renderLifecycle();
  renderChanges();
  renderControl();
  const pending = gov.changes.filter((c) => c.status === "PENDING_APPROVAL").length;
  document.querySelector("#nav-change-count").textContent = pending;
  document.querySelector("#nav-quarantine-count").textContent =
    gov.control.status?.quarantined?.length || 0;
}

/* ------------------------------------------------------------------ 생명주기 */
function stepper(current) {
  const index = STAGES.findIndex(([key]) => key === current);
  return `<div class="stepper" aria-label="생명주기 단계">${STAGES.map(([key, label], i) =>
    `<span class="step ${i < index ? "done" : ""} ${i === index ? "current" : ""}" title="${label}"></span>`).join("")}</div>`;
}

function renderLifecycle() {
  const { stages, items, alerts, policy } = gov.lifecycle;
  document.querySelector("#stage-pipeline").innerHTML = stages.map((stage, i) => `
    <button class="stage-card ${gov.stageFilter === stage.stage ? "selected" : ""} stage-${stage.stage}"
      onclick="filterStage('${stage.stage}')">
      <small>${i + 1}단계</small><strong>${stage.count}</strong><span>${escapeHtml(stage.label)}</span>
    </button>${i < stages.length - 1 ? `<i class="stage-arrow">→</i>` : ""}`).join("");

  document.querySelector("#lifecycle-policy").textContent =
    `보존 ${policy.retention_days || 0}일 · 미사용 ${policy.stale_days || 0}일 · 교체 ${policy.rotation_days || 0}일 기준`;

  document.querySelector("#aging-alerts").innerHTML = alerts.length
    ? alerts.map((alert) => `
      <div class="alert-row">
        ${badge(alert.severity)}
        <div><span class="primary">${escapeHtml(alert.nhi_name)}</span>
        <span class="sub">${escapeHtml(alert.message)}</span></div>
        <button class="text-button" onclick="openLifecycle('${escapeHtml(alert.nhi_id)}')">상세 →</button>
      </div>`).join("")
    : `<div class="empty-state">노후화 경보가 없습니다.</div>`;

  const rows = items.filter((item) => !gov.stageFilter || item.stage === gov.stageFilter);
  document.querySelector("#lifecycle-rows").innerHTML = rows.length ? rows.map((item) => `
    <tr data-search="${escapeHtml([item.nhi_name, item.owner, item.provider].join(" ").toLowerCase())}">
      <td><span class="primary">${escapeHtml(item.nhi_name)}</span><span class="sub">${escapeHtml(item.provider)} · ${escapeHtml(item.environment || "unknown")}</span></td>
      <td>${stepper(item.stage)}<span class="sub">${escapeHtml(item.stage_label)}${item.days_in_stage != null ? ` · ${item.days_in_stage}일째` : ""}</span></td>
      <td>${item.age_days != null ? `${item.age_days}일` : "—"}<span class="sub">마지막 사용 ${item.days_since_last_use != null ? `${item.days_since_last_use}일 전` : "—"}</span></td>
      <td>${item.control_state === "QUARANTINED" ? badge("QUARANTINED") + " " : ""}${item.aging.slice(0, 2).map((f) => `<span class="flag ${escapeHtml(f.severity)}">${escapeHtml(f.code)}</span>`).join(" ") || `<span class="sub">정상</span>`}</td>
      <td>${item.pending_change_count ? `<span class="badge PENDING_APPROVAL">승인 ${item.pending_change_count}</span>` : ""}</td>
      <td><button class="text-button" onclick="openLifecycle('${escapeHtml(item.nhi_id)}')">타임라인 →</button></td>
    </tr>`).join("") : emptyRow(6, "해당 단계의 NHI가 없습니다.");
}

function filterStage(stage) {
  gov.stageFilter = gov.stageFilter === stage ? "" : stage;
  renderLifecycle();
}

async function openLifecycle(nhiId) {
  try {
    const view = await api(`/lifecycle/${encodeURIComponent(nhiId)}`);
    const demo = view.demo_workspace;
    document.querySelector("#lifecycle-detail").innerHTML = `
      <div class="dialog-head"><div><p class="eyebrow">NHI LIFECYCLE</p><h2>${escapeHtml(view.nhi_name)}</h2></div>
        <button type="button" class="dialog-close" onclick="this.closest('dialog').close()">×</button></div>
      <div class="big-stepper">${STAGES.map(([key, label], i) => {
        const current = STAGES.findIndex(([k]) => k === view.stage);
        return `<div class="big-step ${i < current ? "done" : ""} ${i === current ? "current" : ""}"><i>${i + 1}</i><span>${label}</span></div>`;
      }).join("")}</div>
      <dl class="facts">
        <div><dt>Owner</dt><dd>${escapeHtml(view.owner || "미지정")}</dd></div>
        <div><dt>Credential</dt><dd>${badge(view.credential_state)} v${view.credential_version}</dd></div>
        <div><dt>통제 상태</dt><dd>${badge(view.control_state)}</dd></div>
        <div><dt>권한</dt><dd>${(view.permissions || []).map((p) => chip(p)).join("") || "—"}</dd></div>
      </dl>
      <p class="next-step"><b>다음 조치</b> ${escapeHtml(view.next_step)}</p>
      <h3>타임라인</h3>
      <ol class="timeline">${view.timeline.map((event) => `
        <li class="tl-${escapeHtml(event.stage)}"><time>${fmtDate(event.occurred_at)}</time>
          <div><span class="primary">${escapeHtml(event.event_type)}</span> <small>${escapeHtml(stageLabel(event.stage))} · ${escapeHtml(event.actor)}</small>
          ${event.detail?.reason ? `<span class="sub">${escapeHtml(event.detail.reason)}</span>` : ""}</div></li>`).join("")}</ol>
      <div class="dialog-actions">
        ${view.manual_advance_to ? `<button class="secondary-button" onclick="advanceStage('${escapeHtml(nhiId)}', ${demo})">${escapeHtml(stageLabel(view.manual_advance_to))} 단계로 진행</button>` : ""}
        ${view.stage === "ACTIVE" ? `<button class="secondary-button" onclick="openProposeFor('${escapeHtml(nhiId)}')">변경 제안</button>` : ""}
        ${view.stage === "DEACTIVATED" ? `<button class="danger-button" onclick="openProposeFor('${escapeHtml(nhiId)}', 'TOKEN_DISPOSE')">파기 제안</button>` : ""}
      </div>`;
    document.querySelector("#lifecycle-dialog").showModal();
  } catch (error) { showError(error.message); }
}

async function advanceStage(nhiId, demo) {
  try {
    await govPost(`/lifecycle/${encodeURIComponent(nhiId)}/advance`,
      { actor: actorName(), reason: "Dashboard 에서 단계 진행" }, demo);
    document.querySelector("#lifecycle-dialog").close();
    await loadDashboard();
  } catch (error) { showError(error.message); }
}

/* ------------------------------------------------------------------ 변경 승인 */
function diffRow(label, before, after, render = (v) => escapeHtml(String(v ?? "—"))) {
  const changed = JSON.stringify(before) !== JSON.stringify(after);
  return `<tr class="${changed ? "changed" : ""}"><th>${label}</th><td>${render(before)}</td><td>${render(after)}</td></tr>`;
}

function permChips(list, other, kind) {
  if (!list.length) return `<span class="sub">없음</span>`;
  return list.map((item) => chip(item, other.includes(item) ? "" : kind)).join("");
}

function renderPlan(plan) {
  const { impact, before, after, rollback, approval } = plan;
  const d = impact.diff;
  const sc = impact.service_continuity;
  const br = impact.blast_radius;
  return `
    <div class="plan-head">
      <span class="badge ${escapeHtml(plan.tier)}">승인 등급 ${escapeHtml(plan.tier)}</span>
      <span class="plan-summary">${escapeHtml(impact.summary)}</span>
    </div>
    <ul class="reasons">${approval.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
      ${approval.required ? `<li>${approval.separation_of_duties ? "요청자와 다른 관리자의 승인이 필요합니다." : "관리자 승인이 필요합니다."}${approval.impact_acknowledgement_required ? " 영향도 확인 체크가 필수입니다." : ""}</li>` : ""}</ul>
    <table class="diff-table">
      <thead><tr><th></th><th>변경 전</th><th>변경 후</th></tr></thead>
      <tbody>
        <tr class="${d.permissions.removed.length || d.permissions.added.length ? "changed" : ""}"><th>권한</th>
          <td>${permChips(d.permissions.before, d.permissions.after, "removed")}</td>
          <td>${permChips(d.permissions.after, d.permissions.before, "added")}</td></tr>
        <tr class="${d.scopes.removed.length || d.scopes.added.length ? "changed" : ""}"><th>Scope</th>
          <td>${permChips(d.scopes.before, d.scopes.after, "removed")}</td>
          <td>${permChips(d.scopes.after, d.scopes.before, "added")}</td></tr>
        ${diffRow("실효 접근", d.effective_access.before, d.effective_access.after, (v) => v.length ? v.map((p) => chip(p)).join("") : `<span class="sub">접근 불가</span>`)}
        ${diffRow("Credential 상태", d.credential_state.before, d.credential_state.after)}
        ${diffRow("통제 상태", d.control_state.before, d.control_state.after)}
        ${diffRow("생명주기 단계", stageLabel(d.lifecycle_stage.before), stageLabel(d.lifecycle_stage.after))}
        ${diffRow("Credential 버전", `v${d.credential_version.before}`, `v${d.credential_version.after}`)}
      </tbody>
    </table>
    <div class="plan-grid">
      <section><h4>영향 범위</h4>
        <p>환경 <b>${escapeHtml(br.environment)}</b> · 리소스 ${br.accessible_resource_count || 0}개${br.linked_ai_agent ? ` · AI Agent <b>${escapeHtml(br.linked_ai_agent)}</b>` : ""}</p>
        <p>${(br.connected_services || []).map((s) => chip(s)).join("") || ""}${(br.resource_samples || []).slice(0, 4).map((r) => chip(r, "res")).join("")}</p></section>
      <section class="continuity ${escapeHtml(sc.risk)}"><h4>서비스 연속성 <span class="badge ${escapeHtml(sc.risk)}">${escapeHtml(sc.risk)}</span></h4>
        <p>${sc.will_interrupt ? "⚠ 적용 즉시 서비스 호출이 중단될 수 있습니다." : "✓ 즉시 중단 없음"}</p>
        <ul>${sc.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul>
        ${sc.mitigations.length ? `<h5>완화 방안</h5><ul>${sc.mitigations.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul>` : ""}</section>
      <section><h4>보안 효과</h4><ul>${impact.security_effect.map((n) => `<li>${escapeHtml(n)}</li>`).join("") || "<li>—</li>"}</ul></section>
      <section class="rollback ${rollback.supported ? "" : "none"}"><h4>롤백 계획 ${rollback.supported ? badge("가능") : badge("불가")}</h4>
        <p>${escapeHtml(rollback.supported ? rollback.strategy : rollback.unsupported_reason)}</p>
        ${rollback.window_hours ? `<p class="sub">유예 ${rollback.window_hours}시간 이내에만 가능</p>` : ""}
        <ol>${(rollback.steps || []).map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ol></section>
    </div>`;
}

function renderChanges() {
  const filter = gov.changeFilter;
  const rows = gov.changes.filter((c) => !filter || c.status === filter);
  document.querySelectorAll("#change-filters button").forEach((button) =>
    button.classList.toggle("active", button.dataset.status === filter));
  document.querySelector("#change-list").innerHTML = rows.length ? rows.map((change) => {
    const d = change.impact.diff;
    const sc = change.impact.service_continuity;
    return `
    <article class="change-card tier-${escapeHtml(change.tier)}">
      <header>
        <div><h3>${escapeHtml(CHANGE_LABELS[change.change_type] || change.change_type)} · ${escapeHtml(change.nhi_name)}</h3>
          <p>${escapeHtml(change.reason || "사유 없음")}</p></div>
        <div class="change-badges"><span class="badge ${escapeHtml(change.tier)}">${escapeHtml(change.tier)}</span>
          <span class="badge status-${escapeHtml(change.status)}">${escapeHtml(STATUS_LABELS[change.status] || change.status)}</span></div>
      </header>
      <div class="mini-diff">
        <div>${permChips(d.permissions.before, d.permissions.after, "removed")}</div><i>→</i>
        <div>${permChips(d.permissions.after, d.permissions.before, "added")}</div>
        <span class="mini-state">${escapeHtml(d.lifecycle_stage.before === d.lifecycle_stage.after ? "" : `${stageLabel(d.lifecycle_stage.before)} → ${stageLabel(d.lifecycle_stage.after)}`)}</span>
      </div>
      <footer>
        <span class="sub">요청 ${escapeHtml(change.requested_by)}${change.source === "control-plane" ? " (실시간 통제)" : ""} · ${fmtDate(change.created_at)} · 연속성 ${escapeHtml(sc.risk)}${change.approved_by ? ` · 승인 ${escapeHtml(change.approved_by)}` : ""}</span>
        <button class="secondary-button" onclick="openChange('${change.change_id}')">${change.status === "PENDING_APPROVAL" ? "영향도 검토·승인" : "상세"}</button>
      </footer>
    </article>`;
  }).join("") : `<div class="empty-state">해당 상태의 변경 요청이 없습니다.</div>`;
}

function openChange(changeId) {
  const change = gov.changes.find((c) => c.change_id === changeId);
  if (!change) return;
  gov.openChange = change;
  const pending = change.status === "PENDING_APPROVAL";
  const canRollback = change.status === "APPLIED" && change.rollback.supported;
  const needAck = change.approval.impact_acknowledgement_required;
  document.querySelector("#change-detail").innerHTML = `
    <div class="dialog-head"><div><p class="eyebrow">CHANGE REQUEST · ${escapeHtml(STATUS_LABELS[change.status] || change.status)}</p>
      <h2>${escapeHtml(CHANGE_LABELS[change.change_type])} · ${escapeHtml(change.nhi_name)}</h2></div>
      <button type="button" class="dialog-close" onclick="this.closest('dialog').close()">×</button></div>
    <p class="muted-line">요청 ${escapeHtml(change.requested_by)} · ${fmtDate(change.created_at)} — ${escapeHtml(change.reason || "사유 없음")}</p>
    ${renderPlan(change)}
    ${change.approved_by ? `<p class="muted-line">승인 ${escapeHtml(change.approved_by)} · ${fmtDate(change.approved_at)} ${escapeHtml(change.decision_reason)}</p>` : ""}
    ${change.rolled_back_by ? `<p class="muted-line">롤백 ${escapeHtml(change.rolled_back_by)} · ${fmtDate(change.rolled_back_at)} ${escapeHtml(change.rollback_reason)}</p>` : ""}
    ${change.rollback_expires_at && change.status === "APPLIED" ? `<p class="muted-line">롤백 가능: ${fmtDate(change.rollback_expires_at)} 까지</p>` : ""}
    ${pending || canRollback ? `
    <div class="decision">
      <label>작업자<input id="change-actor" value="${escapeHtml(actorName())}"></label>
      <label>사유<input id="change-reason" placeholder="승인/거부/롤백 사유"></label>
      ${pending && needAck ? `<label class="ack"><input type="checkbox" id="change-ack"> 변경 전·후 형상과 서비스 영향도를 확인했습니다.</label>` : ""}
      ${pending && change.change_type === "TOKEN_DISPOSE" ? `
      <fieldset class="evidence"><legend>파기 증적 (필수)</legend>
        <label>파기 방법<select id="ev-method">
          <option value="SECRET_MATERIAL_DELETED">보관 중인 원문·키 삭제</option>
          <option value="PROVIDER_REVOKED">공급자에서 Credential 폐기</option>
          <option value="ACCOUNT_DELETED">서비스 계정·App 삭제</option></select></label>
        <label>검증자 (수행자와 다른 사람)<input id="ev-verifier" placeholder="예: sam"></label>
        <label>검증 방법<input id="ev-check" placeholder="예: 폐기된 Token 으로 GET /user 호출"></label>
        <label>검증 결과<select id="ev-result">
          <option value="AUTH_REJECTED_401">401 인증 거부</option>
          <option value="AUTH_REJECTED_403">403 인증 거부</option>
          <option value="NOT_FOUND_404">404 대상 없음</option>
          <option value="MATERIAL_ABSENT">보관 원문 없음 확인</option></select></label>
      </fieldset>` : ""}
    </div>
    <div class="dialog-actions">
      ${pending ? `<button class="danger-button" onclick="decideChange('reject')">거부</button>
      <button class="primary-button" onclick="decideChange('approve')">승인 후 적용</button>` : ""}
      ${canRollback ? `<button class="danger-button" onclick="decideChange('rollback')">롤백 (변경 전 형상으로 복원)</button>` : ""}
    </div>` : ""}`;
  document.querySelector("#change-dialog").showModal();
}

async function decideChange(action) {
  const change = gov.openChange;
  const actor = document.querySelector("#change-actor").value.trim();
  if (!actor) return showError("작업자 이름이 필요합니다.");
  localStorage.setItem("nhiActor", actor);
  const body = {
    actor,
    reason: document.querySelector("#change-reason").value,
    acknowledge_impact: Boolean(document.querySelector("#change-ack")?.checked),
  };
  if (action === "approve" && change.change_type === "TOKEN_DISPOSE") {
    body.destruction_evidence = {
      method: document.querySelector("#ev-method").value,
      verified_by: document.querySelector("#ev-verifier").value.trim(),
      verification_check: document.querySelector("#ev-check").value.trim(),
      verification_result: document.querySelector("#ev-result").value,
    };
  }
  try {
    await govPost(`/changes/${change.change_id}/${action}`, body, change.demo_workspace);
    document.querySelector("#change-dialog").close();
    await loadDashboard();
    showSuccess(`${CHANGE_LABELS[change.change_type]} 요청이 ${{ approve: "승인·적용", reject: "거부", rollback: "롤백" }[action]}되었습니다.`);
  } catch (error) { showError(error.message); }
}

/* 변경 제안 */
function proposeParamsHtml(type, nhi) {
  if (type === "SCOPE_CHANGE") {
    const current = nhi?.permissions || [];
    return `<fieldset><legend>변경 후 권한</legend>${["READ", "WRITE", "DELETE", "ADMIN"].map((p) =>
      `<label class="inline"><input type="checkbox" name="perm" value="${p}" ${current.includes(p) ? "checked" : ""}> ${p}</label>`).join("")}</fieldset>`;
  }
  if (type === "TOKEN_ROTATE") {
    return `<label>이전 Token 유예 시간(시간) — 0이면 즉시 무효화<input type="number" id="propose-grace" min="0" max="336" value="${gov.lifecycle.policy.rotation_grace_hours ?? 24}"></label>`;
  }
  return "";
}

function proposeParams() {
  const type = document.querySelector("#propose-type").value;
  if (type === "SCOPE_CHANGE") {
    return { target_permissions: [...document.querySelectorAll("#propose-params input[name=perm]:checked")].map((i) => i.value) };
  }
  if (type === "TOKEN_ROTATE") return { grace_period_hours: Number(document.querySelector("#propose-grace").value) };
  return {};
}

function refreshProposeForm() {
  const nhi = gov.lifecycle.items.find((i) => i.nhi_id === document.querySelector("#propose-nhi").value);
  document.querySelector("#propose-params").innerHTML = proposeParamsHtml(document.querySelector("#propose-type").value, nhi);
  document.querySelector("#propose-preview").innerHTML = "";
}

function openProposeFor(nhiId, type) {
  document.querySelector("#lifecycle-dialog")?.close();
  openPropose(nhiId, type);
}

function openPropose(nhiId, type) {
  const items = gov.lifecycle.items.filter((i) => i.stage !== "DECOMMISSIONED");
  document.querySelector("#propose-nhi").innerHTML = items.map((i) =>
    `<option value="${escapeHtml(i.nhi_id)}" ${i.nhi_id === nhiId ? "selected" : ""}>${escapeHtml(i.nhi_name)} · ${escapeHtml(i.stage_label)}</option>`).join("");
  if (type) document.querySelector("#propose-type").value = type;
  document.querySelector("#propose-actor").value = actorName();
  refreshProposeForm();
  document.querySelector("#propose-dialog").showModal();
}

function proposePayload() {
  return {
    nhi_id: document.querySelector("#propose-nhi").value,
    change_type: document.querySelector("#propose-type").value,
    params: proposeParams(),
  };
}

async function previewProposal() {
  try {
    const plan = await api("/changes/preview", { method: "POST", body: JSON.stringify(proposePayload()) });
    document.querySelector("#propose-preview").innerHTML = renderPlan(plan);
  } catch (error) {
    document.querySelector("#propose-preview").innerHTML = `<div class="error-banner">${escapeHtml(error.message)}</div>`;
  }
}

async function submitProposal() {
  const actor = document.querySelector("#propose-actor").value.trim();
  if (!actor) return showError("요청자 이름이 필요합니다.");
  localStorage.setItem("nhiActor", actor);
  const payload = proposePayload();
  const demo = gov.lifecycle.items.find((i) => i.nhi_id === payload.nhi_id)?.demo_workspace;
  try {
    const change = await govPost("/changes", {
      ...payload, requested_by: actor,
      reason: document.querySelector("#propose-reason").value,
    }, demo);
    document.querySelector("#propose-dialog").close();
    await loadDashboard();
    gov.changeFilter = change.status === "PENDING_APPROVAL" ? "PENDING_APPROVAL" : "APPLIED";
    renderChanges();
    setView("changes");
    showSuccess(change.status === "APPLIED"
      ? "LOW 등급이라 자동 승인되어 적용되었습니다."
      : "변경이 제안되었습니다. 영향도를 검토하고 승인하세요.");
  } catch (error) {
    document.querySelector("#propose-preview").innerHTML = `<div class="error-banner">${escapeHtml(error.message)}</div>`;
  }
}

/* ------------------------------------------------------------------ 실시간 통제 */
function renderControl() {
  const status = gov.control.status;
  if (!status) return;
  document.querySelector("#control-mode").innerHTML =
    `<span class="badge mode-${escapeHtml(status.mode)}">${escapeHtml(({ enforce: "ENFORCE · REVIEW/DENY 차단", monitor: "MONITOR · REVIEW 관찰, DENY 차단", human_in_the_loop: "HUMAN IN THE LOOP · REVIEW 승인 대기" })[status.mode] || status.mode)}</span>`;
  document.querySelector("#control-counters").innerHTML = ["DENY", "REVIEW", "ALERT"].map((verdict) =>
    `<div class="counter verdict-${verdict}"><strong>${status.last_hour[verdict] || 0}</strong><span>${verdict} · 최근 1시간</span></div>`).join("")
    + `<div class="counter"><strong>${status.pending_control_changes}</strong><span>통제가 올린 승인 대기</span></div>`;
  document.querySelector("#quarantine-list").innerHTML = status.quarantined.length
    ? status.quarantined.map((n) => `
      <div class="alert-row"><span class="badge QUARANTINED">QUARANTINED</span>
        <div><span class="primary">${escapeHtml(n.nhi_name)}</span><span class="sub">모든 사용 요청이 차단되고 있습니다.</span></div>
        <button class="secondary-button" onclick="releaseNhi('${escapeHtml(n.nhi_id)}')">격리 해제</button></div>`).join("")
    : `<div class="empty-state">격리 중인 NHI가 없습니다.</div>`;

  const select = document.querySelector("#sim-nhi");
  if (select.options.length !== gov.lifecycle.items.length) {
    select.innerHTML = gov.lifecycle.items.filter((i) => i.stage !== "DECOMMISSIONED").map((i) =>
      `<option value="${escapeHtml(i.nhi_id)}">${escapeHtml(i.nhi_name)}</option>`).join("");
  }
  document.querySelector("#control-feed").innerHTML = gov.control.events.length
    ? gov.control.events.map(feedItem).join("")
    : `<div class="empty-state">아직 통제 이벤트가 없습니다. 아래 시뮬레이터로 발생시켜 보세요.</div>`;
}

function feedItem(event) {
  const name = gov.lifecycle.items.find((i) => i.nhi_id === event.nhi_id)?.nhi_name || event.nhi_id;
  return `<div class="feed-item verdict-${escapeHtml(event.verdict)}">
    ${verdictBadge(event.verdict)}
    <div><span class="primary">${escapeHtml(name)}</span> <small>${escapeHtml(event.event_type)}${event.allowed ? " · 허용" : " · 차단/승인 대기"}</small>
      ${event.rules.map((r) => `<span class="sub"><b>${escapeHtml(r.rule_id)}</b> ${escapeHtml(r.message)}</span>`).join("")}</div>
    <time>${fmtDate(event.occurred_at)}</time></div>`;
}

async function pollControl() {
  if (document.hidden || !document.querySelector('[data-view="control"]').classList.contains("active")) return;
  try {
    const data = await api(`/control/events?after_seq=${gov.control.lastSeq}&limit=100`);
    if (!data.events.length) return;
    gov.control.lastSeq = data.last_seq;
    gov.control.events = [...data.events.reverse(), ...gov.control.events].slice(0, 60);
    gov.control.status = await api("/control/status");
    gov.changes = (await api("/changes?limit=200")).changes;
    renderControl();
    renderChanges();
    document.querySelector("#nav-change-count").textContent =
      gov.changes.filter((c) => c.status === "PENDING_APPROVAL").length;
  } catch (_) { /* 다음 주기에 재시도 */ }
}

function simFields() {
  const type = document.querySelector("#sim-type").value;
  document.querySelector("#sim-fields").innerHTML = {
    CREDENTIAL_USE: `<label>요청 권한<select id="sim-permission"><option>READ</option><option>WRITE</option><option>DELETE</option><option>ADMIN</option></select></label>
      <label>출처 IP (선택)<input id="sim-ip" placeholder="203.0.113.9"></label>`,
    USAGE_SPIKE: `<label>현재 요청/분<input id="sim-rate" type="number" value="400"></label>
      <label>평소 요청/분<input id="sim-baseline" type="number" value="40"></label>`,
    EXPOSURE_DETECTED: `<label>노출 위치<input id="sim-location" value="public repo: config/prod.env"></label>`,
  }[type];
}

async function fireSimulation() {
  const nhiId = document.querySelector("#sim-nhi").value;
  const type = document.querySelector("#sim-type").value;
  const demo = gov.lifecycle.items.find((i) => i.nhi_id === nhiId)?.demo_workspace;
  const attributes = type === "CREDENTIAL_USE"
    ? { permission: document.querySelector("#sim-permission").value, source_ip: document.querySelector("#sim-ip").value || undefined }
    : type === "USAGE_SPIKE"
      ? { requests_per_min: Number(document.querySelector("#sim-rate").value), baseline_per_min: Number(document.querySelector("#sim-baseline").value) }
      : { location: document.querySelector("#sim-location").value };
  try {
    const result = await govPost("/control/events", { nhi_id: nhiId, event_type: type, attributes }, demo);
    document.querySelector("#sim-result").innerHTML = `
      <div class="sim-result verdict-${escapeHtml(result.verdict)}">
        <div>${verdictBadge(result.verdict)} <b>${result.allowed ? "요청 허용" : "요청 차단"}</b>
          <small>${result.enforced ? "집행됨" : "섀도 모드 — 실제로는 차단하지 않음"}</small></div>
        ${result.rules.map((r) => `<span class="sub"><b>${escapeHtml(r.rule_id)}</b> ${escapeHtml(r.message)}</span>`).join("") || `<span class="sub">발동한 규칙 없음 — 정상 요청입니다.</span>`}
        ${result.quarantine_change_id ? `<span class="sub">→ 즉시 격리가 적용되었습니다 (변경 ${escapeHtml(result.quarantine_change_id.slice(0, 8))}).</span>` : ""}
        ${result.follow_up_change_ids.length ? `<span class="sub">→ Token 폐기 승인 요청이 Change Control 에 등록되었습니다.</span>` : ""}
      </div>`;
    await loadDashboard();
  } catch (error) { showError(error.message); }
}

async function releaseNhi(nhiId) {
  const demo = gov.lifecycle.items.find((i) => i.nhi_id === nhiId)?.demo_workspace;
  try {
    await govPost(`/control/nhi/${encodeURIComponent(nhiId)}/release`, { actor: actorName(), reason: "Dashboard 에서 격리 해제" }, demo);
    await loadDashboard();
    showSuccess("격리를 해제했습니다. 사용 요청이 다시 허용됩니다.");
  } catch (error) { showError(error.message); }
}

/* ------------------------------------------------------------------ 초기화 */
document.querySelectorAll("#change-filters button").forEach((button) =>
  button.addEventListener("click", () => { gov.changeFilter = button.dataset.status; renderChanges(); }));
document.querySelector("#new-change-button").addEventListener("click", () => openPropose());
document.querySelector("#propose-nhi").addEventListener("change", refreshProposeForm);
document.querySelector("#propose-type").addEventListener("change", refreshProposeForm);
document.querySelector("#propose-preview-button").addEventListener("click", previewProposal);
document.querySelector("#propose-submit-button").addEventListener("click", submitProposal);
document.querySelector("#sim-type").addEventListener("change", simFields);
document.querySelector("#sim-fire").addEventListener("click", fireSimulation);
simFields();
gov.poller = setInterval(pollControl, 3000);
