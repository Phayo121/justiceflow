"use strict";

const ROLE_INFO = {
  police: { label: "Police", title: "Police intake", description: "Register initial records and make administrative referrals.", visibleStages: ["Police intake", "Closed"] },
  prosecution: { label: "Prosecution", title: "Prosecution review", description: "Review incoming referrals and record authorized workflow updates.", visibleStages: ["Prosecutor review", "Closed"] },
  court: { label: "Court", title: "Court proceedings", description: "Track cases in the court workflow and record authorized onward handoffs.", visibleStages: ["Court proceedings", "Closed"] },
  corrections: { label: "Corrections", title: "Correctional services", description: "Track custody handoffs and administrative completion.", visibleStages: ["Correctional custody", "Closed"] },
  admin: { label: "Administrator", title: "Access administration", description: "Provision staff accounts. Case records are not visible in this administrator workspace.", visibleStages: [] }
};
const STAGE_CLASS = { "Police intake": "police", "Prosecutor review": "prosecution", "Court proceedings": "court", "Correctional custody": "corrections", Closed: "closed" };
let profile;
let cases = [];
let toastTimer;
const caseBody = document.getElementById("case-table-body");
const caseModal = document.getElementById("case-modal");
const detailModal = document.getElementById("detail-modal");
const toast = document.getElementById("toast");

async function api(url, options = {}) {
  const response = await fetch(url, { credentials: "same-origin", ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) } });
  const result = response.status === 204 ? {} : await response.json();
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Your session has ended. Please sign in again.");
  }
  if (response.status === 428) {
    window.location.assign("/change-password");
    throw new Error("Change your temporary password to continue.");
  }
  if (!response.ok) throw new Error(result.error || "Request failed.");
  return result;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

function showToast(message, isError = false) {
  window.clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 3500);
}

function roleWorkspace(role) {
  return `/${role === "admin" ? "admin" : role}`;
}

function routeGuard() {
  const role = window.location.pathname.slice(1).split("/")[0];
  if (role !== profile.role) window.location.replace(roleWorkspace(profile.role));
}

function renderNavigation(info) {
  const nav = document.getElementById("workspace-nav");
  if (profile.role === "admin") {
    nav.innerHTML = '<a class="workspace-nav-item active" href="/admin"><span>⚙</span> Staff accounts</a><a class="workspace-nav-item" href="/#rights"><span>§</span> Rights reference</a>';
    return;
  }
  nav.innerHTML = `<a class="workspace-nav-item active" href="${roleWorkspace(profile.role)}"><span>▤</span> ${escapeHtml(info.label)} register <b id="nav-case-count">0</b></a><a class="workspace-nav-item" href="/#rights"><span>§</span> Rights reference</a>`;
}

function setProfile() {
  const info = ROLE_INFO[profile.role];
  document.title = `${info.title} | JusticeFlow`;
  document.getElementById("role-badge").textContent = info.label;
  document.getElementById("workspace-title").textContent = info.title;
  document.getElementById("page-eyebrow").textContent = `ESWATINI · ${info.label.toUpperCase()} WORKSPACE`;
  document.getElementById("page-title").textContent = `Welcome, ${profile.displayName}`;
  document.getElementById("page-description").textContent = info.description;
  document.getElementById("staff-name").textContent = profile.displayName;
  document.getElementById("staff-role").textContent = info.label;
  document.getElementById("staff-avatar").textContent = profile.displayName.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  renderNavigation(info);
  if (profile.role === "admin") {
    document.getElementById("cases-panel").hidden = true;
    document.getElementById("admin-panel").hidden = false;
    document.getElementById("stats-grid").innerHTML = '<article><span>Staff accounts</span><strong>Provisioned by administrators</strong><small>Roles limit access to assigned agency workflows</small></article>';
  } else {
    document.getElementById("new-case-button").hidden = profile.role !== "police";
  }
}

function renderCases() {
  const query = document.getElementById("case-search").value.trim().toLowerCase();
  const stage = document.getElementById("stage-filter").value;
  const visible = cases.filter((item) => (!stage || item.stage === stage) && [item.id, item.alias, item.offenceCategory, item.station].some((value) => value.toLowerCase().includes(query)));
  caseBody.innerHTML = visible.map((item) => `<tr><td class="case-reference">${escapeHtml(item.id)}</td><td class="person-cell">${escapeHtml(item.alias)}</td><td>${escapeHtml(item.offenceCategory)}</td><td>${escapeHtml(item.station)}</td><td><span class="stage-pill ${STAGE_CLASS[item.stage]}">${escapeHtml(item.stage)}</span></td><td>${escapeHtml(new Date(item.updatedAt).toLocaleString())}</td><td><button class="row-action" type="button" data-case-id="${escapeHtml(item.id)}" aria-label="Open ${escapeHtml(item.id)}">›</button></td></tr>`).join("");
  document.getElementById("empty-state").hidden = visible.length > 0;
  const count = document.getElementById("nav-case-count");
  if (count) count.textContent = String(cases.length);
  const stages = ROLE_INFO[profile.role].visibleStages;
  document.getElementById("stats-grid").innerHTML = stages.map((name) => `<article><span>${escapeHtml(name)}</span><strong>${cases.filter((item) => item.stage === name).length}</strong><small>Cases visible to your role</small></article>`).join("");
}

async function loadCases() {
  const result = await api("/api/cases");
  cases = result.cases;
  renderCases();
}

function openModal(modal) {
  modal.hidden = false;
  modal.querySelector("input, textarea, button")?.focus();
}

function closeModal(modal) {
  modal.hidden = true;
}

function renderCase(item) {
  document.getElementById("detail-title").textContent = item.id;
  const eventList = item.events.map((event) => `<li><strong>${escapeHtml(event.stage)} · ${escapeHtml(new Date(event.createdAt).toLocaleString())}</strong><span>${escapeHtml(event.note)}</span><small>${escapeHtml(event.actor)}</small></li>`).reverse().join("");
  const transitions = { police: ["Police intake", ["Prosecutor review"]], prosecution: ["Prosecutor review", ["Court proceedings", "Closed"]], court: ["Court proceedings", ["Correctional custody", "Closed"]], corrections: ["Correctional custody", ["Closed"]] };
  const allowed = transitions[profile.role];
  const transitionOptions = allowed && item.stage === allowed[0] ? allowed[1].map((stage) => `<option>${escapeHtml(stage)}</option>`).join("") : "";
  document.getElementById("case-detail").innerHTML = `
    <dl class="detail-grid"><div><dt>Person / alias</dt><dd>${escapeHtml(item.alias)}</dd></div><div><dt>Offence category</dt><dd>${escapeHtml(item.offenceCategory)}</dd></div><div><dt>Police station</dt><dd>${escapeHtml(item.station)}</dd></div><div><dt>Current stage</dt><dd><span class="stage-pill ${STAGE_CLASS[item.stage]}">${escapeHtml(item.stage)}</span></dd></div></dl>
    <h3 class="subheading">Activity history</h3><ol class="activity-list">${eventList || "<li>No activity recorded.</li>"}</ol>
    ${transitionOptions ? `<section class="handoff"><h3>Record an administrative handoff</h3><p>The next team will see this case after the handoff. This records a workflow update only.</p><form id="handoff-form"><label>Next stage<select name="stage" required>${transitionOptions}</select></label><label>Handoff note<textarea name="note" maxlength="1000" rows="3" required></textarea></label><button class="button button-dark" type="submit">Record handoff</button></form></section>` : ""}
  `;
  openModal(detailModal);
}

document.getElementById("logout-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
    window.location.assign("/login");
  } catch (error) { showToast(error.message, true); }
});

document.getElementById("case-search").addEventListener("input", renderCases);
document.getElementById("stage-filter").addEventListener("change", renderCases);
document.getElementById("new-case-button").addEventListener("click", () => openModal(caseModal));
document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", () => closeModal(button.closest(".modal-backdrop"))));
document.querySelectorAll(".modal-backdrop").forEach((backdrop) => backdrop.addEventListener("click", (event) => { if (event.target === backdrop) closeModal(backdrop); }));
document.addEventListener("keydown", (event) => { if (event.key === "Escape") document.querySelectorAll(".modal-backdrop:not([hidden])").forEach(closeModal); });

caseBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-case-id]");
  if (!button) return;
  try {
    const { case: record } = await api(`/api/cases/${encodeURIComponent(button.dataset.caseId)}`);
    renderCase(record);
  } catch (error) { showToast(error.message, true); }
});

document.getElementById("new-case-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  try {
    const result = await api("/api/cases", { method: "POST", body: JSON.stringify(values) });
    form.reset();
    closeModal(caseModal);
    await loadCases();
    showToast(`Case ${result.case.id} created.`);
  } catch (error) { showToast(error.message, true); }
});

document.getElementById("case-detail").addEventListener("submit", async (event) => {
  if (event.target.id !== "handoff-form") return;
  event.preventDefault();
  const values = Object.fromEntries(new FormData(event.target));
  const caseId = document.getElementById("detail-title").textContent;
  try {
    const result = await api(`/api/cases/${encodeURIComponent(caseId)}/handoff`, { method: "POST", body: JSON.stringify(values) });
    await loadCases();
    if (result.case.events) renderCase(result.case);
    else closeModal(detailModal);
    showToast(`Handoff recorded: ${values.stage}.`);
  } catch (error) { showToast(error.message, true); }
});

document.getElementById("create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  const message = document.getElementById("admin-message");
  message.hidden = true;
  try {
    const result = await api("/api/admin/users", { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(form))) });
    form.reset();
    message.textContent = `Account "${result.user.username}" created. Give the temporary password to the staff member using an approved secure channel.`;
    message.hidden = false;
  } catch (error) { showToast(error.message, true); }
  finally { button.disabled = false; }
});

async function start() {
  try {
    const { user } = await api("/api/session");
    profile = user;
    routeGuard();
    setProfile();
    if (profile.role !== "admin") await loadCases();
  } catch (error) {
    if (!["Your session has ended. Please sign in again.", "Change your temporary password to continue."].includes(error.message)) showToast(error.message, true);
  }
}

start();
