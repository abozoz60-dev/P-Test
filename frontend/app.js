"use strict";
const API = "";
let token = localStorage.getItem("ptest_token") || "";
let role = localStorage.getItem("ptest_role") || "";

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  if (res.status === 401) { logout(); throw new Error("Session expired"); }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.detail) || res.statusText);
  return data;
}

/* ---------- auth ---------- */
$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#loginErr"); err.hidden = true;
  try {
    const d = await api("/api/auth/login", { method: "POST", body: JSON.stringify({
      username: $("#username").value, password: $("#password").value }) });
    token = d.access_token; role = d.role;
    localStorage.setItem("ptest_token", token);
    localStorage.setItem("ptest_role", role);
    enterApp();
  } catch (ex) { err.textContent = ex.message; err.hidden = false; }
});

function logout() {
  token = ""; role = "";
  localStorage.removeItem("ptest_token"); localStorage.removeItem("ptest_role");
  $("#appShell").hidden = true; $("#login").hidden = false;
}
$("#logoutBtn").addEventListener("click", logout);

async function enterApp() {
  $("#login").hidden = true; $("#appShell").hidden = false;
  $("#whoami").textContent = `role: ${role}`;
  await refreshAll();
}

/* ---------- tabs ---------- */
$$(".tab").forEach((t) => t.addEventListener("click", () => {
  $$(".tab").forEach((x) => x.classList.remove("active"));
  t.classList.add("active");
  $$(".tabpane").forEach((p) => (p.hidden = true));
  $("#tab-" + t.dataset.tab).hidden = false;
}));

/* ---------- overview ---------- */
async function loadOverview() {
  const p = await api("/api/posture");
  $("#scoreVal").textContent = p.score;
  $("#scoreVal").style.color = p.score >= 80 ? "var(--low)" : p.score >= 50 ? "var(--med)" : "var(--crit)";
  $("#scoreMethod").textContent = p.methodology;
  $("#statTargets").textContent = p.totals.targets;
  $("#statScans").textContent = p.totals.scans;
  $("#statFindings").textContent = p.totals.findings;
  const order = ["critical", "high", "medium", "low", "informational"];
  const max = Math.max(1, ...order.map((s) => p.by_severity[s] || 0));
  $("#sevBars").innerHTML = order.map((s) => {
    const n = p.by_severity[s] || 0;
    return `<div class="sevbar"><span class="sev-${s}">${s}</span>
      <span class="bar bg-${s}" style="width:${(n / max) * 100}%"></span><span>${n}</span></div>`;
  }).join("");
}

/* ---------- targets ---------- */
async function loadTargets() {
  const targets = await api("/api/targets");
  const tb = $("#targetsTable tbody");
  tb.innerHTML = targets.map((t) => `<tr>
    <td>${t.id}</td><td>${esc(t.name)}</td><td class="small">${esc(t.scope)}</td>
    <td>${t.approved ? "✅ " + esc(t.approved_by) : "—"}</td>
    <td>${t.enabled ? "yes" : "no"}</td>
    <td>${role === "admin" && !t.approved ? `<button onclick="approveTarget(${t.id})">Approve</button>` : ""}
        ${role === "admin" && t.enabled ? `<button class="btn-ghost danger" onclick="disableTarget(${t.id})">Disable</button>` : ""}</td>
  </tr>`).join("") || `<tr><td colspan="6" class="muted">No targets registered.</td></tr>`;
  // populate scan target dropdown (approved+enabled only)
  const sel = $("#scanTarget");
  const opts = targets.filter((t) => t.approved && t.enabled);
  sel.innerHTML = opts.map((t) => `<option value="${t.id}">${esc(t.name)} (${esc(t.scope)})</option>`).join("")
    || `<option value="">No approved targets</option>`;
}
window.approveTarget = async (id) => { await api(`/api/targets/${id}/approve`, { method: "POST" }); refreshAll(); };
window.disableTarget = async (id) => { await api(`/api/targets/${id}/disable`, { method: "POST" }); refreshAll(); };

$("#targetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#targetErr"); err.hidden = true;
  try {
    await api("/api/targets", { method: "POST", body: JSON.stringify({
      name: $("#tName").value, scope: $("#tScope").value,
      owner_attestation: $("#tAttest").value, authorization_ref: $("#tAuthRef").value }) });
    $("#targetForm").reset(); refreshAll();
  } catch (ex) { err.textContent = ex.message; err.hidden = false; }
});

/* ---------- scans ---------- */
async function loadChecks() {
  const checks = await api("/api/checks");
  $("#moduleChecks").innerHTML = checks.map((c) =>
    `<label title="${esc(c.description)}"><input type="checkbox" value="${c.id}" checked>${esc(c.name)}</label>`).join("");
}
async function loadScans() {
  const scans = await api("/api/scans");
  $("#scansTable tbody").innerHTML = scans.map((s) => `<tr>
    <td>${s.id}</td><td>${s.target_id}</td><td class="small">${esc(s.modules)}</td>
    <td>${esc(s.status)}${s.error ? ` <span class="err small">(${esc(s.error)})</span>` : ""}</td>
    <td>${esc(s.operator)}</td>
    <td>${["queued", "running"].includes(s.status) ? `<button class="btn-ghost danger" onclick="cancelScan(${s.id})">Cancel</button>` : ""}
        <button class="btn-ghost" onclick="viewFindings(${s.id})">Findings</button></td>
  </tr>`).join("") || `<tr><td colspan="6" class="muted">No scans yet.</td></tr>`;
}
window.cancelScan = async (id) => { await api(`/api/scans/${id}/cancel`, { method: "POST" }); refreshAll(); };
window.viewFindings = (id) => {
  $$(".tab").forEach((x) => x.classList.remove("active"));
  document.querySelector('[data-tab="findings"]').classList.add("active");
  $$(".tabpane").forEach((p) => (p.hidden = true));
  $("#tab-findings").hidden = false;
  loadFindings({ scan_id: id });
};

$("#scanForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#scanErr"); err.hidden = true;
  const modules = [...$$("#moduleChecks input:checked")].map((i) => i.value);
  try {
    await api("/api/scans", { method: "POST", body: JSON.stringify({
      target_id: parseInt($("#scanTarget").value, 10), modules }) });
    setTimeout(refreshAll, 1500);
    refreshAll();
  } catch (ex) { err.textContent = ex.message; err.hidden = false; }
});

/* ---------- findings ---------- */
async function loadFindings(extra = {}) {
  const q = new URLSearchParams();
  const sev = $("#fSeverity").value, st = $("#fStatus").value, cat = $("#fCategory").value;
  if (sev) q.set("severity", sev);
  if (st) q.set("valstatus", st);
  if (cat) q.set("category", cat);
  if (extra.scan_id) q.set("scan_id", extra.scan_id);
  const findings = await api("/api/findings?" + q.toString());
  $("#findingsList").innerHTML = findings.map((f) => `
    <div class="finding s-${f.severity}">
      <h4><span class="sev-${f.severity}">●</span> ${esc(f.title)}</h4>
      <div class="meta">${esc(f.vuln_id)} · ${esc(f.asset)} · ${esc(f.category)} · confidence ${esc(f.confidence)}</div>
      <dl>
        ${f.evidence ? `<dt>Evidence</dt><dd>${esc(f.evidence)}</dd>` : ""}
        ${f.impact ? `<dt>Impact</dt><dd>${esc(f.impact)}</dd>` : ""}
        ${f.remediation ? `<dt>Remediation</dt><dd>${esc(f.remediation)}</dd>` : ""}
        ${f.references ? `<dt>References</dt><dd>${esc(f.references)}</dd>` : ""}
      </dl>
      <div class="status-row"><span class="pill">${esc(f.status)}</span>
        ${["operator", "admin"].includes(role) ? `<select onchange="setFindingStatus(${f.id}, this.value)">
          ${["suspected", "confirmed", "false_positive", "fixed"].map((s) =>
            `<option value="${s}" ${s === f.status ? "selected" : ""}>${s}</option>`).join("")}
        </select>` : ""}</div>
    </div>`).join("") || `<p class="muted">No findings match.</p>`;
}
window.setFindingStatus = async (id, status) => {
  await api(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
  loadOverview();
};
$("#fApply").addEventListener("click", () => loadFindings());

/* ---------- audit ---------- */
async function loadAudit() {
  if (role !== "admin") { $("#auditTable").closest(".card").innerHTML = '<p class="muted">Admin only.</p>'; return; }
  const d = await api("/api/audit");
  const b = $("#chainBadge");
  b.textContent = d.chain_intact ? "chain intact" : `TAMPERED (id ${d.first_bad_id})`;
  b.className = "badge " + (d.chain_intact ? "ok" : "");
  $("#auditTable tbody").innerHTML = d.events.map((e) => `<tr>
    <td>${e.id}</td><td class="small">${esc(e.ts)}</td><td>${esc(e.actor)}</td>
    <td>${esc(e.action)}</td><td>${esc(e.target_ref)}</td><td class="small">${esc(e.detail)}</td>
  </tr>`).join("");
}

/* ---------- emergency stop ---------- */
async function loadEstop() {
  const d = await api("/api/emergency-stop");
  $("#estopBadge").hidden = !d.emergency_stop;
}
$("#estopBtn").addEventListener("click", async () => {
  const cur = await api("/api/emergency-stop");
  if (role !== "admin") { alert("Admin only"); return; }
  await api(`/api/emergency-stop?engage=${!cur.emergency_stop}`, { method: "POST" });
  refreshAll();
});

async function refreshAll() {
  try {
    await Promise.all([loadOverview(), loadTargets(), loadChecks(), loadScans(), loadEstop()]);
    await loadFindings();
    if (role === "admin") await loadAudit();
  } catch (ex) { console.error(ex); }
}

if (token) enterApp();
