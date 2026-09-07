"use strict";

const STORAGE_KEY = "sentinel-studio-findings-v1";
const severityWeights = { Critical: 10, High: 7, Medium: 4, Low: 2, Informational: 0 };
const severityColors = { Critical: "#ff4d6d", High: "#ff8a4c", Medium: "#f4c95d", Low: "#55b4e9", Informational: "#9eacc0" };

// Clearly fictional demonstration records. These are reporting examples, not scan results.
const sampleFindings = [
  {
    id: "F-001", title: "Session lifetime exceeds policy", severity: "High", asset: "portal.northstar.example",
    status: "Open", owner: "Identity Team", tags: ["session", "authentication", "OWASP"],
    impact: "Long-lived authenticated sessions increase the window in which a lost or unattended device could be used to access a fictional customer account. Additional user interaction and an existing valid session would be required.",
    evidence: "Sample observation: the demonstration test account remained authenticated after the fictional 12-hour policy threshold. No session tokens or personal data were retained.",
    remediation: "Enforce absolute and idle session limits at the server, invalidate sessions after sensitive account changes, and require re-authentication for high-impact actions. Verify behavior across web and API clients.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"]
  },
  {
    id: "F-002", title: "Cloud administration lacks phishing-resistant MFA", severity: "Critical", asset: "ns-production",
    status: "In progress", owner: "Cloud Platform", tags: ["identity", "cloud", "MFA"],
    impact: "If a privileged credential were separately compromised, a weaker second factor may not provide sufficient protection against modern phishing. Administrative access could affect the confidentiality, integrity, and availability of fictional cloud resources.",
    evidence: "Sample configuration review: two fictional emergency administrator accounts permit a legacy one-time-password factor. No authentication attempts were performed.",
    remediation: "Require phishing-resistant authentication such as passkeys or hardware-backed FIDO2 keys for privileged roles. Restrict emergency accounts, monitor their use, and maintain a tested recovery process.",
    references: ["https://www.cisa.gov/resources-tools/resources/implementing-phishing-resistant-mfa"]
  },
  {
    id: "F-003", title: "API errors disclose internal component names", severity: "Medium", asset: "api.northstar.example",
    status: "Open", owner: "API Engineering", tags: ["API", "error-handling", "CWE-209"],
    impact: "Verbose error metadata can help an attacker understand internal architecture and refine subsequent attempts. The sampled information did not include credentials or customer records.",
    evidence: "Sample observation: a malformed request returned a fictional package name and internal service identifier in the JSON error response. Values were redacted in retained notes.",
    remediation: "Return stable, generic client error messages and correlation identifiers. Keep detailed diagnostics in access-controlled server logs, and test exception handlers at trust boundaries.",
    references: ["https://cwe.mitre.org/data/definitions/209.html", "https://owasp.org/API-Security/"]
  },
  {
    id: "F-004", title: "Content Security Policy permits broad script sources", severity: "Medium", asset: "portal.northstar.example",
    status: "Risk accepted", owner: "Web Platform", tags: ["browser", "CSP", "defense-in-depth"],
    impact: "A permissive policy reduces defense in depth if a separate script-injection flaw is introduced. This condition alone does not demonstrate script execution or compromise.",
    evidence: "Sample header review: the fictional policy allows a broad third-party content domain and inline styles. No injection testing was conducted.",
    remediation: "Inventory required origins, remove unused sources, prefer nonces or hashes for scripts, and deploy changes in report-only mode before enforcement. Review third-party dependencies.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
  },
  {
    id: "F-005", title: "Dormant workforce accounts retained beyond offboarding target", severity: "High", asset: "id.northstar.example",
    status: "Resolved", owner: "People Operations", tags: ["IAM", "lifecycle", "accounts"],
    impact: "Unnecessary active accounts expand the identity attack surface and could retain access inconsistent with current business need.",
    evidence: "Sample review: three fictional accounts were active more than 30 days after their synthetic end dates. Account identifiers were not retained in this demonstration.",
    remediation: "Automate authoritative offboarding, disable access promptly, revoke active sessions, and reconcile identity records on a scheduled basis. Track exceptions with an owner and expiration.",
    references: ["https://www.cisecurity.org/controls/account-management"]
  },
  {
    id: "F-006", title: "Security contact file is not published", severity: "Low", asset: "portal.northstar.example",
    status: "Open", owner: "Security", tags: ["disclosure", "security.txt"],
    impact: "Researchers may have difficulty finding an approved reporting channel, potentially delaying responsible disclosure of a security concern.",
    evidence: "Sample observation: the fictional /.well-known/security.txt path returned a generic not-found response.",
    remediation: "Publish a current security.txt file with a monitored contact, policy URL, expiration date, and preferred languages. Establish internal intake and triage ownership.",
    references: ["https://www.rfc-editor.org/rfc/rfc9116"]
  },
  {
    id: "F-007", title: "Audit log retention is shorter than investigation objective", severity: "Medium", asset: "ns-production",
    status: "In progress", owner: "Detection Team", tags: ["logging", "cloud", "IR"],
    impact: "A short retention period can limit historical investigation, evidence preservation, and timeline reconstruction after a delayed detection.",
    evidence: "Sample configuration review: management-event logs are retained for 30 days while the fictional investigation objective is 90 days.",
    remediation: "Align retention with legal, privacy, and incident-response requirements. Protect centralized logs from alteration, monitor ingestion health, and test retrieval.",
    references: ["https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection"]
  },
  {
    id: "F-008", title: "Dependency inventory has incomplete ownership metadata", severity: "Low", asset: "api.northstar.example",
    status: "Resolved", owner: "AppSec", tags: ["supply-chain", "inventory", "SBOM"],
    impact: "Missing ownership can delay assessment and upgrades when a dependency advisory is published. No vulnerable dependency was identified by this sample record.",
    evidence: "Sample document review: 18% of fictional direct dependencies lacked a named maintenance team in the inventory.",
    remediation: "Assign service and dependency ownership, generate inventories in delivery workflows, and define response targets based on exploitability and business context.",
    references: ["https://www.cisa.gov/sbom"]
  }
];

let findings = loadFindings();
let currentFindingId = null;
let lastFocusedElement = null;
let activeSeverity = "All";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const slug = value => value.toLowerCase().replace(/\s+/g, "-");

function loadFindings() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return structuredCloneSafe(sampleFindings);
    const parsed = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed : structuredCloneSafe(sampleFindings);
  } catch {
    return structuredCloneSafe(sampleFindings);
  }
}

function structuredCloneSafe(data) {
  return JSON.parse(JSON.stringify(data));
}

function saveFindings() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(findings));
  } catch {
    toast("Could not save to browser storage.", "error");
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderAll() {
  renderFindings();
  renderDashboard();
  $("#navFindingCount").textContent = findings.filter(f => !["Resolved", "Risk accepted"].includes(f.status)).length;
}

function renderDashboard() {
  const active = findings.filter(f => !["Resolved", "Risk accepted"].includes(f.status));
  const counts = Object.fromEntries(Object.keys(severityWeights).map(s => [s, active.filter(f => f.severity === s).length]));
  const possible = Math.max(active.length * 10, 10);
  const risk = Math.min(100, Math.round(active.reduce((sum, f) => sum + (severityWeights[f.severity] || 0), 0) / possible * 100));
  const label = risk >= 75 ? "Critical" : risk >= 50 ? "Elevated" : risk >= 25 ? "Moderate" : "Low";
  const color = risk >= 75 ? severityColors.Critical : risk >= 50 ? severityColors.High : risk >= 25 ? severityColors.Medium : severityColors.Low;
  $("#riskScore").textContent = risk;
  $("#riskLabel").textContent = label;
  $("#riskLabel").style.color = color;
  $("#riskLabel").style.background = `${color}18`;
  $("#riskGauge").style.setProperty("--risk-angle", `${risk * 3.6}deg`);
  $("#riskGauge").style.background = `conic-gradient(${color} 0deg, ${color} ${risk * 3.6}deg, var(--surface-3) ${risk * 3.6}deg)`;
  $("#riskHeadline").textContent = `${label} residual exposure`;
  $("#riskDescription").textContent = active.length ? `${active.length} active finding${active.length === 1 ? "" : "s"} require review.` : "No active findings remain.";

  const max = Math.max(...Object.values(counts), 1);
  const bars = $("#severityBars");
  bars.replaceChildren();
  ["Critical", "High", "Medium", "Low"].forEach(severity => {
    const row = el("div", "severity-row");
    row.append(el("span", "", severity));
    const track = el("div", "severity-track");
    const fill = el("i", "severity-fill");
    fill.style.width = `${counts[severity] / max * 100}%`;
    fill.style.background = severityColors[severity];
    track.append(fill);
    row.append(track, el("strong", "", counts[severity]));
    bars.append(row);
  });

  const resolved = findings.filter(f => f.status === "Resolved").length;
  const accepted = findings.filter(f => f.status === "Risk accepted").length;
  const progress = findings.length ? Math.round(resolved / findings.length * 100) : 0;
  $("#progressPercent").textContent = `${progress}%`;
  $("#progressRing").style.setProperty("--progress-angle", `${progress * 3.6}deg`);
  $("#resolvedCount").textContent = resolved;
  $("#acceptedCount").textContent = accepted;
  $("#openCount").textContent = active.length;

  const priorityList = $("#priorityList");
  priorityList.replaceChildren();
  [...active].sort((a, b) => severityWeights[b.severity] - severityWeights[a.severity]).slice(0, 4).forEach(finding => {
    const item = el("div", "priority-item");
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.setAttribute("aria-label", `Open ${finding.title}`);
    const dot = el("i", "priority-dot");
    dot.style.background = severityColors[finding.severity];
    const copy = el("div");
    copy.append(el("h3", "", finding.title), el("p", "", `${finding.id} · ${finding.asset} · ${finding.owner || "Unassigned"}`));
    item.append(dot, copy, el("span", "", "→"));
    item.addEventListener("click", () => openDrawer(finding.id));
    item.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openDrawer(finding.id); }
    });
    priorityList.append(item);
  });
  if (!priorityList.children.length) priorityList.append(el("p", "muted", "No active remediation items."));
}

function getFilteredFindings() {
  const query = $("#searchInput").value.trim().toLowerCase();
  const status = $("#statusFilter").value;
  return findings.filter(f => {
    const haystack = [f.id, f.title, f.asset, f.owner, ...(f.tags || [])].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) &&
      (activeSeverity === "All" || f.severity === activeSeverity) &&
      (status === "All" || f.status === status);
  });
}

function renderFindings() {
  const filtered = getFilteredFindings();
  const tbody = $("#findingsTable");
  tbody.replaceChildren();
  filtered.forEach(finding => {
    const row = el("tr");
    row.tabIndex = 0;
    const titleCell = el("td", "finding-title-cell");
    titleCell.append(el("strong", "", finding.title), el("span", "", finding.id));
    const severityCell = el("td");
    severityCell.append(el("span", `severity ${slug(finding.severity)}`, finding.severity));
    const statusCell = el("td");
    statusCell.append(el("span", `status ${slug(finding.status)}`, finding.status));
    const actionCell = el("td");
    const action = el("button", "row-action", "•••");
    action.setAttribute("aria-label", `Open ${finding.title}`);
    actionCell.append(action);
    row.append(titleCell, severityCell, el("td", "", finding.asset), statusCell, el("td", "", finding.owner || "Unassigned"), actionCell);
    row.addEventListener("click", () => openDrawer(finding.id));
    row.addEventListener("keydown", event => {
      if (event.key === "Enter") openDrawer(finding.id);
    });
    tbody.append(row);
  });
  $("#allCount").textContent = findings.length;
  $("#resultCount").textContent = `${filtered.length} of ${findings.length} findings`;
  $("#emptyState").hidden = filtered.length > 0;
}

function openDrawer(id) {
  const finding = findings.find(f => f.id === id);
  if (!finding) return;
  currentFindingId = id;
  lastFocusedElement = document.activeElement;
  $("#drawerId").textContent = finding.id;
  $("#drawerTitle").textContent = finding.title;
  $("#drawerImpact").textContent = finding.impact;
  $("#drawerEvidence").textContent = finding.evidence;
  $("#drawerRemediation").textContent = finding.remediation;
  const meta = $("#drawerMeta");
  meta.replaceChildren();
  const sev = el("span", `severity ${slug(finding.severity)}`, finding.severity);
  meta.append(sev, el("span", `status ${slug(finding.status)}`, finding.status), el("span", "meta-chip", finding.asset), el("span", "meta-chip", finding.owner || "Unassigned"));
  (finding.tags || []).forEach(tag => meta.append(el("span", "meta-chip", `#${tag}`)));
  const refs = $("#drawerReferences");
  refs.replaceChildren();
  (finding.references || []).forEach(reference => {
    const li = el("li");
    if (/^https?:\/\//i.test(reference)) {
      const link = el("a", "", reference);
      link.href = reference;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      li.append(link);
    } else li.textContent = reference;
    refs.append(li);
  });
  if (!refs.children.length) refs.append(el("li", "", "No external references provided."));
  $("#drawerBackdrop").hidden = false;
  $("#findingDrawer").hidden = false;
  document.body.style.overflow = "hidden";
  $("#closeDrawer").focus();
}

function closeDrawer() {
  $("#drawerBackdrop").hidden = true;
  $("#findingDrawer").hidden = true;
  document.body.style.overflow = "";
  currentFindingId = null;
  lastFocusedElement?.focus();
}

function openFindingForm(id = null) {
  closeDrawer();
  $("#findingForm").reset();
  $("#findingId").value = "";
  if (id) {
    const finding = findings.find(f => f.id === id);
    if (!finding) return;
    $("#formMode").textContent = "EDIT RECORD";
    $("#formTitle").textContent = "Edit finding";
    $("#findingId").value = finding.id;
    $("#findingTitle").value = finding.title;
    $("#findingSeverity").value = finding.severity;
    $("#findingStatus").value = finding.status;
    $("#findingAsset").value = finding.asset;
    $("#findingOwner").value = finding.owner || "";
    $("#findingImpact").value = finding.impact;
    $("#findingEvidence").value = finding.evidence;
    $("#findingRemediation").value = finding.remediation;
    $("#findingReferences").value = (finding.references || []).join(", ");
    $("#findingTags").value = (finding.tags || []).join(", ");
  } else {
    $("#formMode").textContent = "NEW RECORD";
    $("#formTitle").textContent = "Create finding";
  }
  $("#findingDialog").showModal();
  requestAnimationFrame(() => $("#findingTitle").focus());
}

function formValue(id) {
  return $(id).value.trim();
}

function nextFindingId() {
  const max = findings.reduce((value, finding) => Math.max(value, Number((finding.id.match(/\d+/) || [0])[0])), 0);
  return `F-${String(max + 1).padStart(3, "0")}`;
}

function saveFindingFromForm(event) {
  event.preventDefault();
  const existingId = formValue("#findingId");
  const record = {
    id: existingId || nextFindingId(),
    title: formValue("#findingTitle"),
    severity: $("#findingSeverity").value,
    status: $("#findingStatus").value,
    asset: formValue("#findingAsset"),
    owner: formValue("#findingOwner"),
    impact: formValue("#findingImpact"),
    evidence: formValue("#findingEvidence"),
    remediation: formValue("#findingRemediation"),
    references: formValue("#findingReferences").split(",").map(v => v.trim()).filter(Boolean),
    tags: formValue("#findingTags").split(",").map(v => v.trim()).filter(Boolean)
  };
  if (existingId) findings = findings.map(f => f.id === existingId ? record : f);
  else findings.unshift(record);
  saveFindings();
  renderAll();
  $("#findingDialog").close();
  toast(existingId ? "Finding updated." : "Finding created.");
}

function deleteCurrentFinding() {
  if (!currentFindingId) return;
  findings = findings.filter(f => f.id !== currentFindingId);
  saveFindings();
  renderAll();
  $("#confirmDialog").close();
  closeDrawer();
  toast("Finding deleted.");
}

function exportData() {
  const payload = {
    schemaVersion: 1,
    exportedAt: new Date().toISOString(),
    application: "Sentinel Studio",
    disclaimer: "Assessment records only. This export does not represent active scanning or independent verification.",
    engagement: { name: "Northstar Security Review", sampleData: true },
    findings
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `sentinel-studio-export-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
  toast("JSON export created.");
}

function validImportedFinding(finding) {
  const allowedSeverities = Object.keys(severityWeights);
  const allowedStatuses = ["Open", "In progress", "Resolved", "Risk accepted"];
  return finding && typeof finding === "object" &&
    ["id", "title", "asset", "impact", "evidence", "remediation"].every(key => typeof finding[key] === "string") &&
    allowedSeverities.includes(finding.severity) && allowedStatuses.includes(finding.status);
}

function importData(file) {
  if (!file) return;
  if (file.size > 2_000_000) { toast("Import rejected: file exceeds 2 MB.", "error"); return; }
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(reader.result);
      const records = Array.isArray(parsed) ? parsed : parsed.findings;
      if (!Array.isArray(records) || !records.every(validImportedFinding)) throw new Error("Invalid schema");
      findings = records.map((record, index) => ({
        ...record,
        id: record.id || `F-${String(index + 1).padStart(3, "0")}`,
        owner: typeof record.owner === "string" ? record.owner : "",
        tags: Array.isArray(record.tags) ? record.tags.filter(v => typeof v === "string") : [],
        references: Array.isArray(record.references) ? record.references.filter(v => typeof v === "string") : []
      }));
      saveFindings();
      renderAll();
      toast(`Imported ${findings.length} findings.`);
    } catch {
      toast("Import failed: choose a valid Sentinel Studio JSON export.", "error");
    } finally {
      $("#fileInput").value = "";
    }
  };
  reader.onerror = () => toast("Import failed: the file could not be read.", "error");
  reader.readAsText(file);
}

function toast(message, type = "") {
  const notice = el("div", `toast ${type}`.trim(), message);
  $("#toastRegion").append(notice);
  setTimeout(() => notice.remove(), 3800);
}

function switchView(viewId) {
  $$(".view").forEach(view => view.classList.toggle("active", view.id === viewId));
  $$(".nav-link").forEach(link => link.classList.toggle("active", link.dataset.view === viewId));
  $(".sidebar").classList.remove("open");
  $("#menuButton").setAttribute("aria-expanded", "false");
  history.replaceState(null, "", `#${viewId}`);
  $(`#${viewId} h1`)?.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function initializeEvents() {
  $$(".nav-link").forEach(link => link.addEventListener("click", () => switchView(link.dataset.view)));
  $$(".go-findings").forEach(button => button.addEventListener("click", () => switchView("findings")));
  $("#menuButton").addEventListener("click", () => {
    const open = $(".sidebar").classList.toggle("open");
    $("#menuButton").setAttribute("aria-expanded", String(open));
  });
  $("#searchInput").addEventListener("input", renderFindings);
  $("#statusFilter").addEventListener("change", renderFindings);
  $$(".filter-chip").forEach(chip => chip.addEventListener("click", () => {
    activeSeverity = chip.dataset.severity;
    $$(".filter-chip").forEach(item => item.classList.toggle("active", item === chip));
    renderFindings();
  }));
  $("#newFinding").addEventListener("click", () => openFindingForm());
  $("#findingForm").addEventListener("submit", saveFindingFromForm);
  $$(".dialog-close").forEach(button => button.addEventListener("click", () => button.closest("dialog").close()));
  $("#closeDrawer").addEventListener("click", closeDrawer);
  $("#drawerCloseButton").addEventListener("click", closeDrawer);
  $("#drawerBackdrop").addEventListener("click", closeDrawer);
  $("#editFinding").addEventListener("click", () => {
    const id = currentFindingId;
    openFindingForm(id);
  });
  $("#deleteFinding").addEventListener("click", () => $("#confirmDialog").showModal());
  $("#cancelDelete").addEventListener("click", () => $("#confirmDialog").close());
  $("#confirmDelete").addEventListener("click", deleteCurrentFinding);
  $("#exportButton").addEventListener("click", exportData);
  $("#importButton").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", event => importData(event.target.files[0]));
  $("#printButton").addEventListener("click", () => window.print());
  $("#openAbout").addEventListener("click", () => $("#aboutDialog").showModal());
  $$(".accordion-toggle").forEach(toggle => toggle.addEventListener("click", () => {
    const content = toggle.nextElementSibling;
    const open = content.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
    toggle.querySelector("span").textContent = open ? "−" : "＋";
  }));
  const pathCopy = {
    "Public web portal": "The fictional internet-facing application is the modeled starting point. Exposure alone is not a vulnerability.",
    "Weak session policy": "A long session window may preserve access longer than intended if a valid session is separately obtained.",
    "Verbose API errors": "Excess technical detail may improve an adversary’s understanding, but does not itself grant access.",
    "Authenticated account": "This conceptual pivot assumes legitimate authentication has already occurred; the assessment did not attempt account compromise.",
    "Sensitive records": "Potential confidentiality impact depends on authorization boundaries and data accessible to the affected account.",
    "Account actions": "Potential integrity impact depends on privileges and safeguards such as re-authentication and transaction confirmation."
  };
  $$(".attack-node").forEach(node => node.addEventListener("click", () => {
    $$(".attack-node").forEach(item => item.classList.toggle("active", item === node));
    $("#pathExplanation").replaceChildren(el("strong", "", node.dataset.node), el("p", "", pathCopy[node.dataset.node]));
  }));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !$("#findingDrawer").hidden) closeDrawer();
  });
}

/*
 * Future scanner adapter boundary:
 * An authorized scanner integration may implement normalize(raw): Finding[] and
 * metadata(): { name, version, importedAt }. Keep collection outside this static
 * application; adapters must only transform user-supplied exports and must never
 * initiate network probes. Validate normalized records before adding them here.
 *
 * class ScannerAdapter {
 *   normalize(rawExport) { throw new Error("Adapter must implement normalize"); }
 *   metadata() { return { name: "Unknown adapter", version: "0" }; }
 * }
 */

function initialize() {
  document.documentElement.classList.add("js");
  document.querySelector(".static-mode-note")?.remove();
  $("#snapshotDate").textContent = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date());
  initializeEvents();
  renderAll();
  const initial = location.hash.slice(1);
  if (["dashboard", "findings", "scope", "attack", "knowledge"].includes(initial)) switchView(initial);
}

initialize();