(function () {
  "use strict";

  const bootstrap = window.__SECUREPATH_BOOTSTRAP__ || {};
  const scanId = bootstrap.scanId;
  if (!scanId) {
    return;
  }

  const state = {
    status: bootstrap.initialStatus || "queued",
    findingsMap: new Map(),
    findingsList: [],
    liveFeedSeen: new Set(),
    sortKey: "severity",
    sortAsc: false,
    activeFindingId: null,
    pollTimer: null,
    startedAt: bootstrap.createdAt ? new Date(bootstrap.createdAt) : null,
    progress: Number(bootstrap.initialProgress || 0),
  };

  const el = {
    scanningPane: document.getElementById("state-scanning"),
    completePane: document.getElementById("state-complete"),
    errorPane: document.getElementById("state-error"),
    errorMessage: document.getElementById("error-message"),
    progressBar: document.getElementById("progress-bar"),
    stepLabel: document.getElementById("step-label"),
    statusBadge: document.getElementById("status-badge"),
    liveFeedList: document.getElementById("live-feed-list"),
    waitingFeed: document.getElementById("waiting-feed"),
    findingsBody: document.getElementById("findings-body"),
    findingsTable: document.getElementById("findings-table"),
    riskScore: document.getElementById("risk-score"),
    countCritical: document.getElementById("count-critical"),
    countHigh: document.getElementById("count-high"),
    countMedium: document.getElementById("count-medium"),
    countLow: document.getElementById("count-low"),
    totalInline: document.getElementById("total-inline"),
    durationInline: document.getElementById("duration-inline"),
    metaSha: document.getElementById("meta-sha"),
    shaInline: document.getElementById("sha-inline"),
    owaspGrid: document.getElementById("owasp-grid"),
  };

  const severityRank = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  function setVisible(pane) {
    const panes = [el.scanningPane, el.completePane, el.errorPane];
    panes.forEach((p) => p && p.classList.add("hidden"));
    if (pane) {
      pane.classList.remove("hidden");
    }
  }

  function sanitize(text) {
    if (text === null || text === undefined) {
      return "";
    }
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function statusClass(status) {
    const s = String(status || "").toLowerCase();
    if (s === "failed") return "critical";
    if (s === "complete") return "low";
    if (s === "generating" || s === "enriching") return "high";
    return "medium";
  }

  function severityColorClass(sev) {
    const s = String(sev || "info").toLowerCase();
    return ["critical", "high", "medium", "low", "info"].includes(s) ? s : "info";
  }

  function parseSoc2(controls) {
    if (Array.isArray(controls)) {
      return controls.map((x) => String(x).trim()).filter(Boolean);
    }
    if (typeof controls === "string") {
      return controls.split(",").map((x) => x.trim()).filter(Boolean);
    }
    return [];
  }

  function parseRemediation(finding) {
    if (Array.isArray(finding.remediation)) {
      return finding.remediation;
    }
    if (typeof finding.remediation_json === "string" && finding.remediation_json.trim()) {
      try {
        const parsed = JSON.parse(finding.remediation_json);
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        return [];
      }
    }
    return [];
  }

  function parseJsonField(finding, field) {
    const val = finding[field];
    if (val && typeof val === "object" && !Array.isArray(val)) return val;
    if (typeof val === "string" && val.trim()) {
      try {
        const parsed = JSON.parse(val);
        return (parsed && typeof parsed === "object") ? parsed : {};
      } catch (e) {
        return {};
      }
    }
    return {};
  }

  function formatDuration() {
    if (!state.startedAt || Number.isNaN(state.startedAt.getTime())) {
      return "n/a";
    }
    const end = new Date();
    let diff = Math.max(0, Math.floor((end.getTime() - state.startedAt.getTime()) / 1000));
    const m = Math.floor(diff / 60);
    const s = diff % 60;
    return `${m}m ${s}s`;
  }

  function updateStatusBadge(status) {
    if (!el.statusBadge) return;
    el.statusBadge.textContent = status;
    el.statusBadge.className = `status-badge ${statusClass(status)}`;
    if (status !== "complete" && status !== "failed") {
      el.statusBadge.classList.add("pulsing");
    }
  }

  function updateProgress(progress, step) {
    if (el.progressBar) {
      el.progressBar.style.width = `${Math.max(0, Math.min(100, Number(progress) || 0))}%`;
    }
    if (el.stepLabel) {
      el.stepLabel.textContent = step || "Processing...";
    }
  }

  function appendLiveFinding(finding) {
    if (!el.liveFeedList || !finding || !finding.id) return;
    if (state.liveFeedSeen.has(finding.id)) return;
    state.liveFeedSeen.add(finding.id);

    if (el.waitingFeed) {
      el.waitingFeed.remove();
    }

    const row = document.createElement("div");
    row.className = "live-item";
    row.innerHTML = `
      <span class="severity-chip ${severityColorClass(finding.severity)}">${sanitize(finding.severity || "info")}</span>
      <div>
        <div class="title">${sanitize(finding.raw_title || "Untitled finding")}</div>
        <div class="location">${sanitize(finding.file_path || "unknown file")}:${sanitize(finding.line_start || "?")}</div>
      </div>
      <span class="tiny-muted">EXAI</span>
    `;
    el.liveFeedList.prepend(row);
  }

  function applyMetrics(counts, risk, total) {
    const critical = Number(counts.critical || 0);
    const high = Number(counts.high || 0);
    const medium = Number(counts.medium || 0);
    const low = Number(counts.low || 0);
    const score = Number(risk || 0);

    if (el.countCritical) el.countCritical.textContent = String(critical);
    if (el.countHigh) el.countHigh.textContent = String(high);
    if (el.countMedium) el.countMedium.textContent = String(medium);
    if (el.countLow) el.countLow.textContent = String(low);
    if (el.totalInline) el.totalInline.textContent = String(total || 0);
    if (el.riskScore) {
      el.riskScore.textContent = String(score);
      if (score <= 30) el.riskScore.style.color = "#34c759";
      else if (score <= 60) el.riskScore.style.color = "#ffd60a";
      else if (score <= 80) el.riskScore.style.color = "#ff9f0a";
      else el.riskScore.style.color = "#ff2d55";
    }
    if (el.durationInline) {
      el.durationInline.textContent = formatDuration();
    }
  }

  function updateOwaspCoverage(findings) {
    if (!el.owaspGrid) return;
    const present = new Set(
      findings.map((f) => String(f.owasp_category || "").trim()).filter(Boolean)
    );
    const boxes = el.owaspGrid.querySelectorAll(".owasp-box");
    boxes.forEach((box) => {
      const cat = box.getAttribute("data-cat") || "";
      if (present.has(cat)) {
        box.classList.add("found");
      } else {
        box.classList.remove("found");
      }
    });
  }

  function compareFindings(a, b, key, asc) {
    let av = a[key];
    let bv = b[key];
    if (key === "severity") {
      av = severityRank[String(a.severity || "info").toLowerCase()] ?? 0;
      bv = severityRank[String(b.severity || "info").toLowerCase()] ?? 0;
    } else if (key === "confidence_score" || key === "line_start") {
      av = Number(av || 0);
      bv = Number(bv || 0);
    } else {
      av = String(av || "").toLowerCase();
      bv = String(bv || "").toLowerCase();
    }

    if (av < bv) return asc ? -1 : 1;
    if (av > bv) return asc ? 1 : -1;
    return 0;
  }

  function sortedFindings() {
    return [...state.findingsList].sort((a, b) =>
      compareFindings(a, b, state.sortKey, state.sortAsc)
    );
  }

  function confidenceCell(score) {
    const n = Math.max(0, Math.min(10, Number(score || 0)));
    return `
      <span class="confidence-wrap">
        <span>${n}/10</span>
        <span class="confidence-bar"><span style="width:${n * 10}%"></span></span>
      </span>
    `;
  }

  function rowMarkup(f) {
    const sev = String(f.severity || "info").toLowerCase();
    return `
      <tr class="finding-row" data-finding-id="${sanitize(f.id)}">
        <td><span class="severity-chip ${severityColorClass(sev)}">${sanitize(sev)}</span></td>
        <td>${sanitize(f.category || "")}</td>
        <td class="mono">${sanitize(f.file_path || "")}</td>
        <td>${sanitize(f.line_start || "")}</td>
        <td>${sanitize(f.raw_title || "")}</td>
        <td>${sanitize((f.soc2_controls || "").toString())}</td>
        <td>${confidenceCell(f.confidence_score)}</td>
      </tr>
    `;
  }

  function expandedPanelMarkup(finding) {
    const controls = parseSoc2(finding.soc2_controls);
    const remediation = parseRemediation(finding);
    const fpRisk = String(finding.false_positive_risk || "medium").toUpperCase();
    const bi = parseJsonField(finding, "business_impact_json") || parseJsonField(finding, "business_impact");
    const ae = parseJsonField(finding, "assets_exposed_json") || parseJsonField(finding, "assets_exposed");

    const remediationCards = remediation.length
      ? remediation
          .map((opt, idx) => {
            const label = sanitize(opt.label || `Option ${idx + 1}`);
            const estimate = sanitize(opt.time_estimate || "");
            const desc = sanitize(opt.description || "");
            const tradeoff = sanitize(opt.tradeoff || "");
            const copyText = sanitize((opt.description || "").replace(/"/g, "&quot;"));
            return `
              <article class="remediation-option">
                <h4>OPTION ${sanitize(opt.rank || idx + 1)}: ${label}<span>${estimate}</span></h4>
                <p>${desc}</p>
                <small>${tradeoff}</small>
                <button class="copy-btn" data-copy="${copyText}">Copy fix</button>
              </article>
            `;
          })
          .join("")
      : '<div class="tiny-muted">No remediation details available.</div>';

    // Business Impact tab content
    const biFinancial = sanitize(bi.financial_exposure || "Financial exposure data unavailable.");
    const biLikelihood = sanitize(bi.exploitation_likelihood || "unknown");
    const biReason = sanitize(bi.likelihood_reason || "");
    const biViolations = Array.isArray(bi.compliance_violations) ? bi.compliance_violations : [];
    const biViolationsHtml = biViolations.length
      ? `<table style="width:100%;border-collapse:collapse;font-size:0.78rem;margin-top:6px">
           <thead><tr style="border-bottom:1px solid var(--border)">
             <th style="text-align:left;padding:4px 6px;color:var(--text-secondary)">Framework</th>
             <th style="text-align:left;padding:4px 6px;color:var(--text-secondary)">Control</th>
             <th style="text-align:left;padding:4px 6px;color:var(--text-secondary)">Implication</th>
           </tr></thead>
           <tbody>${biViolations.map(v => `<tr style="border-bottom:1px solid var(--border)">
             <td style="padding:4px 6px">${sanitize(v.framework || "")}</td>
             <td style="padding:4px 6px;font-weight:700">${sanitize(v.control || "")}</td>
             <td style="padding:4px 6px;color:var(--text-secondary)">${sanitize(v.meaning || "")}</td>
           </tr>`).join("")}</tbody></table>`
      : '<div class="tiny-muted">No violations mapped.</div>';

    // Assets Exposed tab content
    const aeDataTypes = Array.isArray(ae.data_types) ? ae.data_types : [];
    const aeSystems = Array.isArray(ae.systems_affected) ? ae.systems_affected : [];
    const aeScope = sanitize(ae.exposure_scope || "unknown");
    const aeExplanation = sanitize(ae.exposure_explanation || "");
    const aeRecords = sanitize(ae.estimated_records_at_risk || "unknown");

    const dataTypeTags = aeDataTypes.length
      ? aeDataTypes.map(dt => `<span class="ctl">${sanitize(dt)}</span>`).join("")
      : '<span class="tiny-muted">No data types identified</span>';

    const systemsList = aeSystems.length
      ? aeSystems.map(s => `<div style="margin:2px 0;font-size:0.82rem">· ${sanitize(s)}</div>`).join("")
      : '<div class="tiny-muted">No systems identified</div>';

    return `
      <div class="exai-panel" data-panel-for="${sanitize(finding.id)}">
        <div class="tabs">
          <button class="tab-btn active" data-tab="overview">Overview</button>
          <button class="tab-btn" data-tab="impact">Business Impact</button>
          <button class="tab-btn" data-tab="assets">Assets Exposed</button>
          <button class="tab-btn" data-tab="remediation">Remediation</button>
          <button class="tab-btn" data-tab="compliance">Compliance</button>
          <button class="tab-btn" data-tab="raw">Raw</button>
        </div>

        <div class="tab-pane active" data-pane="overview">
          <div class="overview-grid">
            <div class="overview-card">
              <h4>FINDING EXPLANATION</h4>
              <p>${sanitize(finding.plain_english || "No explanation available.")}</p>
            </div>
            <div class="overview-card risk">
              <h4>BUSINESS RISK</h4>
              <p>${sanitize(finding.business_risk || "No business risk narrative available.")}</p>
            </div>
            <div class="overview-card exploit">
              <h4>EXPLOIT SCENARIO</h4>
              <p>${sanitize(finding.exploit_scenario || "No exploit scenario available.")}</p>
            </div>
          </div>
        </div>

        <div class="tab-pane" data-pane="impact">
          <div class="overview-grid">
            <div class="overview-card risk">
              <h4>FINANCIAL EXPOSURE</h4>
              <p>${biFinancial}</p>
            </div>
            <div class="overview-card">
              <h4>EXPLOITATION LIKELIHOOD</h4>
              <p><span class="severity-chip ${biLikelihood === 'high' ? 'critical' : biLikelihood === 'medium' ? 'medium' : 'low'}" style="margin-right:8px">${biLikelihood.toUpperCase()}</span>${biReason}</p>
            </div>
            <div class="overview-card">
              <h4>COMPLIANCE VIOLATIONS</h4>
              ${biViolationsHtml}
            </div>
          </div>
        </div>

        <div class="tab-pane" data-pane="assets">
          <div class="overview-grid">
            <div class="overview-card">
              <h4>DATA TYPES AT RISK</h4>
              <div class="controls-wrap" style="margin-top:4px">${dataTypeTags}</div>
            </div>
            <div class="overview-card">
              <h4>SYSTEMS AFFECTED</h4>
              ${systemsList}
            </div>
            <div class="overview-card">
              <h4>EXPOSURE SCOPE</h4>
              <p><span class="severity-chip ${aeScope === 'external_facing' ? 'critical' : aeScope === 'third_party_accessible' ? 'medium' : 'low'}">${aeScope.replace(/_/g, ' ').toUpperCase()}</span></p>
            </div>
            <div class="overview-card">
              <h4>EXPOSURE DETAIL</h4>
              <p>${aeExplanation}</p>
              ${aeRecords !== 'unknown' ? `<p style="margin-top:4px;color:var(--text-secondary);font-size:0.8rem">Estimated records at risk: <b>${aeRecords}</b></p>` : ''}
            </div>
          </div>
        </div>

        <div class="tab-pane" data-pane="remediation">
          <div class="remediation-grid">${remediationCards}</div>
        </div>

        <div class="tab-pane" data-pane="compliance">
          <div class="compliance-grid">
            <div><b>Relevant Compliance Controls:</b></div>
            <div class="controls-wrap">
              ${
                controls.length
                  ? controls.map((ctl) => `<span class="ctl">${sanitize(ctl)}</span>`).join("")
                  : '<span class="tiny-muted">No controls mapped</span>'
              }
            </div>
            <div><b>CWE:</b> ${sanitize(finding.cwe_id || "Unknown")}</div>
            <div><b>OWASP:</b> ${sanitize(finding.owasp_category || "Unknown")}</div>
            <div><b>Confidence:</b> ${sanitize(finding.confidence_score || 0)}/10</div>
            <div><b>False positive risk:</b> ${sanitize(fpRisk)}</div>
            <div class="tiny-muted">${sanitize(finding.false_positive_reason || "")}</div>
          </div>
        </div>

        <div class="tab-pane" data-pane="raw">
          <div class="raw-box">
            <div class="tiny-muted mono">${sanitize(finding.file_path || "")}:${sanitize(finding.line_start || "")}-${sanitize(finding.line_end || "")}</div>
            <pre><code>${sanitize(finding.code_snippet || "No snippet available.")}</code></pre>
          </div>
        </div>
      </div>
    `;
  }

  function renderFindingsTable() {
    if (!el.findingsBody) return;
    const findings = sortedFindings();
    const html = findings.map((f) => rowMarkup(f)).join("");
    el.findingsBody.innerHTML = html;

    if (state.activeFindingId) {
      const row = el.findingsBody.querySelector(`tr[data-finding-id="${CSS.escape(state.activeFindingId)}"]`);
      if (row) {
        expandRow(row, state.activeFindingId);
      } else {
        state.activeFindingId = null;
      }
    }
  }

  function closeAllExpanded() {
    const openRows = el.findingsBody.querySelectorAll("tr.expanded-row");
    openRows.forEach((r) => r.remove());
    state.activeFindingId = null;
  }

  function bindTabs(panel) {
    const buttons = panel.querySelectorAll(".tab-btn");
    const panes = panel.querySelectorAll(".tab-pane");
    buttons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const tab = btn.getAttribute("data-tab");
        buttons.forEach((b) => b.classList.remove("active"));
        panes.forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const pane = panel.querySelector(`.tab-pane[data-pane="${tab}"]`);
        if (pane) pane.classList.add("active");
      });
    });
  }

  function bindCopyButtons(panel) {
    panel.querySelectorAll(".copy-btn").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const text = btn.getAttribute("data-copy") || "";
        try {
          await navigator.clipboard.writeText(text);
          const original = btn.textContent;
          btn.textContent = "Copied!";
          btn.classList.add("copied");
          setTimeout(() => {
            btn.textContent = original;
            btn.classList.remove("copied");
          }, 2000);
        } catch (err) {
          btn.textContent = "Copy failed";
          setTimeout(() => {
            btn.textContent = "Copy fix";
          }, 1200);
        }
      });
    });
  }

  function expandRow(row, findingId) {
    closeAllExpanded();
    const finding = state.findingsMap.get(findingId);
    if (!finding) return;

    const expanded = document.createElement("tr");
    expanded.className = "expanded-row";
    const td = document.createElement("td");
    td.colSpan = 7;
    td.innerHTML = expandedPanelMarkup(finding);
    expanded.appendChild(td);
    row.insertAdjacentElement("afterend", expanded);
    state.activeFindingId = findingId;

    const panel = td.querySelector(".exai-panel");
    if (panel) {
      bindTabs(panel);
      bindCopyButtons(panel);
    }
  }

  function bindTableInteractions() {
    if (!el.findingsTable) return;
    const headerCells = el.findingsTable.querySelectorAll("thead th[data-sort]");
    headerCells.forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.getAttribute("data-sort");
        if (!key) return;
        if (state.sortKey === key) {
          state.sortAsc = !state.sortAsc;
        } else {
          state.sortKey = key;
          state.sortAsc = key !== "severity";
        }
        renderFindingsTable();
      });
    });

    el.findingsBody.addEventListener("click", (event) => {
      const row = event.target.closest("tr.finding-row");
      if (!row) return;
      const findingId = row.getAttribute("data-finding-id");
      if (!findingId) return;
      if (state.activeFindingId === findingId) {
        closeAllExpanded();
      } else {
        expandRow(row, findingId);
      }
    });
  }

  function mergeFindings(newFindings) {
    if (!Array.isArray(newFindings)) return;
    newFindings.forEach((f) => {
      if (!f || !f.id) return;
      const old = state.findingsMap.get(f.id) || {};
      const merged = { ...old, ...f };
      state.findingsMap.set(f.id, merged);
      appendLiveFinding(merged);
    });
    state.findingsList = Array.from(state.findingsMap.values());
  }

  function updateShaDisplay(data) {
    const sha = String(data.commit_sha || bootstrap.commitSha || "").slice(0, 12) || "pending";
    if (el.metaSha) el.metaSha.textContent = sha;
    if (el.shaInline) el.shaInline.textContent = sha;
  }

  function renderByStatus(status, data) {
    const s = String(status || "").toLowerCase();
    if (s === "failed") {
      setVisible(el.errorPane);
      if (el.errorMessage) {
        el.errorMessage.textContent = data.current_step || "Scan failed. Please try another repository.";
      }
      return;
    }
    if (s === "complete") {
      setVisible(el.completePane);
      return;
    }
    setVisible(el.scanningPane);
  }

  async function pollStatus() {
    try {
      const response = await fetch(`/api/scan/${encodeURIComponent(scanId)}/status`, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Status request failed (${response.status})`);
      }
      const data = await response.json();
      state.status = String(data.status || state.status);
      state.progress = Number(data.progress || state.progress || 0);

      updateStatusBadge(state.status);
      updateProgress(state.progress, data.current_step || "");
      updateShaDisplay(data);
      mergeFindings(data.findings || []);
      applyMetrics(data.counts || {}, data.risk_score || 0, data.total_findings || state.findingsList.length);
      updateOwaspCoverage(state.findingsList);
      renderFindingsTable();
      renderByStatus(state.status, data);

      if (state.status === "complete" || state.status === "failed") {
        stopPolling();
      }
    } catch (error) {
      setVisible(el.errorPane);
      if (el.errorMessage) {
        el.errorMessage.textContent = `Unable to retrieve scan status: ${error.message}`;
      }
      stopPolling();
    }
  }

  function startPolling() {
    stopPolling();
    pollStatus();
    state.pollTimer = window.setInterval(pollStatus, 2000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function bootstrapInitial() {
    updateProgress(bootstrap.initialProgress || 0, bootstrap.initialStep || "Initializing scan...");
    updateStatusBadge(bootstrap.initialStatus || "queued");
    applyMetrics(bootstrap.counts || {}, bootstrap.riskScore || 0, bootstrap.totalFindings || 0);
    if (el.metaSha && bootstrap.commitSha) el.metaSha.textContent = String(bootstrap.commitSha).slice(0, 12);
    if (el.shaInline && bootstrap.commitSha) el.shaInline.textContent = String(bootstrap.commitSha).slice(0, 12);
    bindTableInteractions();
    renderByStatus(bootstrap.initialStatus || "queued", bootstrap);
  }

  window.addEventListener("beforeunload", stopPolling);

  bootstrapInitial();
  startPolling();
})();
