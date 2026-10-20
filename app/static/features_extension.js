/**
 * CCNS Advanced Feature Extensions
 * ================================
 * Implements:
 * 1. Interactive Adversarial Fuzzer Studio (live 5-class query mutation)
 * 2. Automated BOLA Remediation & Policy Code Generator (Strawberry, Shield, OPA)
 * 3. Multi-Tenant Access Matrix Simulator (interactive 2D cross-tenant grid)
 * 4. Real-Time Anomaly Stream & 1-Click Attack Replay
 * 5. ROC & Precision-Recall Curve Visualization (SVG Canvas)
 */

(function () {
  "use strict";

  function $(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // =========================================================================
  // 1. INTERACTIVE ADVERSARIAL FUZZER STUDIO
  // =========================================================================
  window.openFuzzerStudio = async function () {
    const modal = $("modal-fuzzer");
    if (!modal) return;
    modal.classList.add("active");

    const queryInput = typeof getQueryContent === "function" ? getQueryContent() : ($("native-query-input") ? $("native-query-input").value : "");
    const targetId = $("target-id-input") && $("target-id-input").value ? parseInt($("target-id-input").value, 10) : 101;

    $("fuzzer-base-query-display").textContent = queryInput || "query { resource(id: 101) { id name secret_key } }";
    await generateFuzzerVariants(queryInput, targetId);
  };

  window.closeFuzzerStudio = function () {
    const modal = $("modal-fuzzer");
    if (modal) modal.classList.remove("active");
  };

  async function generateFuzzerVariants(query, targetId) {
    const container = $("fuzzer-variants-container");
    if (!container) return;
    container.innerHTML = `<div style="text-align:center;padding:30px;color:var(--text-muted)"><span class="spinner-sm"></span> Synthesizing 5 adversarial query variants...</div>`;

    try {
      const res = await fetch("/api/v1/research/fuzzer/mutate-query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query || "query { resource(id: 101) { id name secret_key } }", target_id: targetId || 101 })
      });
      if (!res.ok) throw new Error("Fuzzer mutation failed");
      const data = await res.json();
      const variants = data.variants || [];

      container.innerHTML = variants.map((v, idx) => `
        <div class="detail-card" style="margin-bottom:12px;background:var(--bg-card);border:1px solid var(--border-base)">
          <div class="detail-card-head" style="display:flex;justify-content:space-between;align-items:center">
            <div style="display:flex;align-items:center;gap:8px">
              <span class="pill-badge warning">${idx + 1}. ${esc(v.mutation_class)}</span>
              <span style="font-weight:700;color:var(--text-primary)">${esc(v.title)}</span>
            </div>
            <div style="display:flex;gap:8px">
              <button class="btn-secondary" style="padding:3px 10px;font-size:11px" onclick="loadFuzzedVariantToEditor(${idx})">Load in Editor</button>
              <button class="btn-run-primary" style="padding:3px 10px;font-size:11px" onclick="runFuzzedVariantDirect(${idx})">Run Test</button>
            </div>
          </div>
          <div class="detail-card-body" style="padding:10px 14px">
            <p style="font-size:11.5px;color:var(--text-secondary);margin:0 0 8px 0">${esc(v.description)}</p>
            <pre class="code-block" style="max-height:100px;font-size:11px">${esc(v.fuzzed_query)}</pre>
          </div>
        </div>
      `).join("");

      window._activeFuzzedVariants = variants;
    } catch (err) {
      container.innerHTML = `<div style="color:var(--rose-400);padding:20px">Error generating fuzzed variants: ${err.message}</div>`;
    }
  }

  window.loadFuzzedVariantToEditor = function (idx) {
    const v = (window._activeFuzzedVariants || [])[idx];
    if (!v) return;
    if (typeof setEditorContent === "function") {
      setEditorContent(v.fuzzed_query);
    } else if ($("native-query-input")) {
      $("native-query-input").value = v.fuzzed_query;
    }
    if (v.variables && Object.keys(v.variables).length > 0 && $("native-vars-input")) {
      $("native-vars-input").value = JSON.stringify(v.variables, null, 2);
    }
    closeFuzzerStudio();
    if (typeof notify === "function") notify(`Loaded adversarial mutation: ${v.title}`);
  };

  window.runFuzzedVariantDirect = async function (idx) {
    loadFuzzedVariantToEditor(idx);
    if (typeof executeWorkbench === "function") {
      await executeWorkbench();
    }
  };

  // =========================================================================
  // 2. AUTOMATED BOLA REMEDIATION CODE GENERATOR
  // =========================================================================
  window.openRemediationModal = async function () {
    const modal = $("modal-remediation");
    if (!modal) return;
    modal.classList.add("active");

    const targetType = "Resource";
    const fieldName = "secret_key";

    try {
      const res = await fetch("/api/v1/security/remediation/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_type: targetType, field_name: fieldName, owner_field: "owner_id", is_sensitive: true })
      });
      if (!res.ok) throw new Error("Failed to generate remediation");
      const data = await res.json();
      window._activeRemediation = data;

      if ($("remediation-target-pill")) $("remediation-target-pill").textContent = `${data.target_type}.${data.field_name}`;
      if ($("remediation-summary-text")) $("remediation-summary-text").textContent = data.mitigation_summary;

      switchRemediationTab("strawberry");
    } catch (err) {
      alert("Error generating remediation: " + err.message);
    }
  };

  window.closeRemediationModal = function () {
    const modal = $("modal-remediation");
    if (modal) modal.classList.remove("active");
  };

  window.switchRemediationTab = function (tabKey) {
    const data = window._activeRemediation;
    if (!data) return;

    document.querySelectorAll(".remediation-tab-btn").forEach(b => {
      b.classList.toggle("active", b.dataset.tab === tabKey);
    });

    const codeEl = $("remediation-code-block");
    if (!codeEl) return;

    if (tabKey === "strawberry") {
      codeEl.textContent = data.strawberry_python;
    } else if (tabKey === "shield") {
      codeEl.textContent = data.graphql_shield_ts;
    } else if (tabKey === "opa") {
      codeEl.textContent = data.opa_rego;
    }
  };

  window.copyRemediationCode = function () {
    const codeEl = $("remediation-code-block");
    if (codeEl) {
      navigator.clipboard.writeText(codeEl.textContent).then(() => {
        if (typeof notify === "function") notify("Remediation policy copied to clipboard!");
        else alert("Remediation policy copied!");
      });
    }
  };

  // =========================================================================
  // 3. MULTI-TENANT ISOLATION MATRIX SIMULATOR
  // =========================================================================
  window.openTenantMatrixModal = async function () {
    const modal = $("modal-tenant-matrix");
    if (!modal) return;
    modal.classList.add("active");

    const tbody = $("tenant-matrix-tbody");
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:24px"><span class="spinner-sm"></span> Loading cross-tenant authorization matrix...</td></tr>`;

    try {
      const res = await fetch("/api/v1/security/multi-tenant-matrix");
      if (!res.ok) throw new Error("Failed to load multi-tenant matrix");
      const data = await res.json();

      tbody.innerHTML = data.matrix.map(row => {
        const p = row.principal;
        const pBadge = p.role === "ADMIN" ? "info" : (p.tenant === "Alpha" ? "emerald" : (p.tenant === "Beta" ? "purple" : "neutral"));
        const cellsHtml = row.cells.map(c => {
          const isAllowed = c.decision === "ALLOW";
          const cellClass = isAllowed ? "background:rgba(16,185,129,0.15);color:var(--emerald-400);border:1px solid rgba(16,185,129,0.3)" : "background:rgba(244,63,94,0.15);color:var(--rose-400);border:1px solid rgba(244,63,94,0.3)";
          const label = isAllowed ? "ALLOW (200)" : `BLOCKED (${c.gateway_status})`;
          return `
            <td style="text-align:center;padding:8px">
              <button onclick="testMatrixCell('${p.id || ''}', '${p.role}', ${c.resource_id})" style="border-radius:var(--radius-sm);padding:4px 8px;font-size:10.5px;font-weight:700;font-family:var(--font-mono);cursor:pointer;${cellClass}">
                ${label}<br><span style="font-size:9.5px;opacity:0.85">${c.reason}</span>
              </button>
            </td>
          `;
        }).join("");

        return `
          <tr>
            <td style="font-weight:600;padding:10px 14px">
              <span class="pill-badge ${pBadge}" style="margin-right:6px">${p.tenant}</span>
              ${esc(p.label)}
            </td>
            ${cellsHtml}
          </tr>
        `;
      }).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" style="color:var(--rose-400);padding:14px">Error: ${err.message}</td></tr>`;
    }
  };

  window.closeTenantMatrixModal = function () {
    const modal = $("modal-tenant-matrix");
    if (modal) modal.classList.remove("active");
  };

  window.testMatrixCell = function (userId, role, resourceId) {
    closeTenantMatrixModal();
    if ($("caller-identity-select") && userId) {
      $("caller-identity-select").value = userId;
    }
    if ($("target-id-input")) {
      $("target-id-input").value = resourceId;
    }
    const query = `query GetResource {\n  resource(id: ${resourceId}) {\n    id\n    name\n    secretKey\n  }\n}`;
    if (typeof setEditorContent === "function") {
      setEditorContent(query);
    } else if ($("native-query-input")) {
      $("native-query-input").value = query;
    }
    if (typeof notify === "function") notify(`Testing Principal ${userId || 'Anon'} against Resource ${resourceId}`);
    if (typeof executeWorkbench === "function") {
      executeWorkbench();
    }
  };

  // =========================================================================
  // 4. REAL-TIME ANOMALY & ATTACK STREAM
  // =========================================================================
  let _lastSeenEventId = 0;
  let _liveStreamInterval = null;

  window.initLiveAnomalyStream = function () {
    if (_liveStreamInterval) clearInterval(_liveStreamInterval);
    _liveStreamInterval = setInterval(pollLiveEvents, 5000);
    pollLiveEvents();
  };

  async function pollLiveEvents() {
    try {
      const res = await fetch(`/api/v1/security/live-events?since_id=${_lastSeenEventId}&limit=5`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.latest_id > _lastSeenEventId) {
        if (_lastSeenEventId > 0 && data.events && data.events.length > 0) {
          data.events.forEach(ev => {
            if (ev.decision === "DENY" || ev.risk_level === "HIGH") {
              showAttackAlertToast(ev);
            }
          });
        }
        _lastSeenEventId = data.latest_id;
      }
    } catch (err) {
      // Quiet fail on stream polling
    }
  }

  function showAttackAlertToast(ev) {
    const container = $("toast-container") || createToastContainer();
    const toast = document.createElement("div");
    toast.className = "attack-alert-toast";
    toast.style.cssText = `
      background: var(--bg-surface);
      border: 1px solid var(--rose-500);
      box-shadow: 0 8px 24px rgba(244, 63, 94, 0.25);
      border-radius: var(--radius-md);
      padding: 12px 16px;
      margin-top: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      animation: slideInRight 0.25s ease-out;
      min-width: 320px;
      max-width: 440px;
    `;

    toast.innerHTML = `
      <div>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="pill-badge danger" style="font-size:9px">LIVE ATTACK</span>
          <span style="font-weight:700;font-size:12px;color:var(--text-primary)">BOLA Attempt Blocked</span>
        </div>
        <div style="font-size:11px;color:var(--text-secondary);margin-top:4px">
          Caller: <b>${ev.user_id || 'Anon'}</b> &rarr; Path: <code>${ev.graphql_path || 'resource'}</code> (Risk: ${ev.risk_score || 90}/100)
        </div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn-run-primary" style="padding:4px 8px;font-size:10.5px" onclick="replayAttackFromToast('${ev.graphql_path || 'resource'}', ${ev.object_id || 102}, '${ev.user_id || 101}', this)">Replay</button>
        <button class="btn-secondary" style="padding:4px 6px;font-size:10.5px" onclick="this.closest('.attack-alert-toast').remove()">&times;</button>
      </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 12000);
  }

  function createToastContainer() {
    const c = document.createElement("div");
    c.id = "toast-container";
    c.style.cssText = "position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;";
    document.body.appendChild(c);
    return c;
  }

  window.replayAttackFromToast = function (path, targetId, callerId, btnEl) {
    if (btnEl) btnEl.closest('.attack-alert-toast').remove();
    if (typeof navigateToView === "function") navigateToView("workbench");
    if ($("caller-identity-select") && callerId) $("caller-identity-select").value = callerId;
    if ($("target-id-input") && targetId) $("target-id-input").value = targetId;

    const query = `query ReplayedAttack {\n  ${path}(id: ${targetId}) {\n    id\n    name\n    secretKey\n  }\n}`;
    if (typeof setEditorContent === "function") setEditorContent(query);
    else if ($("native-query-input")) $("native-query-input").value = query;

    if (typeof notify === "function") notify(`Replaying attack: Caller ${callerId} -> ${path}(${targetId})`);
    if (typeof executeWorkbench === "function") executeWorkbench();
  };

  // =========================================================================
  // 5. INTERACTIVE ROC & PRECISION-RECALL CURVE VISUALIZER (SVG)
  // =========================================================================
  window.renderCurvesVisualization = async function (expId) {
    const container = $("research-curves-container");
    if (!container || !expId) return;

    try {
      const res = await fetch(`/api/v1/research/experiments/${expId}/curves`);
      if (!res.ok) return;
      const data = await res.json();
      const methods = data.methods || {};

      // Build SVG paths for ROC (FPR vs TPR)
      // ViewBox: 0 0 300 200, Margin: 30, W=240, H=140
      function toRocCoords(fpr, tpr) {
        const x = 40 + fpr * 240;
        const y = 170 - tpr * 140;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }

      function toPrCoords(rec, prec) {
        const x = 40 + rec * 240;
        const y = 170 - prec * 140;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }

      let rocSvgLines = "";
      let prSvgLines = "";
      let legendsHtml = "";

      Object.values(methods).forEach(m => {
        const rocPath = m.roc_curve.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${toRocCoords(pt.fpr, pt.tpr)}`).join(" ");
        const prPath = m.pr_curve.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${toPrCoords(pt.recall, pt.precision)}`).join(" ");

        rocSvgLines += `<path d="${rocPath}" fill="none" stroke="${m.color}" stroke-width="2.5" />`;
        prSvgLines += `<path d="${prPath}" fill="none" stroke="${m.color}" stroke-width="2.5" />`;

        legendsHtml += `
          <div style="display:flex;align-items:center;gap:6px;font-size:11px">
            <span style="width:10px;height:10px;border-radius:2px;background:${m.color}"></span>
            <span style="color:var(--text-primary);font-weight:600">${esc(m.method_name.split(':')[0])}:</span>
            <span style="color:var(--text-secondary)">AUC-ROC: <b>${m.auc_roc}</b> | AUC-PR: <b>${m.auc_pr}</b></span>
          </div>
        `;
      });

      container.innerHTML = `
        <!-- ROC Curve -->
        <div style="background:var(--bg-app);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-weight:700;font-size:12px;color:var(--text-primary)">Receiver Operating Characteristic (ROC)</span>
            <span class="pill-badge emerald" style="font-size:9.5px">TPR vs FPR</span>
          </div>
          <svg viewBox="0 0 300 200" style="width:100%;height:180px;background:var(--bg-card);border-radius:var(--radius-sm)">
            <!-- Grid Lines -->
            <line x1="40" y1="30" x2="280" y2="30" stroke="rgba(255,255,255,0.05)" />
            <line x1="40" y1="100" x2="280" y2="100" stroke="rgba(255,255,255,0.05)" />
            <line x1="40" y1="170" x2="280" y2="170" stroke="rgba(255,255,255,0.2)" />
            <line x1="40" y1="30" x2="40" y2="170" stroke="rgba(255,255,255,0.2)" />
            <!-- Chance diagonal -->
            <line x1="40" y1="170" x2="280" y2="30" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4,4" />
            <!-- Axes Labels -->
            <text x="160" y="195" font-size="9" fill="var(--text-muted)" text-anchor="middle">False Positive Rate (FPR)</text>
            <text x="12" y="105" font-size="9" fill="var(--text-muted)" text-anchor="middle" transform="rotate(-90 12 105)">True Positive Rate (TPR)</text>
            <!-- Curves -->
            ${rocSvgLines}
          </svg>
        </div>

        <!-- Precision-Recall Curve -->
        <div style="background:var(--bg-app);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:14px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-weight:700;font-size:12px;color:var(--text-primary)">Precision-Recall Curve (PR)</span>
            <span class="pill-badge info" style="font-size:9.5px">Precision vs Recall</span>
          </div>
          <svg viewBox="0 0 300 200" style="width:100%;height:180px;background:var(--bg-card);border-radius:var(--radius-sm)">
            <!-- Grid Lines -->
            <line x1="40" y1="30" x2="280" y2="30" stroke="rgba(255,255,255,0.05)" />
            <line x1="40" y1="100" x2="280" y2="100" stroke="rgba(255,255,255,0.05)" />
            <line x1="40" y1="170" x2="280" y2="170" stroke="rgba(255,255,255,0.2)" />
            <line x1="40" y1="30" x2="40" y2="170" stroke="rgba(255,255,255,0.2)" />
            <!-- Axes Labels -->
            <text x="160" y="195" font-size="9" fill="var(--text-muted)" text-anchor="middle">Recall</text>
            <text x="12" y="105" font-size="9" fill="var(--text-muted)" text-anchor="middle" transform="rotate(-90 12 105)">Precision</text>
            <!-- Curves -->
            ${prSvgLines}
          </svg>
        </div>

        <!-- Shared Legend Row -->
        <div style="grid-column:1 / -1;display:flex;justify-content:space-around;flex-wrap:wrap;gap:12px;padding:8px 12px;background:var(--bg-card);border-radius:var(--radius-sm)">
          ${legendsHtml}
        </div>
      `;
    } catch (err) {
      console.error("[Research Lab] Failed to render discrimination curves:", err);
    }
  };

  // Auto-start live anomaly monitor on page load
  window.addEventListener("DOMContentLoaded", () => {
    initLiveAnomalyStream();
    const btnFuzzer = $("btn-open-fuzzer");
    if (btnFuzzer) btnFuzzer.addEventListener("click", openFuzzerStudio);
    const btnRemediation = $("btn-open-remediation");
    if (btnRemediation) btnRemediation.addEventListener("click", openRemediationModal);
    const btnMatrix = $("btn-open-matrix");
    if (btnMatrix) btnMatrix.addEventListener("click", openTenantMatrixModal);
  });

})();
