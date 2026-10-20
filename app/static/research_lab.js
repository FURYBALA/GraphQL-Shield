/**
 * CCNS Research Lab - Frontend Controller
 * =======================================
 * Manages experiment lifecycle, 7 sub-views, 10-node evidence explorer,
 * dataset review audit trails, and reproducible artifact downloads.
 */

(function () {
  "use strict";

  // --- Research Lab State ---
  const state = {
    activeExperimentId: null,
    activeDatasetId: "ds_benchmark_v1",
    activeSubTab: "overview",
    activeCaseId: "CORPUS-001",
    activeMethodId: "method_correlated",
    activeEvidenceGraph: null,
    selectedNodeIdx: 0,
    experimentsList: [],
    datasetsList: [],
    currentComparisonData: null,
    currentAblationsData: null,
    currentErrorsData: null,
    currentCasesData: [],
  };

  // Helper selector
  const $ = (id) => document.getElementById(id);

  // Initialize Research Lab
  window.initResearchLab = async function () {
    console.log("[Research Lab] Initializing...");
    await loadInitialData();
  };

  async function loadInitialData() {
    try {
      // 1. Fetch datasets
      const dsRes = await fetch("/api/v1/research/datasets");
      if (dsRes.ok) {
        state.datasetsList = await dsRes.json();
        renderDatasetDropdown();
      }

      // 2. Fetch experiments
      const expRes = await fetch("/api/v1/research/experiments");
      if (expRes.ok) {
        state.experimentsList = await expRes.json();
        renderExperimentDropdown();
        if (state.experimentsList.length > 0) {
          const withAbl = state.experimentsList.find(e => e.manifest && e.manifest.methods_evaluated && e.manifest.methods_evaluated.length > 3) ||
                          state.experimentsList[0];
          state.activeExperimentId = withAbl.id;
        }
      }

      // 3. If no experiment exists yet, trigger baseline experiment
      if (!state.activeExperimentId) {
        console.log("[Research Lab] No existing experiments found. Launching initial baseline...");
        await launchExperimentDirectly();
      } else {
        await switchSubTab(state.activeSubTab);
      }
    } catch (err) {
      console.error("[Research Lab] Initialization failed:", err);
    }
  }

  function renderDatasetDropdown() {
    const sel = $("research-dataset-select");
    if (!sel) return;
    sel.innerHTML = state.datasetsList.map(d => `<option value="${d.id}">${d.name} (${d.total_cases} cases)</option>`).join("");
    sel.value = state.activeDatasetId;
    sel.onchange = (e) => {
      state.activeDatasetId = e.target.value;
      if (state.activeSubTab === "dataset") loadDatasetTab();
    };
  }

  function renderExperimentDropdown() {
    const sel = $("research-exp-select");
    if (!sel) return;
    if (state.experimentsList.length === 0) {
      sel.innerHTML = `<option value="">No Experiments</option>`;
      return;
    }
    sel.innerHTML = state.experimentsList.map(e => `<option value="${e.id}">${e.name} (${e.id})</option>`).join("");
    if (state.activeExperimentId) sel.value = state.activeExperimentId;
    sel.onchange = async (e) => {
      state.activeExperimentId = e.target.value;
      await switchSubTab(state.activeSubTab);
    };
  }

  // Subtab switching
  window.switchResearchSubTab = async function (tabKey) {
    state.activeSubTab = tabKey;
    document.querySelectorAll(".research-tab-btn").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.rtab === tabKey);
    });
    document.querySelectorAll(".research-tab-content").forEach(el => {
      el.classList.toggle("active", el.id === `rtab-content-${tabKey}`);
    });

    switch (tabKey) {
      case "overview":
        await loadOverviewTab();
        break;
      case "comparison":
        await loadComparisonTab();
        break;
      case "ablations":
        await loadAblationsTab();
        break;
      case "errors":
        await loadErrorsTab();
        break;
      case "dataset":
        await loadDatasetTab();
        break;
      case "evidence":
        await loadEvidenceTab();
        break;
      case "reports":
        await loadReportsTab();
        break;
      case "generalization":
        await loadGeneralizationTab();
        break;
    }
  };

  async function switchSubTab(tabKey) {
    await window.switchResearchSubTab(tabKey);
  }

  // =============================================================================
  // 1. OVERVIEW TAB
  // =============================================================================
  async function loadOverviewTab() {
    if (!state.activeExperimentId) return;
    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}`);
      if (!res.ok) return;
      const exp = await res.json();

      const methodRuns = exp.method_runs || [];
      const staticRun = methodRuns.find(m => m.method_id === "method_static_taint");
      const gatewayRun = methodRuns.find(m => m.method_id === "method_runtime_gateway");
      const correlatedRun = methodRuns.find(m => m.method_id === "method_correlated");

      const fmtPct = (val) => val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : "N/A";

      // Populate KPI cards
      if ($("kpi-cases-count")) {
        const total = correlatedRun ? correlatedRun.metrics.total_cases : 115;
        const excluded = correlatedRun ? correlatedRun.metrics.excluded_cases : 10;
        $("kpi-cases-count").textContent = `${total - excluded} / ${total}`;
      }
      if ($("kpi-static-f1") && staticRun) {
        $("kpi-static-f1").textContent = fmtPct(staticRun.metrics.f1_score);
        $("kpi-static-details").textContent = `P: ${fmtPct(staticRun.metrics.precision)} | R: ${fmtPct(staticRun.metrics.recall)}`;
      }
      if ($("kpi-gateway-f1") && gatewayRun) {
        $("kpi-gateway-f1").textContent = fmtPct(gatewayRun.metrics.f1_score);
        $("kpi-gateway-details").textContent = `P: ${fmtPct(gatewayRun.metrics.precision)} | R: ${fmtPct(gatewayRun.metrics.recall)}`;
      }
      if ($("kpi-correlated-f1") && correlatedRun) {
        $("kpi-correlated-f1").textContent = fmtPct(correlatedRun.metrics.f1_score);
        $("kpi-correlated-details").textContent = `P: ${fmtPct(correlatedRun.metrics.precision)} | R: ${fmtPct(correlatedRun.metrics.recall)}`;
      }

      // Populate Method Summary Table
      const tbody = $("research-overview-methods-body");
      if (tbody) {
        tbody.innerHTML = methodRuns.map(m => `
          <tr>
            <td style="font-weight:700">${m.method_name}</td>
            <td><span class="pill-badge neutral">${m.method_version}</span></td>
            <td>${m.metrics.evaluated_cases}</td>
            <td><strong style="color:var(--emerald-500)">${fmtPct(m.metrics.precision)}</strong></td>
            <td><strong style="color:var(--sky-500)">${fmtPct(m.metrics.recall)}</strong></td>
            <td><strong style="color:var(--emerald-500)">${fmtPct(m.metrics.f1_score)}</strong></td>
            <td>${fmtPct(m.metrics.accuracy)}</td>
            <td>${fmtPct(m.metrics.false_positive_rate)}</td>
            <td>${m.metrics.mean_latency_ms ? m.metrics.mean_latency_ms.toFixed(2) + " ms" : "N/A"}</td>
          </tr>
        `).join("");
      }

      // Populate Recent Experiments Table
      const expTbody = $("research-recent-experiments-body");
      if (expTbody) {
        expTbody.innerHTML = state.experimentsList.slice(0, 5).map(e => `
          <tr>
            <td><span style="font-family:var(--font-mono);font-weight:700">${e.id}</span></td>
            <td>${e.name}</td>
            <td><span class="pill-badge neutral">${e.dataset_id}</span></td>
            <td>${e.started_at.replace("T", " ").substring(0, 19)}</td>
            <td><span class="pill-badge success">COMPLETED</span></td>
            <td>
              <button class="btn-secondary" style="padding:2px 8px;font-size:11px" onclick="selectAndSwitchExperiment('${e.id}')">View</button>
            </td>
          </tr>
        `).join("");
      }
    } catch (err) {
      console.error("[Research Lab] Failed to load overview:", err);
    }
  }

  window.selectAndSwitchExperiment = async function (expId) {
    state.activeExperimentId = expId;
    renderExperimentDropdown();
    await switchSubTab("comparison");
  };

  // =============================================================================
  // 2. METHOD COMPARISON TAB
  // =============================================================================
  async function loadComparisonTab() {
    if (!state.activeExperimentId) return;
    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}/comparison`);
      if (!res.ok) return;
      const data = await res.json();
      state.currentComparisonData = data;

      const fmtPct = (val) => val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : "N/A";

      // 1. Comparative Matrix Table
      const tbody = $("research-comparison-table-body");
      if (tbody) {
        tbody.innerHTML = data.method_runs.map(mr => {
          const m = mr.metrics;
          const cm = mr.confusion_matrix;
          return `
            <tr>
              <td><strong>${mr.method_name}</strong></td>
              <td>${m.total_cases}</td>
              <td>${m.evaluated_cases}</td>
              <td>${m.excluded_cases}</td>
              <td><span style="color:var(--emerald-500);font-weight:700">${cm.tp}</span></td>
              <td><span style="color:var(--amber-500);font-weight:700">${cm.fp}</span></td>
              <td><span style="color:var(--sky-500);font-weight:700">${cm.tn}</span></td>
              <td><span style="color:var(--rose-500);font-weight:700">${cm.fn}</span></td>
              <td><strong>${fmtPct(m.precision)}</strong></td>
              <td><strong>${fmtPct(m.recall)}</strong></td>
              <td><strong style="color:var(--emerald-500)">${fmtPct(m.f1_score)}</strong></td>
              <td>${fmtPct(m.accuracy)}</td>
              <td>${fmtPct(m.specificity)}</td>
              <td>${m.mean_latency_ms ? m.mean_latency_ms.toFixed(2) + " ms" : "N/A"}</td>
            </tr>
          `;
        }).join("");
      }

      // 2. Visual Confusion Matrices
      const cmRow = $("research-cm-cards-container");
      if (cmRow) {
        cmRow.innerHTML = data.method_runs.map(mr => {
          const cm = mr.confusion_matrix;
          return `
            <div class="cm-box">
              <div class="cm-box-header">
                <span>${mr.method_name}</span>
                <span class="pill-badge neutral">N=${mr.metrics.evaluated_cases}</span>
              </div>
              <div class="cm-grid-2x2">
                <div class="cm-cell tp">
                  <div class="cm-cell-label">TP (True Pos)</div>
                  <div class="cm-cell-value">${cm.tp}</div>
                </div>
                <div class="cm-cell fp">
                  <div class="cm-cell-label">FP (False Pos)</div>
                  <div class="cm-cell-value">${cm.fp}</div>
                </div>
                <div class="cm-cell fn">
                  <div class="cm-cell-label">FN (False Neg)</div>
                  <div class="cm-cell-value">${cm.fn}</div>
                </div>
                <div class="cm-cell tn">
                  <div class="cm-cell-label">TN (True Neg)</div>
                  <div class="cm-cell-value">${cm.tn}</div>
                </div>
              </div>
            </div>
          `;
        }).join("");
      }

      // 3. Disagreements Table
      renderDisagreementsTable(data.disagreements || []);

      // 4. Empirical ROC & PR Discrimination Curves
      if (typeof window.renderCurvesVisualization === "function") {
        window.renderCurvesVisualization(state.activeExperimentId);
      }
    } catch (err) {
      console.error("[Research Lab] Failed to load comparison:", err);
    }
  }

  function renderDisagreementsTable(disagreements) {
    const tbody = $("research-disagreements-body");
    const countBadge = $("research-disagreements-count");
    if (countBadge) countBadge.textContent = `${disagreements.length} cases`;
    if (!tbody) return;

    if (disagreements.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:20px">No method disagreements detected.</td></tr>`;
      return;
    }

    tbody.innerHTML = disagreements.map(d => `
      <tr>
        <td><span style="font-family:var(--font-mono);font-weight:700">${d.case_id}</span></td>
        <td>${d.name}</td>
        <td><span class="pill-badge neutral">${d.category}</span></td>
        <td><span class="pill-badge ${d.ground_truth === 'VULNERABLE' ? 'danger' : 'success'}">${d.ground_truth}</span></td>
        <td><span class="pill-badge ${d.static_prediction === 'VULNERABLE' ? 'danger' : 'neutral'}">${d.static_prediction}</span></td>
        <td><span class="pill-badge ${d.gateway_prediction === 'VULNERABLE' ? 'danger' : 'neutral'}">${d.gateway_prediction}</span></td>
        <td><span class="pill-badge ${d.correlated_prediction === 'VULNERABLE' ? 'danger' : 'success'}" style="font-weight:700">${d.correlated_prediction}</span></td>
        <td>
          <button class="btn-secondary" style="padding:2px 8px;font-size:11px" onclick="inspectCaseEvidence('${d.case_id}')">Trace</button>
        </td>
      </tr>
    `).join("");
  }

  window.inspectCaseEvidence = async function (caseId) {
    state.activeCaseId = caseId;
    await switchSubTab("evidence");
  };

  // =============================================================================
  // 3. ABLATION STUDIES TAB
  // =============================================================================
  async function loadAblationsTab() {
    if (!state.activeExperimentId) return;
    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}/ablations`);
      if (!res.ok) return;
      const data = await res.json();
      state.currentAblationsData = data;

      const ablations = data.ablations || [];
      const tbody = $("research-ablations-table-body");
      if (!tbody) return;

      if (ablations.length === 0) {
        tbody.innerHTML = `<tr><td colspan="11" style="text-align:center;color:var(--text-muted);padding:20px">No ablation studies recorded for this experiment run.</td></tr>`;
        const listContainer = $("research-ablation-changed-cases-list");
        if (listContainer) listContainer.innerHTML = `<p style="color:var(--text-muted);font-size:12px">No ablation data recorded for this run.</p>`;
        return;
      }

      const fmtPct = (val) => val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : "N/A";
      const fmtDelta = (val) => {
        if (val === null || val === undefined) return `<span class="delta-pill neutral">0.0%</span>`;
        const pct = (val * 100).toFixed(1);
        if (val > 0) return `<span class="delta-pill positive">+${pct}%</span>`;
        if (val < 0) return `<span class="delta-pill negative">${pct}%</span>`;
        return `<span class="delta-pill neutral">0.0%</span>`;
      };

      tbody.innerHTML = ablations.map(ab => {
        const st = ab.statistical_test || {};
        const isSig = st.is_statistically_significant;
        return `
          <tr>
            <td><strong>${ab.ablation_name}</strong></td>
            <td><strong>${fmtPct(ab.metrics_baseline.f1_score)}</strong></td>
            <td>${fmtPct(ab.metrics_ablated.f1_score)}</td>
            <td>${fmtDelta(ab.f1_delta)}</td>
            <td>${fmtDelta(ab.precision_delta)}</td>
            <td>${fmtDelta(ab.recall_delta)}</td>
            <td>${ab.shared_cases_count}</td>
            <td><strong>${ab.changed_cases ? ab.changed_cases.length : 0}</strong></td>
            <td><code>${st.mcnemar_chi2 !== undefined ? st.mcnemar_chi2 : 'N/A'}</code></td>
            <td><code>${st.p_value !== undefined ? st.p_value : 'N/A'}</code></td>
            <td>
              <span class="pill-badge ${isSig ? 'danger' : 'neutral'}">${isSig ? 'SIGNIFICANT' : 'NOT SIG'}</span>
            </td>
          </tr>
        `;
      }).join("");

      // Render changed cases list for the first ablation by default
      if (ablations.length > 0) {
        renderAblationChangedCases(ablations[0]);
      }
    } catch (err) {
      console.error("[Research Lab] Failed to load ablations:", err);
    }
  }

  function renderAblationChangedCases(ablation) {
    const listContainer = $("research-ablation-changed-cases-list");
    if (!listContainer) return;

    const cases = ablation.changed_cases || [];
    if (cases.length === 0) {
      listContainer.innerHTML = `<p style="color:var(--text-muted);font-size:12px">No classification changes observed under this ablation.</p>`;
      return;
    }

    listContainer.innerHTML = cases.map(c => `
      <div style="background:var(--bg-card);border:1px solid var(--border-base);border-radius:var(--radius-md);padding:10px 14px;display:flex;justify-content:space-between;align-items:center">
        <div>
          <span style="font-family:var(--font-mono);font-weight:700">${c.case_id}</span>
          <p style="font-size:11.5px;color:var(--text-secondary);margin-top:2px">${c.explanation}</p>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <span class="pill-badge success">Base: ${c.baseline_pred}</span>
          <span>&rarr;</span>
          <span class="pill-badge danger">Ablated: ${c.ablated_pred}</span>
          <button class="btn-secondary" style="padding:2px 8px;font-size:11px" onclick="inspectCaseEvidence('${c.case_id}')">Evidence</button>
        </div>
      </div>
    `).join("");
  }

  // =============================================================================
  // 4. ERROR ANALYSIS TAB
  // =============================================================================
  async function loadErrorsTab() {
    if (!state.activeExperimentId) return;
    const methodId = state.activeMethodId || "method_correlated";
    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}/errors?method_id=${methodId}`);
      if (!res.ok) return;
      const data = await res.json();
      state.currentErrorsData = data;

      // Update counters
      if ($("error-fp-count")) $("error-fp-count").textContent = data.counts.false_positives;
      if ($("error-fn-count")) $("error-fn-count").textContent = data.counts.false_negatives;
      if ($("error-inconc-count")) $("error-inconc-count").textContent = data.counts.inconclusive;
      if ($("error-excluded-count")) $("error-excluded-count").textContent = data.counts.excluded;

      renderErrorList("fp");
    } catch (err) {
      console.error("[Research Lab] Failed to load errors:", err);
    }
  }

  window.filterErrorType = function (type) {
    document.querySelectorAll(".error-filter-btn").forEach(b => b.classList.toggle("active", b.dataset.etype === type));
    renderErrorList(type);
  };

  function renderErrorList(type) {
    const list = $("research-errors-list-container");
    if (!list || !state.currentErrorsData) return;

    let items = [];
    if (type === "fp") items = state.currentErrorsData.false_positives;
    else if (type === "fn") items = state.currentErrorsData.false_negatives;
    else if (type === "inconclusive") items = state.currentErrorsData.inconclusive;
    else if (type === "excluded") items = state.currentErrorsData.excluded;

    if (items.length === 0) {
      list.innerHTML = `<div style="text-align:center;padding:30px;color:var(--text-muted)">No ${type.toUpperCase()} records found for this method.</div>`;
      return;
    }

    list.innerHTML = items.map(item => `
      <div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:12px 16px;display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-family:var(--font-mono);font-weight:700">${item.case_id}</span>
            <span class="pill-badge neutral">${item.category}</span>
            <span class="pill-badge ${item.ground_truth_security === 'VULNERABLE' ? 'danger' : 'success'}">GT: ${item.ground_truth_security}</span>
            <span class="pill-badge ${item.predicted_security === 'VULNERABLE' ? 'danger' : 'neutral'}">Pred: ${item.predicted_security}</span>
          </div>
          <p style="font-size:12px;color:var(--text-secondary);margin-top:4px">${item.name}</p>
          ${item.inconclusive_reason ? `<p style="font-size:11px;color:var(--amber-500);margin-top:2px">Reason: ${item.inconclusive_reason}</p>` : ''}
        </div>
        <div>
          <button class="btn-secondary" onclick="inspectCaseEvidence('${item.case_id}')">Inspect 10-Node Trace</button>
        </div>
      </div>
    `).join("");
  }

  // =============================================================================
  // 5. DATASET & GROUND TRUTH TAB
  // =============================================================================
  async function loadDatasetTab() {
    try {
      const res = await fetch(`/api/v1/research/datasets/${state.activeDatasetId}/cases`);
      if (!res.ok) return;
      const cases = await res.json();
      state.currentCasesData = cases;

      const tbody = $("research-cases-table-body");
      if (!tbody) return;

      tbody.innerHTML = cases.map(c => `
        <tr>
          <td><span style="font-family:var(--font-mono);font-weight:700">${c.id}</span></td>
          <td>${c.name}</td>
          <td><span class="pill-badge neutral">${c.category}</span></td>
          <td><span class="pill-badge ${c.syntax_type === 'MALFORMED' ? 'danger' : 'neutral'}">${c.syntax_type}</span></td>
          <td>User #${c.caller_user_id || 'None'} (${c.caller_role})</td>
          <td>Resource #${c.target_object_id || 'None'}</td>
          <td>Owner #${c.true_owner_id || 'None'}</td>
          <td><span class="pill-badge ${c.ground_truth_security === 'VULNERABLE' ? 'danger' : (c.ground_truth_security === 'MALFORMED' ? 'neutral' : 'success')}">${c.ground_truth_security}</span></td>
          <td>v${c.version}</td>
          <td>
            <button class="btn-secondary" style="padding:2px 8px;font-size:11px" onclick="openReviewModal('${c.id}')">Review</button>
          </td>
        </tr>
      `).join("");
    } catch (err) {
      console.error("[Research Lab] Failed to load dataset:", err);
    }
  }

  window.openReviewModal = function (caseId) {
    const c = state.currentCasesData.find(item => item.id === caseId);
    if (!c) return;
    $("review-modal-case-id").textContent = c.id;
    $("review-modal-current-sec").textContent = c.ground_truth_security;
    $("review-modal-new-sec").value = c.ground_truth_security;
    $("review-modal-reviewer").value = "Lead Security Evaluator";
    $("review-modal-rationale").value = "";
    $("modal-review-label").classList.add("active");
  };

  window.closeReviewModal = function () {
    $("modal-review-label").classList.remove("active");
  };

  window.submitLabelReview = async function () {
    const caseId = $("review-modal-case-id").textContent;
    const newSec = $("review-modal-new-sec").value;
    const reviewer = $("review-modal-reviewer").value;
    const rationale = $("review-modal-rationale").value;

    if (!rationale.trim()) {
      alert("Please provide an audit rationale for the ground-truth change.");
      return;
    }

    try {
      const res = await fetch(`/api/v1/research/cases/${caseId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          new_security: newSec,
          reviewer: reviewer,
          review_rationale: rationale
        })
      });

      if (res.ok) {
        closeReviewModal();
        await loadDatasetTab();
        alert(`Case ${caseId} label successfully reviewed and audit record logged.`);
      } else {
        alert("Failed to submit label review.");
      }
    } catch (err) {
      console.error("[Research Lab] Error reviewing label:", err);
    }
  };

  // =============================================================================
  // 6. EVIDENCE EXPLORER TAB (10-NODE TRACE)
  // =============================================================================
  async function loadEvidenceTab() {
    if (!state.activeExperimentId) return;
    const caseId = state.activeCaseId || "CORPUS-001";
    const methodId = state.activeMethodId || "method_correlated";

    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}/evidence/${caseId}?method_id=${methodId}`);
      if (!res.ok) return;
      const data = await res.json();
      state.activeEvidenceGraph = data.evidence_graph;

      // Update Case Header
      if ($("evidence-case-id-display")) $("evidence-case-id-display").textContent = data.case_id;
      if ($("evidence-outcome-badge")) {
        const b = $("evidence-outcome-badge");
        b.textContent = data.classification_outcome;
        b.className = `pill-badge ${data.classification_outcome === 'TP' || data.classification_outcome === 'TN' ? 'success' : 'danger'}`;
      }
      if ($("evidence-exec-id")) $("evidence-exec-id").textContent = data.execution_id || "exec_syn_verified";

      // Populate Case Selector Dropdown if empty
      populateEvidenceCaseSelector();

      // Render 10 Nodes Pipeline
      render10NodesPipeline(data.evidence_graph.nodes || []);
      selectEvidenceNode(0);
    } catch (err) {
      console.error("[Research Lab] Failed to load evidence:", err);
    }
  }

  function populateEvidenceCaseSelector() {
    const sel = $("evidence-case-select");
    if (!sel || sel.children.length > 1) return;
    if (state.currentCasesData.length > 0) {
      sel.innerHTML = state.currentCasesData.map(c => `
        <option value="${c.id}" ${c.id === state.activeCaseId ? 'selected' : ''}>${c.id} - ${c.name}</option>
      `).join("");
      sel.onchange = async (e) => {
        state.activeCaseId = e.target.value;
        await loadEvidenceTab();
      };
    }
  }

  function render10NodesPipeline(nodes) {
    const container = $("evidence-nodes-pipeline-container");
    if (!container) return;

    container.innerHTML = nodes.map((n, idx) => {
      const badgeClass = n.status.toLowerCase().replace(/_/g, "-");
      return `
        <div class="evidence-node-item ${idx === state.selectedNodeIdx ? 'selected' : ''}" onclick="selectEvidenceNode(${idx})">
          <div class="node-left-col">
            <div class="node-badge-idx">${n.index}</div>
            <div class="node-meta">
              <h4>${n.name}</h4>
              <p>${n.summary}</p>
            </div>
          </div>
          <div>
            <span class="node-status-badge ${badgeClass}">${n.status}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  window.selectEvidenceNode = function (idx) {
    state.selectedNodeIdx = idx;
    document.querySelectorAll(".evidence-node-item").forEach((el, i) => {
      el.classList.toggle("selected", i === idx);
    });

    if (!state.activeEvidenceGraph || !state.activeEvidenceGraph.nodes) return;
    const node = state.activeEvidenceGraph.nodes[idx];
    if (!node) return;

    if ($("inspector-node-title")) $("inspector-node-title").textContent = `${node.index}. ${node.name}`;
    if ($("inspector-node-status")) {
      const b = $("inspector-node-status");
      b.textContent = node.status;
      b.className = `node-status-badge ${node.status.toLowerCase().replace(/_/g, '-')}`;
    }
    if ($("inspector-node-category")) $("inspector-node-category").textContent = node.category.replace(/_/g, " ").toUpperCase();
    if ($("inspector-node-summary")) $("inspector-node-summary").textContent = node.summary;

    if ($("inspector-node-details-json")) {
      $("inspector-node-details-json").textContent = JSON.stringify(node.details, null, 2);
    }
  };

  // =============================================================================
  // 7. REPRODUCIBILITY & REPORTS TAB
  // =============================================================================
  async function loadReportsTab() {
    if (!state.activeExperimentId) return;
    const expId = state.activeExperimentId;

    try {
      // Set download links
      if ($("btn-download-json")) $("btn-download-json").href = `/api/v1/research/experiments/${expId}/export/json`;
      if ($("btn-download-csv")) $("btn-download-csv").href = `/api/v1/research/experiments/${expId}/export/csv`;
      if ($("btn-download-report")) $("btn-download-report").href = `/api/v1/research/experiments/${expId}/export/report`;
      if ($("btn-download-latex")) $("btn-download-latex").href = `/api/v1/research/experiments/${expId}/export/latex`;
      if ($("btn-download-bundle")) $("btn-download-bundle").href = `/api/v1/research/experiments/${expId}/export/bundle`;

      // Set CLI command
      if ($("report-cli-command")) {
        $("report-cli-command").textContent = `python -c "from app.security.research.evaluator import run_full_experiment; run_full_experiment('${state.activeDatasetId}')"`;
      }

      // Fetch live Markdown report
      const repRes = await fetch(`/api/v1/research/experiments/${expId}/export/report`);
      if (repRes.ok) {
        const mdText = await repRes.text();
        if ($("report-markdown-preview")) {
          $("report-markdown-preview").textContent = mdText;
        }
      }
    } catch (err) {
      console.error("[Research Lab] Failed to load reports:", err);
    }
  }

  // =============================================================================
  // EXPERIMENT EXECUTION TRIGGERS
  // =============================================================================
  window.launchResearchExperiment = async function () {
    const btn = $("btn-research-run-exp");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner-sm"></span> Running...`;
    }

    try {
      const res = await fetch("/api/v1/research/experiments/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dataset_id: state.activeDatasetId,
          include_ablations: true,
          exclude_malformed: true
        })
      });

      if (res.ok) {
        const result = await res.json();
        state.activeExperimentId = result.id;
        // Refresh experiment list
        const expRes = await fetch("/api/v1/research/experiments");
        if (expRes.ok) state.experimentsList = await expRes.json();
        renderExperimentDropdown();
        await switchSubTab("overview");
        alert(`Evaluation experiment ${result.id} successfully executed across 115 test cases!`);
      } else {
        alert("Failed to execute research experiment.");
      }
    } catch (err) {
      console.error("[Research Lab] Experiment execution failed:", err);
      alert("Error launching experiment: " + err.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `Run Experiment`;
      }
    }
  };

  // =============================================================================
  // 8. BENCHMARK GENERALIZATION TAB
  // =============================================================================
  let currentCoverageData = null;
  let activeGenSplit = "all";

  async function loadGeneralizationTab() {
    try {
      // 1. Fetch coverage breakdown
      const covRes = await fetch("/api/v1/research/datasets/ds_generalization_v2/coverage");
      if (covRes.ok) {
        currentCoverageData = await covRes.json();
        renderGeneralizationCoverage();
      }

      // 2. Fetch or find generalization experiment to populate path attribution KPIs
      const expRes = await fetch("/api/v1/research/experiments");
      if (expRes.ok) {
        const exps = await expRes.json();
        const genExp = exps.find(e => e.dataset_id === "ds_generalization_v2");
        if (genExp && genExp.method_runs) {
          const corRun = genExp.method_runs.find(m => m.method_id === "method_correlated");
          if (corRun && corRun.metrics) {
            const m = corRun.metrics;
            const fmt = (val) => val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : "N/A";
            if ($("gen2-path-precision")) $("gen2-path-precision").textContent = fmt(m.path_precision);
            if ($("gen2-path-recall")) $("gen2-path-recall").textContent = fmt(m.path_recall);
            if ($("gen2-path-exact")) $("gen2-path-exact").textContent = fmt(m.path_exact_match_rate);
          }
        }
      }

      if (currentCoverageData) {
        if ($("gen2-leakage-badge")) {
          $("gen2-leakage-badge").textContent = currentCoverageData.leakage_free ? "Leakage-Free: Disjoint Sets" : "Leakage Detected";
          $("gen2-leakage-badge").className = currentCoverageData.leakage_free ? "pill-badge emerald" : "pill-badge danger";
        }
        if ($("gen2-leakage-val")) {
          $("gen2-leakage-val").textContent = currentCoverageData.leakage_free ? "0 Overlap" : "Collision";
        }
      }
    } catch (err) {
      console.error("[Research Lab] Failed loading generalization tab:", err);
    }
  }

  window.filterGeneralizationSplit = function (splitKey) {
    activeGenSplit = splitKey;
    document.querySelectorAll("#gen2-split-filters button").forEach(btn => {
      btn.classList.toggle("active", btn.dataset.split === splitKey);
    });
    renderGeneralizationCoverage();
  };

  function renderGeneralizationCoverage() {
    if (!currentCoverageData) return;
    const tbody = $("gen2-coverage-tbody");
    if (!tbody) return;

    const catDetails = {
      MULTI_TENANT: {
        focus: "Cross-tenant isolation boundaries between user organizations and data domains.",
        splits: "Tuning: 3 | Held-Out: 3 | Stress: 2",
        types: "BASIC (8)",
        sec: '<span class="pill-badge danger">4 VULN</span> <span class="pill-badge emerald">4 BENIGN</span>'
      },
      NESTED_RELATIONSHIP: {
        focus: "Parent-child object traversals (Resource -> Documents) with independent ownership policies.",
        splits: "Tuning: 3 | Held-Out: 3 | Stress: 2",
        types: "BASIC (8)",
        sec: '<span class="pill-badge danger">4 VULN</span> <span class="pill-badge emerald">4 BENIGN</span>'
      },
      ALIAS_DISAMBIGUATION: {
        focus: "Multi-root aliased queries (e.g. myRes vs victimRes) disambiguated to discrete AST paths.",
        splits: "Tuning: 3 | Held-Out: 3 | Stress: 2",
        types: "ALIAS (8)",
        sec: '<span class="pill-badge danger">4 VULN</span> <span class="pill-badge emerald">4 BENIGN</span>'
      },
      FRAGMENTS_NAMED_OPS: {
        focus: "Inline fragments and named operations with selective execution and target spread.",
        splits: "Tuning: 2 | Held-Out: 2 | Stress: 2",
        types: "FRAGMENT (5) / NAMED (1)",
        sec: '<span class="pill-badge danger">3 VULN</span> <span class="pill-badge emerald">3 BENIGN</span>'
      },
      VARIABLE_OBJECT_IDS: {
        focus: "Dynamic query variables passing target object identifiers evaluated at execution time.",
        splits: "Tuning: 2 | Held-Out: 2 | Stress: 2",
        types: "VARIABLE (6)",
        sec: '<span class="pill-badge danger">3 VULN</span> <span class="pill-badge emerald">3 BENIGN</span>'
      },
      OWNERSHIP_EDGE_CASES: {
        focus: "Shared collaboration objects, revoked role permissions, and admin override boundaries.",
        splits: "Tuning: 2 | Held-Out: 2 | Stress: 2",
        types: "BASIC (6)",
        sec: '<span class="pill-badge danger">3 VULN</span> <span class="pill-badge emerald">3 BENIGN</span>'
      },
      MUTATION_AUTHORIZATION: {
        focus: "State-modifying mutations (update, delete, transfer) evaluated with database fixture rollback.",
        splits: "Tuning: 3 | Held-Out: 3 | Stress: 2",
        types: "MUTATION (8)",
        sec: '<span class="pill-badge danger">4 VULN</span> <span class="pill-badge emerald">4 BENIGN</span>'
      },
      PARTIAL_AUTHORIZATION: {
        focus: "Multi-object queries mixing authorized and unauthorized fields in a single GraphQL request.",
        splits: "Tuning: 3 | Held-Out: 1 | Stress: 2",
        types: "BASIC (6)",
        sec: '<span class="pill-badge danger">5 VULN</span> <span class="pill-badge emerald">1 BENIGN</span>'
      },
      MALFORMED_SYNTAX: {
        focus: "Syntax anomalies, unclosed braces, and invalid field tokens handled safely without crashing.",
        splits: "Tuning: 2 | Held-Out: 1 | Stress: 1",
        types: "MALFORMED (4)",
        sec: '<span class="pill-badge neutral">4 MALFORMED</span>'
      }
    };

    const byCat = currentCoverageData.by_category || {};
    tbody.innerHTML = Object.entries(byCat).map(([cat, count]) => {
      const meta = catDetails[cat] || {
        focus: "Custom benchmark category",
        splits: "All splits",
        types: "BASIC",
        sec: '<span class="pill-badge neutral">Active</span>'
      };
      return `
        <tr>
          <td><strong>${cat}</strong></td>
          <td>${count}</td>
          <td>${meta.sec}</td>
          <td>${meta.types}</td>
          <td>${meta.splits}</td>
          <td>${meta.focus}</td>
        </tr>
      `;
    }).join("");
  }

  async function launchExperimentDirectly() {
    try {
      const res = await fetch("/api/v1/research/experiments/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dataset_id: state.activeDatasetId,
          include_ablations: true
        })
      });
      if (res.ok) {
        const result = await res.json();
        state.activeExperimentId = result.id;
        state.experimentsList = [result];
        renderExperimentDropdown();
        await switchSubTab("overview");
      }
    } catch (e) {
      console.error(e);
    }
  }

  window.rerunActiveExperiment = async function () {
    if (!state.activeExperimentId) return;
    try {
      const res = await fetch(`/api/v1/research/experiments/${state.activeExperimentId}/rerun`, {
        method: "POST"
      });
      if (res.ok) {
        const result = await res.json();
        state.activeExperimentId = result.id;
        const expRes = await fetch("/api/v1/research/experiments");
        if (expRes.ok) state.experimentsList = await expRes.json();
        renderExperimentDropdown();
        await switchSubTab("overview");
        alert(`Rerun successful. New verified experiment ID: ${result.id}`);
      }
    } catch (err) {
      console.error("[Research Lab] Rerun failed:", err);
    }
  };

})();
