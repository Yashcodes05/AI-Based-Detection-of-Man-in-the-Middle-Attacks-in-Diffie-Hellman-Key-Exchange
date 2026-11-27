const btnHonest = document.getElementById("btn-honest");
const btnMitm = document.getElementById("btn-mitm");
const btnBatch = document.getElementById("btn-batch");
const btnResetView = document.getElementById("btn-reset-view");
const btnRetrain = document.getElementById("btn-retrain");
const btnClear = document.getElementById("btn-clear");
const profileSelect = document.getElementById("attack-profile");
const aiToggle = document.getElementById("ai-toggle-input");
const aiToggleLabel = document.getElementById("ai-toggle-label");
const aiBanner = document.getElementById("ai-banner");
const aiBannerText = document.getElementById("ai-banner-text");
const riskCard = document.getElementById("risk-card");

const filterSearch = document.getElementById("filter-search");
const filterVerdict = document.getElementById("filter-verdict");
const filterAi = document.getElementById("filter-ai");
const filterProfile = document.getElementById("filter-profile");
const filterMinRisk = document.getElementById("filter-min-risk");
const minRiskVal = document.getElementById("min-risk-val");

let allSessions = [];
let selectedRecord = null;
let activeFeatureCat = "All";

function updateAiToggleUI() {
  const enabled = aiToggle.checked;
  aiToggleLabel.innerHTML = enabled ? "AI Detection: <strong>ON</strong>" : "AI Detection: <strong>OFF</strong>";
  if (enabled) {
    aiBanner.className = "ai-banner ai-banner-on";
    aiBannerText.innerHTML =
      "AI Behavioral Monitor is <strong>ACTIVE</strong> — handshakes are scored in real time for MITM anomalies.";
    riskCard.classList.remove("ai-off-dim");
  } else {
    aiBanner.className = "ai-banner ai-banner-off";
    aiBannerText.innerHTML =
      "AI Behavioral Monitor is <strong>OFF</strong> — simulating standard unauthenticated DH (MITM attacks go undetected!).";
    riskCard.classList.add("ai-off-dim");
  }
}

aiToggle.addEventListener("change", updateAiToggleUI);

async function loadMetrics() {
  const res = await fetch("/api/metrics");
  const data = await res.json();
  renderMetrics(data.metrics || []);
}

async function loadSessions() {
  const res = await fetch("/api/sessions");
  const data = await res.json();
  allSessions = data.sessions || [];
  updateKPIs(allSessions);
  renderRiskChart(allSessions);
  applySessionFilters();
}

function updateKPIs(sessions) {
  const total = sessions.length;
  const attacks = sessions.filter((x) => x.session.is_attack === 1);
  const caught = attacks.filter((x) => x.detection.is_anomalous).length;
  const normals = sessions.filter((x) => x.session.is_attack === 0 && x.ai_enabled !== false);
  const mitmsAiOn = attacks.filter((x) => x.ai_enabled !== false);

  document.getElementById("kpi-total").textContent = total;
  document.getElementById("kpi-caught").textContent = `${caught} / ${attacks.length}`;

  const avgNorm = normals.length
    ? Math.round(normals.reduce((a, b) => a + b.detection.risk_score, 0) / normals.length)
    : null;
  const avgMitm = mitmsAiOn.length
    ? Math.round(mitmsAiOn.reduce((a, b) => a + b.detection.risk_score, 0) / mitmsAiOn.length)
    : null;

  document.getElementById("kpi-avg-norm").textContent = avgNorm !== null ? `${avgNorm}/100` : "—";
  document.getElementById("kpi-avg-mitm").textContent = avgMitm !== null ? `${avgMitm}/100` : "—";
}

function renderRiskChart(sessions) {
  const svg = document.getElementById("risk-chart");
  const recent = sessions.slice(0, 20).reverse();
  if (!recent.length) {
    svg.innerHTML =
      '<text x="270" y="90" text-anchor="middle" fill="#8b9bb4" font-size="13">Run sessions or Batch (10) to plot Risk Score timeline</text>';
    return;
  }

  const w = 540;
  const h = 170;
  const padL = 28;
  const padB = 22;
  const plotH = h - padB - 14;
  const plotW = w - padL - 12;
  const barW = Math.max(10, Math.floor(plotW / recent.length) - 6);
  const thresholdY = 14 + plotH * (1 - 0.7);

  let bars = "";
  recent.forEach((item, i) => {
    const score = item.detection.risk_score || 0;
    const barH = Math.max(3, (score / 100) * plotH);
    const x = padL + i * (plotW / recent.length) + 3;
    const y = 14 + plotH - barH;
    const color =
      item.ai_enabled === false
        ? "#8b9bb4"
        : score >= 70
        ? "#ff4d6d"
        : score >= 45
        ? "#f59e0b"
        : "#10b981";
    bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW}" height="${barH.toFixed(
      1
    )}" rx="3" fill="${color}"><title>${item.session.session_id}: ${score}/100 (${item.session.attack_profile})</title></rect>`;
  });

  svg.innerHTML = `
    <line x1="${padL}" y1="14" x2="${padL}" y2="${14 + plotH}" stroke="#1d2a44" stroke-width="1"/>
    <line x1="${padL}" y1="${14 + plotH}" x2="${w - 10}" y2="${14 + plotH}" stroke="#1d2a44" stroke-width="1"/>
    <line x1="${padL}" y1="${thresholdY.toFixed(1)}" x2="${w - 10}" y2="${thresholdY.toFixed(
    1
  )}" stroke="#ff4d6d" stroke-dasharray="4 4" stroke-width="1.2"/>
    <text x="4" y="${thresholdY.toFixed(1)}" fill="#ff4d6d" font-size="10">70</text>
    <text x="4" y="20" fill="#8b9bb4" font-size="10">100</text>
    <text x="10" y="${14 + plotH}" fill="#8b9bb4" font-size="10">0</text>
    ${bars}
  `;
}

function renderFeatureInspector(record) {
  if (!record || !record.feature_details) return;
  document.getElementById("feat-session-label").textContent = record.session.session_id;
  const container = document.getElementById("feature-bars");
  const filtered =
    activeFeatureCat === "All"
      ? record.feature_details
      : record.feature_details.filter((f) => f.category === activeFeatureCat);

  container.innerHTML = filtered
    .map((f) => {
      const pct = Math.min(100, Math.max(4, (Math.max(0, f.z_score) / 6) * 100));
      const zSign = f.z_score >= 0 ? `+${f.z_score}` : `${f.z_score}`;
      return `
        <div class="feat-row">
          <div class="feat-name">
            <span>${f.label}</span>
            <small>[${f.category}] obs: ${f.observed} | base: ${f.baseline_mean}</small>
          </div>
          <div class="feat-track">
            <div class="feat-fill ${f.severity}" style="width:${pct.toFixed(0)}%"></div>
          </div>
          <div class="feat-z">${zSign}σ</div>
        </div>`;
    })
    .join("");
}

document.getElementById("feature-tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab-btn");
  if (!btn) return;
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  activeFeatureCat = btn.dataset.cat;
  if (selectedRecord) renderFeatureInspector(selectedRecord);
});

function applySessionFilters() {
  const q = filterSearch.value.trim().toLowerCase();
  const v = filterVerdict.value;
  const ai = filterAi.value;
  const prof = filterProfile.value;
  const minRisk = Number(filterMinRisk.value);
  minRiskVal.textContent = minRisk;

  const filtered = allSessions.filter((item) => {
    const s = item.session;
    const d = item.detection;
    const aiOn = item.ai_enabled !== false;

    if (v === "anomalous" && !d.is_anomalous) return false;
    if (v === "normal" && d.is_anomalous) return false;
    if (ai === "on" && !aiOn) return false;
    if (ai === "off" && aiOn) return false;
    if (prof !== "all" && s.attack_profile !== prof) return false;
    if ((d.risk_score || 0) < minRisk) return false;

    if (q) {
      const indText = (d.indicators || []).map((i) => i.label).join(" ").toLowerCase();
      const hay = `${s.session_id} ${s.mode} ${s.attack_profile} ${d.verdict} ${indText}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  document.getElementById("session-count-label").textContent = `${filtered.length} of ${allSessions.length} shown`;
  renderSessions(filtered);
}

[filterSearch, filterVerdict, filterAi, filterProfile, filterMinRisk].forEach((el) => {
  el.addEventListener("input", applySessionFilters);
  el.addEventListener("change", applySessionFilters);
});

function renderMetrics(metrics) {
  const tbody = document.getElementById("metrics-body");
  tbody.innerHTML = metrics
    .map(
      (m) => `
      <tr>
        <td><strong>${m.model}</strong></td>
        <td>${m.paradigm}</td>
        <td>${m.accuracy}%</td>
        <td>${m.precision}%</td>
        <td>${m.recall}%</td>
        <td>${m.f1}%</td>
        <td>${m.roc_auc}</td>
      </tr>`
    )
    .join("");
}

function renderSessions(sessions) {
  const tbody = document.getElementById("sessions-body");
  if (!sessions.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="muted">No matching sessions found.</td></tr>';
    return;
  }
  tbody.innerHTML = sessions
    .map((item) => {
      const s = item.session;
      const d = item.detection;
      const aiOn = item.ai_enabled !== false;
      const topInd = !aiOn
        ? "Not monitored (AI OFF)"
        : d.indicators.length
        ? d.indicators[0].label
        : "Baseline normal";
      const cls = !aiOn
        ? "normal"
        : d.risk_level === "HIGH"
        ? "high"
        : d.risk_level === "MEDIUM"
        ? "medium"
        : "normal";
      return `
        <tr class="clickable" data-sid="${s.session_id}">
          <td>${item.timestamp}</td>
          <td><code>${s.session_id}</code></td>
          <td><span class="badge ${aiOn ? "normal" : "off"}">${aiOn ? "ON" : "OFF"}</span></td>
          <td>${s.mode} (${s.attack_profile})</td>
          <td>${s.secrets_match ? "Yes (K₁=K₂)" : "No (K₁≠K₂)"}</td>
          <td><strong>${d.risk_score}/100</strong></td>
          <td><span class="badge ${cls}">${d.verdict}</span></td>
          <td>${topInd}</td>
        </tr>`;
    })
    .join("");

  tbody.querySelectorAll("tr.clickable").forEach((row) => {
    row.addEventListener("click", () => {
      const rec = allSessions.find((x) => x.session.session_id === row.dataset.sid);
      if (rec) renderLatest(rec);
    });
  });
}

function renderLatest(record) {
  selectedRecord = record;
  const s = record.session;
  const d = record.detection;
  const tel = s.telemetry;
  const aiOn = record.ai_enabled !== false;

  const badge = document.getElementById("verdict-badge");
  const level = document.getElementById("risk-level");
  const scoreEl = document.getElementById("risk-score");
  const bar = document.getElementById("risk-bar");

  const cls = !aiOn
    ? "normal"
    : d.risk_level === "HIGH"
    ? "high"
    : d.risk_level === "MEDIUM"
    ? "medium"
    : "normal";
  badge.className = `badge ${cls}`;
  badge.textContent = d.verdict;
  document.getElementById("session-id-label").textContent = s.session_id;

  const indList = document.getElementById("indicators-list");
  if (!aiOn) {
    scoreEl.textContent = d.risk_score;
    level.textContent = "NORMAL";
    bar.style.width = "10%";
    bar.style.background = "var(--green)";
    indList.innerHTML =
      '<li class="muted">No anomalies reported — standard DH without AI assumes this handshake is normal (even if intercepted).</li>';
  } else {
    scoreEl.textContent = d.risk_score;
    level.textContent = d.risk_level;
    bar.style.width = `${d.risk_score}%`;
    bar.style.background =
      d.risk_level === "HIGH" ? "var(--red)" : d.risk_level === "MEDIUM" ? "var(--amber)" : "var(--green)";

    if (!d.indicators.length) {
      indList.innerHTML = '<li class="muted">No anomalous indicators — traffic matches learned normal baseline.</li>';
    } else {
      indList.innerHTML = d.indicators
        .map(
          (ind) => `
          <li class="ind-${ind.severity}">
            <span><strong>[${ind.category}]</strong> ${ind.label}</span>
            <span class="meta">+${ind.z_score}σ (obs: ${ind.observed})</span>
          </li>`
        )
        .join("");
    }
  }

  document.getElementById("alice-pub").textContent = `gᵃ: ${s.alice_pub_fp}`;
  document.getElementById("bob-pub").textContent = `gᵇ: ${s.bob_pub_fp}`;
  document.getElementById("alice-sec").textContent = `K₁: ${s.alice_secret_fp}`;
  document.getElementById("bob-sec").textContent = `K₂: ${s.bob_secret_fp}`;
  document.getElementById("crypto-match-badge").textContent = s.secrets_match
    ? "Shared Secret Verified (K_A == K_B)"
    : "MITM Key Split (K_A != K_B)";

  const attackerNode = document.getElementById("node-attacker");
  const linkRight = document.getElementById("link-right");
  if (s.attacker_intercepted) {
    attackerNode.classList.remove("hidden");
    linkRight.classList.remove("hidden");
  } else {
    attackerNode.classList.add("hidden");
    linkRight.classList.add("hidden");
  }

  document.getElementById("tel-lat").textContent = `${tel.handshake_latency_ms.toFixed(1)} ms`;
  document.getElementById("tel-spread").textContent = `${tel.latency_spread_ms.toFixed(2)} ms`;
  document.getElementById("tel-retries").textContent = tel.handshake_retries.toFixed(0);
  document.getElementById("tel-inter").textContent = tel.intermediary_host_count.toFixed(0);
  document.getElementById("tel-path").textContent = tel.path_hop_anomaly.toFixed(2);
  document.getElementById("tel-auth").textContent = tel.auth_cert_anomaly >= 0.5 ? "Anomaly" : "OK";

  renderFeatureInspector(record);
}

function setButtonsDisabled(disabled) {
  btnHonest.disabled = disabled;
  btnMitm.disabled = disabled;
  btnBatch.disabled = disabled;
}

async function runSimulation(attackProfile) {
  setButtonsDisabled(true);
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack_profile: attackProfile, ai_enabled: aiToggle.checked }),
    });
    const data = await res.json();
    renderLatest(data);
    await loadSessions();
  } finally {
    setButtonsDisabled(false);
  }
}

btnHonest.addEventListener("click", () => runSimulation("none"));
btnMitm.addEventListener("click", () => runSimulation(profileSelect.value));

btnBatch.addEventListener("click", async () => {
  setButtonsDisabled(true);
  try {
    const res = await fetch("/api/simulate_batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ai_enabled: aiToggle.checked }),
    });
    const data = await res.json();
    if (data.latest) renderLatest(data.latest);
    await loadSessions();
  } finally {
    setButtonsDisabled(false);
  }
});

btnClear.addEventListener("click", async () => {
  await fetch("/api/clear", { method: "POST" });
  await loadSessions();
});

function resetDashboardView() {
  selectedRecord = null;

  const badge = document.getElementById("verdict-badge");
  badge.className = "badge";
  badge.textContent = "AWAITING SESSION";
  document.getElementById("session-id-label").textContent = "—";
  document.getElementById("risk-score").textContent = "--";
  document.getElementById("risk-level").textContent = "—";
  const bar = document.getElementById("risk-bar");
  bar.style.width = "0%";
  bar.style.background = "var(--green)";
  document.getElementById("indicators-list").innerHTML =
    '<li class="muted">Run a handshake simulation to inspect behavioral indicators.</li>';

  document.getElementById("alice-pub").textContent = "Pub: —";
  document.getElementById("bob-pub").textContent = "Pub: —";
  document.getElementById("alice-sec").textContent = "K: —";
  document.getElementById("bob-sec").textContent = "K: —";
  document.getElementById("crypto-match-badge").textContent = "—";
  document.getElementById("node-attacker").classList.add("hidden");
  document.getElementById("link-right").classList.add("hidden");

  ["tel-lat", "tel-spread", "tel-retries", "tel-inter", "tel-path", "tel-auth"].forEach((id) => {
    document.getElementById(id).textContent = "—";
  });

  activeFeatureCat = "All";
  document.querySelectorAll("#feature-tabs .tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.cat === "All");
  });
  document.getElementById("feat-session-label").textContent = "Latest session";
  document.getElementById("feature-bars").innerHTML =
    '<div class="muted" style="font-size:13px;">Run a simulation to inspect all 14 observable features.</div>';

  filterSearch.value = "";
  filterVerdict.value = "all";
  filterAi.value = "all";
  filterProfile.value = "all";
  filterMinRisk.value = "0";
  applySessionFilters();
}

btnResetView.addEventListener("click", resetDashboardView);

btnRetrain.addEventListener("click", async () => {
  btnRetrain.disabled = true;
  try {
    const res = await fetch("/api/retrain", { method: "POST" });
    const data = await res.json();
    renderMetrics(data.metrics || []);
  } finally {
    btnRetrain.disabled = false;
  }
});

loadMetrics();
loadSessions();
