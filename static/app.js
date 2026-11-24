const btnHonest = document.getElementById("btn-honest");
const btnMitm = document.getElementById("btn-mitm");
const btnRetrain = document.getElementById("btn-retrain");
const profileSelect = document.getElementById("attack-profile");
const aiToggle = document.getElementById("ai-toggle-input");
const aiToggleLabel = document.getElementById("ai-toggle-label");
const aiBanner = document.getElementById("ai-banner");
const aiBannerText = document.getElementById("ai-banner-text");
const riskCard = document.getElementById("risk-card");

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
  renderSessions(data.sessions || []);
}

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
    tbody.innerHTML = '<tr><td colspan="8" class="muted">No sessions recorded yet.</td></tr>';
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
        ? "off"
        : d.risk_level === "HIGH"
        ? "high"
        : d.risk_level === "MEDIUM"
        ? "medium"
        : "normal";
      const scoreText = `${d.risk_score}/100`;
      return `
        <tr>
          <td>${item.timestamp}</td>
          <td><code>${s.session_id}</code></td>
          <td><span class="badge ${aiOn ? "normal" : "off"}">${aiOn ? "ON" : "OFF"}</span></td>
          <td>${s.mode} (${s.attack_profile})</td>
          <td>${s.secrets_match ? "Yes (K₁=K₂)" : "No (K₁≠K₂)"}</td>
          <td><strong>${scoreText}</strong></td>
          <td><span class="badge ${cls}">${d.verdict}</span></td>
          <td>${topInd}</td>
        </tr>`;
    })
    .join("");
}

function renderLatest(record) {
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
}

async function runSimulation(attackProfile) {
  btnHonest.disabled = true;
  btnMitm.disabled = true;
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
    btnHonest.disabled = false;
    btnMitm.disabled = false;
  }
}

btnHonest.addEventListener("click", () => runSimulation("none"));
btnMitm.addEventListener("click", () => runSimulation(profileSelect.value));
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
