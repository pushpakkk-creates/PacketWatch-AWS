
const $ = (id) => document.getElementById(id);

let labelChart = null;
let resultChart = null;
let latestCsv = "";
let latestResults = [];
let latestColumns = [];

function displayLabel(value) {
  const text = String(value ?? "");
  if (text.toUpperCase() === "BENIGN") return "Normal Traffic";
  if (text.toUpperCase() === "ATTACK") return "Suspicious Traffic";
  return text;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  window.setTimeout(() => el.classList.remove("show"), 2800);
}

function setAlert(id, message, type = "success") {
  const el = $(id);
  el.textContent = message;
  el.className = `alert show ${type}`;
}

function clearAlert(id) {
  const el = $(id);
  el.className = "alert";
  el.textContent = "";
}

function go(view) {
  document.querySelectorAll(".page-view").forEach(el =>
    el.classList.toggle("active", el.id === `view-${view}`)
  );

  document.querySelectorAll(".nav-item[data-view]").forEach(el =>
    el.classList.toggle("active", el.dataset.view === view)
  );

  const names = {
    overview: "Overview",
    train: "Model training",
    analyze: "Traffic analysis",
    architecture: "AWS architecture"
  };

  $("crumb-title").textContent = names[view] || "Overview";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll(".nav-item[data-view]").forEach(btn =>
  btn.addEventListener("click", () => go(btn.dataset.view))
);

document.querySelectorAll("[data-go]").forEach(btn =>
  btn.addEventListener("click", () => go(btn.dataset.go))
);

function fmt(value) {
  return Number.isFinite(Number(value))
    ? `${(Number(value) * 100).toFixed(1)}%`
    : "—";
}

function num(value) {
  return Number(value || 0).toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

async function api(url, file) {
  const form = new FormData();
  form.append("file", file);

  const response = await fetch(url, {
    method: "POST",
    body: form
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }

  return data;
}

function drawLabelChart(counts) {
  const entries = Object.entries(counts || {});
  $("chart-empty").style.display = entries.length ? "none" : "grid";

  if (!entries.length || !window.Chart) return;

  if (labelChart) labelChart.destroy();

  labelChart = new Chart($("label-chart"), {
    type: "bar",
    data: {
      labels: entries.map(([label]) => displayLabel(label)),
      datasets: [{
        data: entries.map(([, count]) => count),
        backgroundColor: entries.map(([label]) =>
          label.toUpperCase() === "BENIGN" ? "#4ade80" : "#fb7185"
        ),
        borderRadius: 5,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid: { color: "#26334a" },
          ticks: { color: "#7f8da5", font: { size: 9 } }
        },
        y: {
          grid: { display: false },
          ticks: { color: "#aab6ca", font: { size: 9 } }
        }
      }
    }
  });
}

function renderConfusionMatrix(matrix) {
  if (!matrix || !matrix.length || !$("confusion-wrap")) return;

  const cells = [
    ["Actual Normal → Predicted Normal", matrix[0][0]],
    ["Actual Normal → Predicted Suspicious", matrix[0][1]],
    ["Actual Attack → Predicted Normal", matrix[1][0]],
    ["Actual Attack → Predicted Attack", matrix[1][1]]
  ];

  $("confusion-wrap").innerHTML = `
    <div class="confusion-grid">
      ${cells.map(([label, value]) => `
        <div>
          <small>${label}</small>
          <b>${num(value)}</b>
        </div>
      `).join("")}
    </div>
  `;
}

function renderImportance(items) {
  const el = $("importance-wrap");
  if (!el) return;

  if (!items || !items.length) {
    el.innerHTML = "<p>Feature importance is not available in the current API response.</p>";
    return;
  }

  const top = items.slice(0, 8);
  const max = Math.max(
    ...top.map(item => Number(item.importance) || 0),
    0.0001
  );

  el.innerHTML = top.map(item => {
    const value = Number(item.importance) || 0;

    return `
      <div class="importance-row">
        <code title="${escapeHtml(item.feature)}">${escapeHtml(item.feature)}</code>
        <div class="importance-track">
          <i style="width:${Math.max(2, value / max * 100)}%"></i>
        </div>
        <b>${value.toFixed(3)}</b>
      </div>
    `;
  }).join("");
}

function updateDashboard(report) {
  if (!report || report.accuracy === undefined) return;

  $("metric-model").textContent = "Trained";
  $("model-note").textContent = `${num(report.rows_used)} labelled rows`;
  $("model-dot").style.background = "var(--green)";

  $("metric-accuracy").textContent = fmt(report.accuracy);
  $("metric-f1").textContent = fmt(report.f1);
  $("metric-features").textContent = num(report.features_used);

  $("metric-precision").textContent = fmt(report.precision);
  $("metric-recall").textContent = fmt(report.recall);
  $("score-f1").textContent = fmt(report.f1);

  $("bar-precision").style.width =
    `${Math.max(0, Math.min(100, Number(report.precision) * 100))}%`;

  $("bar-recall").style.width =
    `${Math.max(0, Math.min(100, Number(report.recall) * 100))}%`;

  $("bar-f1").style.width =
    `${Math.max(0, Math.min(100, Number(report.f1) * 100))}%`;

  $("last-trained").textContent =
    `MODEL · ${report.trained_at
      ? new Date(report.trained_at).toLocaleString()
      : "TRAINED"}`;

  $("eval-accuracy").textContent = fmt(report.accuracy);
  $("eval-precision").textContent = fmt(report.precision);
  $("eval-recall").textContent = fmt(report.recall);
  $("eval-f1").textContent = fmt(report.f1);

  renderConfusionMatrix(report.confusion_matrix);
  renderImportance(report.feature_importance);
  drawLabelChart(report.label_counts);
}

function renderInspect(data) {
  $("inspect-placeholder").classList.add("hidden");
  $("inspect-results").classList.remove("hidden");

  $("inspect-rows").textContent = num(data.rows);
  $("inspect-cols").textContent = num(data.columns);
  $("inspect-label").textContent = data.has_label ? "Found" : "Missing";

  const labels = Object.entries(data.label_counts || {});

  $("label-chips").innerHTML = labels.map(([key, value]) => `
    <span class="label-chip">
      ${escapeHtml(displayLabel(key))} · ${num(value)}
    </span>
  `).join("") || `<span class="label-chip">No Label field</span>`;

  const rows = data.preview || [];
  const cols = (data.column_names || Object.keys(rows[0] || {})).slice(0, 5);

  $("preview-head").innerHTML = `
    <tr>${cols.map(col => `<th>${escapeHtml(col)}</th>`).join("")}</tr>
  `;

  $("preview-body").innerHTML = rows.map(row => `
    <tr>
      ${cols.map(col => {
        const value = col.toLowerCase() === "label"
          ? displayLabel(row[col])
          : (row[col] ?? "—");

        return `<td title="${escapeHtml(value)}">${escapeHtml(value)}</td>`;
      }).join("")}
    </tr>
  `).join("");
}

function setupFileInput(inputId, labelId, dropId) {
  const input = $(inputId);

  input.addEventListener("change", () => {
    $(labelId).textContent = input.files[0]?.name || "No file selected";
  });

  const drop = $(dropId);

  ["dragenter", "dragover"].forEach(eventName =>
    drop.addEventListener(eventName, event => {
      event.preventDefault();
      drop.classList.add("dragover");
    })
  );

  ["dragleave", "drop"].forEach(eventName =>
    drop.addEventListener(eventName, event => {
      event.preventDefault();
      drop.classList.remove("dragover");
    })
  );

  drop.addEventListener("drop", event => {
    if (!event.dataTransfer.files.length) return;

    const file = event.dataTransfer.files[0];

    if (!file.name.toLowerCase().endsWith(".csv")) {
      toast("Please drop a CSV file.");
      return;
    }

    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
    input.dispatchEvent(new Event("change"));
  });
}

setupFileInput("train-file", "train-filename", "train-drop");
setupFileInput("analyze-file", "analyze-filename", "analyze-drop");

async function generateSyntheticDataset(target) {
  const count = Number($("synthetic-count").value);
  const button = $(target === "train" ? "generate-btn" : "generate-analyze-btn");
  const alertId = target === "train" ? "train-alert" : "analyze-alert";

  clearAlert(alertId);

  button.disabled = true;
  const originalText = button.textContent;
  button.textContent = "Generating…";

  try {
    const response = await fetch(
      `/api/generate-dataset?rows=${count}&attack_percent=25`,
      { method: "POST" }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Could not generate dataset");
    }

    if (!data.csv) {
      throw new Error("The generator response did not include CSV content.");
    }

    const file = new File(
      [data.csv],
      data.filename || "generated_traffic.csv",
      { type: "text/csv" }
    );

    const input = $(target === "train" ? "train-file" : "analyze-file");
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;

    $(target === "train" ? "train-filename" : "analyze-filename").textContent =
      `${file.name} · ${num(data.rows)} rows`;

    if (target === "train") {
      renderInspect(data);
      setAlert(
        alertId,
        `Generated ${num(data.rows)} synthetic records. The dataset is selected. Review the labels, then train the model.`,
        "success"
      );
    } else {
      setAlert(
        alertId,
        `Generated ${num(data.rows)} synthetic records and selected them for analysis. This is simulated data, not real network traffic.`,
        "success"
      );
    }

    toast(`Generated ${num(data.rows)} synthetic flow records`);
  } catch (error) {
    setAlert(alertId, error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

$("generate-btn").addEventListener("click", () => generateSyntheticDataset("train"));
$("generate-analyze-btn").addEventListener("click", () => generateSyntheticDataset("analyze"));

$("inspect-btn").addEventListener("click", async () => {
  clearAlert("train-alert");

  const file = $("train-file").files[0];

  if (!file) {
    setAlert("train-alert", "Choose or generate a CSV first.", "error");
    return;
  }

  const button = $("inspect-btn");
  button.disabled = true;

  try {
    const data = await api("/api/inspect", file);
    renderInspect(data);

    setAlert(
      "train-alert",
      `Inspection complete: ${num(data.rows)} rows and ${num(data.columns)} columns. ${
        data.has_label
          ? "Label column found."
          : "No Label column found; training requires it."
      }`,
      data.has_label ? "success" : "error"
    );
  } catch (error) {
    setAlert("train-alert", error.message, "error");
  } finally {
    button.disabled = false;
  }
});

$("train-btn").addEventListener("click", async () => {
  clearAlert("train-alert");

  const file = $("train-file").files[0];

  if (!file) {
    setAlert("train-alert", "Choose or generate a labelled CSV first.", "error");
    return;
  }

  const button = $("train-btn");
  button.disabled = true;
  $("train-progress").classList.add("show");
  $("progress-label").textContent = "Training and evaluating Random Forest…";

  try {
    const report = await api("/api/train", file);

    updateDashboard(report);

    const trainScore = report.train_accuracy === undefined
      ? ""
      : ` Training accuracy: ${fmt(report.train_accuracy)}.`;

    setAlert(
      "train-alert",
      `Training complete. Test accuracy: ${fmt(report.accuracy)}; recall: ${fmt(report.recall)}; F1: ${fmt(report.f1)}. Model saved on this server.${trainScore}`,
      "success"
    );

    toast("Model trained successfully");
  } catch (error) {
    setAlert("train-alert", error.message, "error");
  } finally {
    button.disabled = false;
    $("train-progress").classList.remove("show");
  }
});

function chooseVisibleColumns(columns) {
  const preferred = [
    "Source IP", "Destination IP", "Timestamp",
    "Flow Duration", "Tot Fwd Pkts", "Flow Bytes/s",
    "Label", "Prediction", "Attack_Probability"
  ];

  const chosen = preferred.filter(col => columns.includes(col));

  for (const col of columns) {
    if (chosen.length >= 8) break;
    if (!chosen.includes(col)) chosen.push(col);
  }

  return chosen.slice(0, 8);
}

function renderResultsTable() {
  const search = ($("results-search").value || "").toLowerCase().trim();
  const filter = $("prediction-filter").value;

  const filtered = latestResults.filter(row => {
    const prediction = String(row.Prediction || "").toUpperCase();
    const filterMatch = filter === "all" || prediction === filter;

    const searchMatch = !search || latestColumns.some(col =>
      String(row[col] ?? "").toLowerCase().includes(search) ||
      displayLabel(row[col]).toLowerCase().includes(search)
    );

    return filterMatch && searchMatch;
  });

  const cols = chooseVisibleColumns(latestColumns);

  $("results-head").innerHTML = `
    <tr>
      ${cols.map(col => {
        const heading = col === "Prediction"
          ? "Traffic classification"
          : col === "Attack_Probability"
            ? "Threat probability"
            : col === "Label"
              ? "Known label"
              : col;

        return `<th>${escapeHtml(heading)}</th>`;
      }).join("")}
    </tr>
  `;

  $("results-body").innerHTML = filtered.map(row => `
    <tr>
      ${cols.map(col => {
        const value = row[col];

        if (col === "Prediction") {
          const attack = String(value).toUpperCase() === "ATTACK";

          return `<td><span class="prediction-pill ${attack ? "attack" : "normal"}">${
            attack ? "Suspicious Traffic" : "Normal Traffic"
          }</span></td>`;
        }

        if (col === "Attack_Probability") {
          const probability = Number(value);
          const high = Number.isFinite(probability) && probability >= 0.5;

          return `<td class="${high ? "probability-high" : "probability-low"}">${
            Number.isFinite(probability) ? `${(probability * 100).toFixed(1)}%` : "—"
          }</td>`;
        }

        if (col.toLowerCase() === "label") {
          return `<td>${escapeHtml(displayLabel(value))}</td>`;
        }

        return `<td title="${escapeHtml(value ?? "")}">${escapeHtml(value ?? "—")}</td>`;
      }).join("")}
    </tr>
  `).join("");

  $("results-count").textContent =
    `${num(filtered.length)} shown · ${num(latestResults.length)} returned in preview`;
}

$("analyze-btn").addEventListener("click", async () => {
  clearAlert("analyze-alert");

  const file = $("analyze-file").files[0];

  if (!file) {
    setAlert("analyze-alert", "Choose or generate a traffic CSV first.", "error");
    return;
  }

  const button = $("analyze-btn");
  button.disabled = true;

  try {
    const data = await api("/api/analyze", file);

    latestCsv = data.csv || "";
    latestResults = data.results || [];
    latestColumns = data.columns || Object.keys(latestResults[0] || {});

    $("analysis-total").textContent = num(data.rows);
    $("analysis-attacks").textContent = num(data.attack_count);
    $("analysis-benign").textContent = num(data.benign_count);

    $("result-empty").style.display = latestResults.length ? "none" : "grid";

    if (resultChart) resultChart.destroy();

    if (window.Chart) {
      resultChart = new Chart($("result-chart"), {
        type: "doughnut",
        data: {
          labels: ["Suspicious Traffic", "Normal Traffic"],
          datasets: [{
            data: [data.attack_count, data.benign_count],
            backgroundColor: ["#fb7185", "#4ade80"],
            borderColor: "#111a2c",
            borderWidth: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                color: "#aab6ca",
                padding: 18,
                font: { size: 10 }
              }
            }
          }
        }
      });
    }

    $("results-placeholder").classList.add("hidden");
    $("results-controls").classList.remove("hidden");
    $("results-table-wrap").classList.remove("hidden");

    $("results-search").value = "";
    $("prediction-filter").value = "all";

    renderResultsTable();

    $("download-btn").disabled = !latestCsv;

    setAlert(
      "analyze-alert",
      `Analysis complete: ${num(data.rows)} flows scored. Review the predictions below; these are model estimates, not confirmed incidents.`,
      "success"
    );

    toast("Traffic analysis complete");
  } catch (error) {
    setAlert("analyze-alert", error.message, "error");
  } finally {
    button.disabled = false;
  }
});

$("results-search").addEventListener("input", renderResultsTable);
$("prediction-filter").addEventListener("change", renderResultsTable);

$("download-btn").addEventListener("click", () => {
  if (!latestCsv) return;

  const url = URL.createObjectURL(
    new Blob([latestCsv], { type: "text/csv;charset=utf-8;" })
  );

  const link = document.createElement("a");
  link.href = url;
  link.download = "packetwatch_predictions.csv";
  link.click();

  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
});

async function loadStatus() {
  try {
    const response = await fetch("/api/status");
    const data = await response.json();

    $("engine-status").textContent =
      `API online · ${data.model_ready ? "model ready" : "model not trained"}`;

    if (data.model_ready) {
      $("metric-model").textContent = "Trained";
      $("model-note").textContent = "Saved model available";
      $("model-dot").style.background = "var(--green)";
      $("analysis-no-model").classList.add("hidden");
    } else {
      $("analysis-no-model").classList.remove("hidden");
    }

    if (data.last_training?.accuracy !== undefined) {
      updateDashboard(data.last_training);
    }
  } catch (error) {
    $("engine-status").textContent = "API unavailable";
    $("analysis-no-model").classList.remove("hidden");
  }
}

loadStatus();
