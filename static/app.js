const state = {
  view: "packets",
  packets: [],
  sessions: [],
  alerts: [],
  dns: [],
  http: [],
  tls: [],
  rules: [],
  stats: {},
  selected: null,
  filter: "",
};

const views = {
  packets: {
    title: "Packet Capture",
    columns: ["id", "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "info"],
  },
  sessions: {
    title: "Active Sessions",
    columns: ["session_key", "src_ip", "dst_ip", "protocol", "packets", "bytes", "state", "last_seen"],
  },
  alerts: {
    title: "Security Alerts",
    columns: ["id", "timestamp", "severity", "category", "src_ip", "dst_ip", "rule_name", "description"],
  },
  protocols: {
    title: "Protocol Metadata",
    columns: ["type", "timestamp", "session_key", "name", "detail", "risk"],
  },
  rules: {
    title: "Detection Rules",
    columns: ["id", "name", "protocol", "threshold", "window_seconds", "severity", "message"],
  },
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB"];
  let size = Number(value || 0);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function protocolRows() {
  const dns = state.dns.map((row) => ({
    type: "DNS",
    timestamp: row.timestamp,
    session_key: row.session_key,
    name: row.query_name,
    detail: `type=${row.query_type} resolver=${row.resolver} entropy=${row.entropy}`,
    risk: row.entropy >= 3.8 ? "High" : "Info",
    raw: row,
  }));
  const http = state.http.map((row) => ({
    type: "HTTP",
    timestamp: row.timestamp,
    session_key: row.session_key,
    name: `${row.method || row.status_code} ${row.uri || row.host}`,
    detail: `host=${row.host} user_agent=${row.user_agent || "n/a"}`,
    risk: String(row.uri || "").includes("login") ? "Medium" : "Info",
    raw: row,
  }));
  const tls = state.tls.map((row) => ({
    type: "TLS",
    timestamp: row.timestamp,
    session_key: row.session_key,
    name: row.sni,
    detail: `version=${row.tls_version} ja3=${row.ja3}`,
    risk: "Info",
    raw: row,
  }));
  return [...dns, ...http, ...tls].sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
}

function parseFilterTokens(clauseStr) {
  const tokens = [];
  const regex = /([a-z0-9_\-]+)\s*(==|!=|>=|<=|=|>|<|:)\s*("[^"]*"|'[^']*'|\S+)|("[^"]*"|'[^']*'|\S+)/gi;
  let match;
  while ((match = regex.exec(clauseStr)) !== null) {
    if (match[1] && match[2] && match[3]) {
      tokens.push(`${match[1]}${match[2]}${match[3].replace(/^['"]|['"]$/g, "")}`);
    } else if (match[4]) {
      const word = match[4].replace(/^['"]|['"]$/g, "");
      if (word.toLowerCase() !== "and" && word !== "&&") {
        tokens.push(word);
      }
    }
  }
  return tokens;
}

function matchSingleToken(row, token) {
  token = token.trim().toLowerCase();
  if (!token) return true;

  if (token.startsWith("!") || token.startsWith("not ")) {
    const sub = token.startsWith("!") ? token.slice(1) : token.slice(4);
    return !matchSingleToken(row, sub);
  }

  const opMatch = token.match(/^([a-z0-9_\-]+)\s*(==|!=|>=|<=|=|>|<|:)\s*(.+)$/i);
  if (opMatch) {
    let [, key, op, val] = opMatch;
    key = key.toLowerCase();
    val = val.trim().toLowerCase();

    if (key === "ip") {
      const src = String(row.src_ip || "").toLowerCase();
      const dst = String(row.dst_ip || "").toLowerCase();
      if (op === "!=") return src !== val && dst !== val;
      return src.includes(val) || dst.includes(val);
    }
    if (key === "src" || key === "src_ip") {
      const src = String(row.src_ip || "").toLowerCase();
      if (op === "!=") return src !== val;
      return src.includes(val);
    }
    if (key === "dst" || key === "dst_ip") {
      const dst = String(row.dst_ip || "").toLowerCase();
      if (op === "!=") return dst !== val;
      return dst.includes(val);
    }
    if (key === "proto" || key === "protocol") {
      const proto = String(row.protocol || row.type || "").toLowerCase();
      if (op === "!=") return proto !== val;
      return proto.includes(val);
    }
    if (key === "port") {
      const sp = String(row.src_port || "");
      const dp = String(row.dst_port || "");
      if (op === "!=") return sp !== val && dp !== val;
      return sp === val || dp === val;
    }
    if (key === "src_port" || key === "sport") {
      const sp = String(row.src_port || "");
      if (op === "!=") return sp !== val;
      return sp === val;
    }
    if (key === "dst_port" || key === "dport") {
      const dp = String(row.dst_port || "");
      if (op === "!=") return dp !== val;
      return dp === val;
    }
    if (key === "length" || key === "len" || key === "bytes") {
      const len = Number(row.length || row.bytes || 0);
      const num = Number(val);
      if (!isNaN(num)) {
        if (op === ">") return len > num;
        if (op === ">=") return len >= num;
        if (op === "<") return len < num;
        if (op === "<=") return len <= num;
        if (op === "!=") return len !== num;
        return len === num;
      }
    }

    const rowVal = String(row[key] ?? "").toLowerCase();
    if (op === "!=") return rowVal !== val;
    return rowVal.includes(val);
  }

  const rowStr = Object.values(row)
    .map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v)))
    .join(" ")
    .toLowerCase();
  return rowStr.includes(token);
}

function matchesFilter(row, filterStr) {
  if (!filterStr || !filterStr.trim()) return true;
  const raw = filterStr.trim();
  const orClauses = raw.split(/\s+or\s+|\s*\|\|\s*/i);
  for (const clause of orClauses) {
    const tokens = parseFilterTokens(clause);
    if (tokens.length === 0) continue;
    const allMatch = tokens.every((token) => matchSingleToken(row, token));
    if (allMatch) return true;
  }
  return false;
}

function rowsForView() {
  const map = {
    packets: state.packets,
    sessions: state.sessions,
    alerts: state.alerts,
    protocols: protocolRows(),
    rules: state.rules,
  };
  const rows = map[state.view] || [];
  if (!state.filter) return rows;
  return rows.filter((row) => matchesFilter(row, state.filter));
}

function renderTable() {
  const view = views[state.view];
  const map = {
    packets: state.packets,
    sessions: state.sessions,
    alerts: state.alerts,
    protocols: protocolRows(),
    rules: state.rules,
  };
  const allRows = map[state.view] || [];
  const rows = rowsForView();
  $("tableTitle").textContent = view.title;
  if (state.filter) {
    $("rowCount").textContent = `Filtered: ${rows.length} of ${allRows.length} rows`;
  } else {
    $("rowCount").textContent = `${rows.length} rows`;
  }
  $("tableHead").innerHTML = `<tr>${view.columns.map((col) => `<th>${col.replaceAll("_", " ")}</th>`).join("")}</tr>`;
  $("tableBody").innerHTML = rows
    .map((row, index) => {
      const cells = view.columns
        .map((col) => {
          const value = row[col] ?? "";
          const className = col === "protocol" || col === "type" || col === "severity" || col === "risk" ? ` class="proto ${value}"` : "";
          return `<td${className}>${escapeHtml(String(value))}</td>`;
        })
        .join("");
      return `<tr data-index="${index}">${cells}</tr>`;
    })
    .join("");
  [...$("tableBody").querySelectorAll("tr")].forEach((tr, index) => {
    tr.addEventListener("click", () => selectRow(rows[index], tr));
  });
}

function selectRow(row, tr) {
  [...document.querySelectorAll("tbody tr")].forEach((el) => el.classList.remove("selected"));
  tr.classList.add("selected");
  state.selected = row;
  const severity = row.severity || row.risk || row.protocol || row.type || "selected";
  $("severityBadge").textContent = severity;
  $("severityBadge").className = severity;
  $("detailView").textContent = JSON.stringify(row.raw || row, null, 2);
}

function renderStats(stats = state.stats) {
  state.stats = stats || {};
  if ($("packetCount")) $("packetCount").textContent = stats.packets || 0;
  if ($("sessionCount")) $("sessionCount").textContent = stats.sessions || 0;
  if ($("byteCount")) $("byteCount").textContent = formatBytes(stats.bytes || 0);

  if ($("httpCount")) $("httpCount").textContent = stats.http_count || 0;
  if ($("dnsCount")) $("dnsCount").textContent = stats.dns_count || 0;
  if ($("tlsCount")) $("tlsCount").textContent = stats.tls_count || 0;

  const pps = stats.pps || 0;
  const bps = stats.bps || 0;
  if ($("packetRateVal")) $("packetRateVal").textContent = `${pps} pps`;
  if ($("currentPps")) $("currentPps").textContent = `${pps} pps`;
  if ($("throughputRateVal")) $("throughputRateVal").textContent = `${formatBytes(bps)}/s`;

  renderBars("protocolBars", stats.protocols || [], "protocol", "count");
  renderBars("portBars", stats.top_ports || [], "port", "count");
  renderBars("talkerBars", stats.top_talkers || [], "label", "bytes", formatBytes);
}

function renderBars(id, rows, labelKey, valueKey, formatter = (v) => v) {
  const max = Math.max(1, ...rows.map((row) => Number(row[valueKey] || 0)));
  $(id).innerHTML =
    rows
      .map((row) => {
        const value = Number(row[valueKey] || 0);
        const rawLabel = row[labelKey] ?? row.src_ip ?? row.ip ?? row.src_mac ?? row.dst_ip ?? "unknown";
        const label = String(rawLabel || "unknown");
        return `<div class="bar-row"><span>${escapeHtml(label)}</span><div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div><strong>${formatter(value)}</strong></div>`;
      })
      .join("") || `<div class="empty-state">No packets captured yet. <span>i</span></div>`;
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[c]);
}

async function refreshAll() {
  const [packets, sessions, alerts, dns, http, tls, rules, stats] = await Promise.all([
    api("/packets"),
    api("/sessions"),
    api("/alerts"),
    api("/dns"),
    api("/http"),
    api("/tls"),
    api("/rules"),
    api("/statistics"),
  ]);
  Object.assign(state, { packets, sessions, alerts, dns, http, tls, rules, stats });
  renderTable();
  renderStats(stats);
}

function initWebSocket() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${location.host}/ws`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    const badge = $("wsStatusBadge");
    if (badge) {
      badge.textContent = "WS CONNECTED";
      badge.className = "badge ws-connected";
    }
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.kind === "packet") {
        state.packets.unshift(data.payload);
        state.packets = state.packets.slice(0, 1000);
        if (state.view === "packets") renderTable();
      } else if (data.kind === "alert") {
        state.alerts.unshift(data.payload);
        $("statusText").textContent = "Security alert detected!";
        if (state.view === "alerts") renderTable();
      } else if (data.kind === "stats") {
        renderStats(data.payload);
      } else if (data.kind === "status") {
        updateCaptureUi(data.payload.running, data.payload.error || "");
      } else if (data.kind === "clear") {
        clearLocalRows();
        $("statusText").textContent = data.payload.message || "All arrived packets and data cleared";
      }
    } catch (e) {}
  };

  ws.onerror = () => {
    wireEventsFallback();
  };

  ws.onclose = () => {
    const badge = $("wsStatusBadge");
    if (badge) {
      badge.textContent = "SSE FALLBACK";
      badge.className = "badge ws-disconnected";
    }
    setTimeout(initWebSocket, 4000);
  };
}

function wireEventsFallback() {
  const source = new EventSource("/events");
  source.addEventListener("packet", (event) => {
    state.packets.unshift(JSON.parse(event.data));
    state.packets = state.packets.slice(0, 1000);
    if (state.view === "packets") renderTable();
  });
  source.addEventListener("alert", (event) => {
    state.alerts.unshift(JSON.parse(event.data));
    $("statusText").textContent = "New alert received";
    if (state.view === "alerts") renderTable();
  });
  source.addEventListener("stats", (event) => renderStats(JSON.parse(event.data)));
}

function updateCaptureUi(running, error = "") {
  const modeText = "Live Npcap";
  if (running) {
    $("statusText").textContent = `Live updating packets (${modeText})...`;
    $("startBtn").classList.add("active-running");
    $("stopBtn").classList.remove("active-running");
  } else {
    $("statusText").textContent = error || `Capture stopped (${modeText})`;
    $("startBtn").classList.remove("active-running");
    $("stopBtn").classList.add("active-running");
  }
}

function clearLocalRows() {
  state.packets = [];
  state.sessions = [];
  state.alerts = [];
  state.dns = [];
  state.http = [];
  state.tls = [];
  state.selected = null;
  $("detailView").textContent = "Select a packet, session, protocol row, rule, or alert.";
  $("severityBadge").textContent = "idle";
  $("severityBadge").className = "idle";
  renderTable();
}

function bindUi() {
  [...document.querySelectorAll(".nav")].forEach((button) => {
    button.addEventListener("click", async () => {
      document.querySelector(".nav.active").classList.remove("active");
      button.classList.add("active");
      state.view = button.dataset.view;
      await refreshAll();
    });
  });
  $("filterInput").addEventListener("input", (event) => {
    state.filter = event.target.value;
    renderTable();
  });
  $("startBtn").addEventListener("click", async () => {
    clearLocalRows();
    const res = await api("/capture/start", { method: "POST", body: JSON.stringify({}) });
    updateCaptureUi(res.running, res.error || "");
  });
  $("stopBtn").addEventListener("click", async () => {
    const res = await api("/capture/stop", { method: "POST" });
    updateCaptureUi(false, res.error || "");
  });
  $("clearBtn").addEventListener("click", async () => {
    await api("/clear", { method: "DELETE" });
    clearLocalRows();
    await refreshAll();
    $("statusText").textContent = "All arrived packets and data cleared";
  });
}

bindUi();
refreshAll()
  .then(async () => {
    initWebSocket();
    try {
      const status = await api("/capture/status");
      updateCaptureUi(status.running, status.error || "");
    } catch (e) {}
  })
  .catch((error) => {
    $("statusText").textContent = error.message;
  });
