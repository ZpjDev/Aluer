import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useReducer,
  useState
} from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || data.reason || "Request failed");
  }
  return data;
}

function asRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function asText(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (asRecord(value)) {
    for (const key of ["summary", "message", "reason", "workflow", "mode", "status", "name", "id"]) {
      const nested = value[key];
      if (typeof nested === "string" || typeof nested === "number" || typeof nested === "boolean") return String(nested);
    }
    try { return JSON.stringify(value); } catch { return fallback; }
  }
  return fallback;
}

function formatPercent(value) { return `${asNumber(value).toFixed(1)}%`; }
function formatNumber(value, digits = 0) { return asNumber(value).toFixed(digits); }
function severityClass(score) {
  const n = asNumber(score);
  if (n >= 85) return "danger";
  if (n >= 60) return "warning";
  return "";
}

function terminalReducer(state, action) {
  switch (action.type) {
    case "append":
      return [...state, `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] ${action.line}`].slice(-120);
    case "clear":
      return [];
    default:
      return state;
  }
}

export default function App() {
  const [overview, setOverview] = useState(null);
  const [health, setHealth] = useState(null);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [terminalLines, dispatchTerminal] = useReducer(terminalReducer, ["[aluer] nebula console booted"]);
  const [streamState, setStreamState] = useState("connecting");
  const [lastHandshake, setLastHandshake] = useState(null);
  const [auditFilter, setAuditFilter] = useState("");
  const [commandInput, setCommandInput] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(6);
  const [showHealth, setShowHealth] = useState(false);
  const [sshForm, setSshForm] = useState({
    alias: "", host: "", port: "22", username: "", password: "", privateKeyPath: ""
  });
  const deferredAuditFilter = useDeferredValue(auditFilter);

  const addLine = (line) => dispatchTerminal({ type: "append", line });

  const refreshOverview = useEffectEvent(async (reason = "manual") => {
    try {
      const data = asRecord(await request("/api/console/overview"));
      startTransition(() => setOverview(data));
      if (reason !== "stream") addLine(`overview refreshed (${reason})`);
    } catch (error) {
      addLine(`refresh failed: ${error.message}`);
    }
  });

  const refreshHealth = useEffectEvent(async () => {
    try {
      const data = asRecord(await request("/api/health"));
      startTransition(() => setHealth(data));
    } catch {
      // health endpoint may not be deployed yet
    }
  });

  useEffect(() => { refreshOverview("boot"); refreshHealth(); }, [refreshOverview, refreshHealth]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => { refreshOverview("poll"); refreshHealth(); }, refreshInterval * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, refreshInterval, refreshOverview, refreshHealth]);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.EventSource !== "function") {
      setStreamState("degraded");
      return;
    }
    const eventSource = new EventSource(`${API_BASE}/api/console/stream/overview`);
    eventSource.addEventListener("overview", (event) => {
      try {
        const data = asRecord(JSON.parse(event.data));
        startTransition(() => setOverview(data));
        setStreamState("live");
      } catch { setStreamState("degraded"); }
    });
    eventSource.onerror = () => setStreamState("degraded");
    return () => eventSource.close();
  }, []);

  useEffect(() => {
    const sessions = asArray(overview?.ssh?.sessions);
    if (!sessions.length) { setSelectedSessionId(""); return; }
    if (!selectedSessionId || !sessions.some((s) => asText(s?.sessionId) === selectedSessionId)) {
      setSelectedSessionId(asText(sessions[0]?.sessionId));
    }
  }, [overview, selectedSessionId]);

  const safeOverview = asRecord(overview);
  const safeHealth = asRecord(health);
  const server = asRecord(safeOverview.server);
  const metrics = asRecord(server.metrics);
  const defense = asRecord(safeOverview.defense);
  const shield = asRecord(defense.shield);
  const sovereign = asRecord(defense.sovereign);
  const network = asRecord(defense.network);
  const ssh = asRecord(safeOverview.ssh);
  const kernel = asRecord(safeOverview.kernel);
  const modules = asArray(safeOverview.modules);
  const audit = asRecord(safeOverview.audit);
  const sessions = asArray(ssh.sessions);
  const engineHandshake = asRecord(ssh.engineHandshake);
  const selectedSession = sessions.find((s) => asText(s?.sessionId) === selectedSessionId);
  const healthComponents = asRecord(safeHealth.components);
  const healthSystem = asRecord(safeHealth.system);

  const mergedAuditItems = [
    ...asArray(audit.events).map((e) => ({
      id: `${asText(e?.category, "event")}-${asText(e?.action, "action")}-${asText(e?.timestamp, Date.now())}`,
      title: `${asText(e?.category, "EVENT")} / ${asText(e?.action, "ACTION")}`,
      details: `${asText(e?.player, "system")} | ${asText(e?.details, "")}`,
      score: asText(e?.category).includes("ALERT") ? 90 : 45
    })),
    ...asArray(audit.networkIncidents).map((inc, i) => ({
      id: `${asText(inc?.type, "incident")}-${asText(inc?.ip, "unknown")}-${i}`,
      title: `${asText(inc?.type, "incident")} / ${asText(inc?.ip, "unknown")}`,
      details: asText(inc?.details || inc?.summary, "network anomaly"),
      score: asNumber(inc?.riskScore, 70)
    })),
    ...asArray(audit.shieldTransitions).map((t, i) => ({
      id: `${asText(t?.mode, "shield")}-${asText(t?.timestamp, Date.now())}-${i}`,
      title: `SHIELD / ${asText(t?.mode, "TRANSITION")}`,
      details: `${asText(t?.reason, "policy update")} | risk ${asText(t?.riskScore, 80)}`,
      score: asNumber(t?.riskScore, 80)
    }))
  ];
  const auditQuery = deferredAuditFilter.trim().toLowerCase();
  const auditItems = !auditQuery
    ? mergedAuditItems.slice(0, 24)
    : mergedAuditItems.filter((item) => `${item.title} ${item.details}`.toLowerCase().includes(auditQuery)).slice(0, 24);

  async function handleShield(mode) {
    try {
      const result = await request("/api/console/shield/engage", {
        method: "POST",
        body: JSON.stringify({ mode, reason: `react-console-${mode.toLowerCase()}` })
      });
      addLine(`shield engaged: ${asText(result.mode, "unknown")}`);
      if (asText(result.deterrenceMessage)) addLine(result.deterrenceMessage);
      refreshOverview("shield");
    } catch (error) { addLine(`shield error: ${error.message}`); }
  }

  async function handleQuickAction(action) {
    try {
      const result = await request("/api/console/quick-action", {
        method: "POST",
        body: JSON.stringify({ action, reason: `react-console-${action}` })
      });
      addLine(`quick action ok: ${action}`);
      if (asText(result.mode)) addLine(`mode ${asText(result.mode)}`);
      refreshOverview(action);
    } catch (error) { addLine(`quick action failed: ${error.message}`); }
  }

  async function connectSsh(event) {
    event.preventDefault();
    try {
      const handshakeResponse = await request("/api/console/ssh/handshake", {
        method: "POST",
        body: JSON.stringify({
          host: sshForm.host,
          port: Number(sshForm.port || 22),
          username: sshForm.username,
          purpose: "react-console-connect"
        })
      });
      const handshake = asRecord(handshakeResponse.handshake);
      setLastHandshake(handshake);
      addLine(`handshake ${handshake.approved ? "approved" : "denied"} | mode=${asText(handshake.shieldMode, "unknown")} heat=${asNumber(handshake.kernelHeat)} risk=${asNumber(handshake.riskScore)}`);
      addLine(asText(handshake.message, "handshake completed"));
      if (!handshake.approved) return;
      const payload = { ...sshForm, port: Number(sshForm.port || 22), handshakeToken: handshake.token };
      const result = await request("/api/console/ssh/connect", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      const session = asRecord(result.session);
      addLine(`ssh connected: ${asText(session.alias, "remote-session")}`);
      setSelectedSessionId(asText(session.sessionId));
      setSshForm((c) => ({ ...c, password: "" }));
      refreshOverview("ssh-connect");
    } catch (error) { addLine(`ssh connect failed: ${error.message}`); }
  }

  async function executeSsh(event) {
    event.preventDefault();
    if (!selectedSessionId || !commandInput.trim()) {
      addLine("select a session and enter a command first");
      return;
    }
    const command = commandInput.trim();
    setCommandInput("");
    addLine(`${selectedSession?.alias || "session"} $ ${command}`);
    try {
      const result = await request("/api/console/ssh/execute", {
        method: "POST",
        body: JSON.stringify({ sessionId: selectedSessionId, command })
      });
      const sshResult = asRecord(result.result);
      if (sshResult.flagged) addLine(`guard: ${asText(sshResult.guardType, "unknown")} severity=${asNumber(sshResult.guardSeverity)}`);
      if (asText(sshResult.stdout)) addLine(sshResult.stdout);
      if (asText(sshResult.stderr)) addLine(`stderr: ${asText(sshResult.stderr)}`);
      addLine(`exit=${asNumber(sshResult.exitStatus)} in ${asNumber(sshResult.durationMs)}ms`);
    } catch (error) { addLine(`ssh execute failed: ${error.message}`); }
  }

  async function disconnectSsh(sessionId) {
    try {
      await request(`/api/console/ssh/${sessionId}`, { method: "DELETE" });
      addLine(`ssh disconnected: ${asText(sessionId).slice(0, 8)}`);
      refreshOverview("ssh-disconnect");
    } catch (error) { addLine(`disconnect failed: ${error.message}`); }
  }

  return (
    <div className="nebula-app">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <div className="ambient ambient-c" />
      <div className="mesh" />

      <aside className="command-rail glass-panel">
        <div>
          <p className="eyebrow">ALUER FABRIC</p>
          <h1>{asText(safeOverview.title, "Aluer Nebula Console")}</h1>
          <p className="muted">{asText(safeOverview.subtitle, "PaperMC defense, recovery, and remote operations fabric")}</p>
        </div>

        <div className="stream-badge">
          <span className={`stream-dot ${streamState}`} />
          <strong>{streamState === "live" ? "Live Stream" : "Polling Fallback"}</strong>
        </div>

        <div className="refresh-controls">
          <label className="toggle-label">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            <span>Auto-refresh</span>
          </label>
          <select className="interval-select" value={refreshInterval} onChange={(e) => setRefreshInterval(Number(e.target.value))} disabled={!autoRefresh}>
            <option value={3}>3s</option>
            <option value={6}>6s</option>
            <option value={10}>10s</option>
            <option value={30}>30s</option>
          </select>
        </div>

        <div className="rail-actions">
          <button className="primary" type="button" onClick={() => refreshOverview("manual")}>刷新总览</button>
          <button className="ghost" type="button" onClick={() => { setShowHealth(!showHealth); refreshHealth(); }}>
            {showHealth ? "隐藏健康检查" : "系统健康检查"}
          </button>
          <button className="ghost" type="button" onClick={() => handleQuickAction("backup-now")}>立即备份</button>
          <button className="ghost" type="button" onClick={() => handleQuickAction("shield-mirage")}>进入 Mirage</button>
          <button className="ghost danger" type="button" onClick={() => handleQuickAction("shield-shelter")}>进入 Shelter</button>
        </div>

        <div className="rail-metric-stack">
          <MetricCard label="TPS" value={formatNumber(metrics.tps, 1)} accent="mint" />
          <MetricCard label="CPU" value={formatPercent(metrics.cpuUsage)} accent="sky" />
          <MetricCard label="Memory" value={formatPercent(metrics.memoryUsage)} accent="sun" />
          <MetricCard label="Threat" value={shield.riskScore || 0} accent="rose" />
        </div>

        {showHealth && (
          <div className="health-panel">
            <p className="eyebrow">SYSTEM HEALTH</p>
            <div className="health-grid">
              {Object.entries(healthComponents).map(([key, comp]) => (
                <div key={key} className={`health-chip ${asText(comp?.status).includes("UP") || asText(comp?.status).includes("ENABLED") ? "up" : "down"}`}>
                  <span className="health-dot" />
                  <span>{asText(comp?.status)}</span>
                </div>
              ))}
            </div>
            {healthSystem?.uptimeSeconds && (
              <p className="muted" style={{ fontSize: "0.78rem", marginTop: 10 }}>
                Uptime: {Math.floor(asNumber(healthSystem.uptimeSeconds) / 3600)}h {Math.floor((asNumber(healthSystem.uptimeSeconds) % 3600) / 60)}m
                {" · "}Heap: {asNumber(healthSystem.heapUsedMB)}/{asNumber(healthSystem.heapMaxMB)} MB
                {" · "}Load: {asText(healthSystem.processCpuLoad, "0")}%
              </p>
            )}
          </div>
        )}
      </aside>

      <main className="main-grid">
        <section className="hero-panel glass-panel">
          <div className="hero-copy">
            <p className="eyebrow">MIRAGE SHIELD</p>
            <h2>{asText(shield.currentMode, "OBSERVE")}</h2>
            <p>{asText(shield.deterrenceMessage, "Deterrence message pending.")}</p>
            <div className="hero-pills">
              <InfoPill label="Workflow" value={asText(shield.recommendedMode, "OBSERVE")} />
              <InfoPill label="Directive" value={asText(sovereign.kernelDirective?.workflow, "MONITOR_ONLY")} />
              <InfoPill label="Handshake" value={engineHandshake.required ? "Required" : "Optional"} />
              <InfoPill label="Queue" value={asText(kernel.taskBus?.queuedTasks, 0)} />
            </div>
          </div>
          <div className="hero-side">
            <div className="hero-meters">
              <ProgressMeter label="Risk Score" value={asNumber(shield.riskScore)} />
              <ProgressMeter label="Kernel Heat" value={asNumber(shield.kernelHeat || sovereign.kernelHeat)} />
              <ProgressMeter label="Resonance" value={asNumber(shield.kernelResonance)} />
            </div>
            <div className="shield-actions">
              {["FORTIFY", "MIRAGE", "SHELTER", "RECOVERY"].map((mode) => (
                <button key={mode} type="button" className={mode === "SHELTER" ? "primary danger" : "primary"}
                  onClick={() => handleShield(mode)}>{mode}</button>
              ))}
            </div>
          </div>
        </section>

        {/* Performance Sparklines */}
        <section className="glass-panel spark-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">PERFORMANCE TREND</p>
              <h3>实时性能走势</h3>
            </div>
            <span className="chip">{server.processRunning ? "online" : "offline"}</span>
          </div>
          <div className="spark-grid">
            <SparkBar label="TPS" value={asNumber(metrics.tps)} max={20} accent="var(--mint)" />
            <SparkBar label="CPU" value={asNumber(metrics.cpuUsage)} max={100} accent="var(--sky)" />
            <SparkBar label="Memory" value={asNumber(metrics.memoryUsage)} max={100} accent="var(--sun)" />
            <SparkBar label="Players" value={asNumber(metrics.onlinePlayers)} max={50} accent="var(--rose)" />
          </div>
        </section>

        <section className="glass-panel module-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">MODULE CONSTELLATION</p>
              <h3>互联能力矩阵</h3>
            </div>
            <span className="chip">nodes {sessions.length + 1}</span>
          </div>
          <div className="module-grid">
            {modules.map((mod) => (
              <article key={asText(mod?.id, Math.random())} className={`module-card ${severityClass(mod?.signal)}`}>
                <span className="module-id">{asText(mod?.id, "module")}</span>
                <h4>{asText(mod?.name, "Unnamed Module")}</h4>
                <p>{asText(mod?.summary, "No summary available.")}</p>
                <div className="module-foot">
                  <strong>{asText(mod?.status, "UNKNOWN")}</strong>
                  <span>signal {asNumber(mod?.signal)}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="glass-panel node-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">NODE FABRIC</p>
              <h3>本地核心与远程节点</h3>
            </div>
            <span className="chip">{server.processRunning ? "local-online" : "local-degraded"}</span>
          </div>
          <div className="node-grid">
            <article className="node-card local">
              <strong>local / {asText(server.serviceName, "minecraft")}</strong>
              <p>{asText(server.workingDir, "/opt/minecraft")}</p>
              <div className="node-stats">
                <span>RCON {server.rconConnected ? "online" : "offline"}</span>
                <span>Players {asNumber(metrics.onlinePlayers)}</span>
                <span>Conn {asNumber(metrics.connections)}</span>
              </div>
            </article>
            {sessions.map((session) => (
              <article key={asText(session?.sessionId, `${asText(session?.alias, "session")}-${asText(session?.host, "unknown")}`)}
                className={`node-card remote ${asText(session?.sessionId) === selectedSessionId ? "selected" : ""}`}
                onClick={() => setSelectedSessionId(asText(session?.sessionId))}>
                <strong>{asText(session?.alias, "remote-session")}</strong>
                <p>{asText(session?.username, "user")}@{asText(session?.host, "host")}:{asText(session?.port, 22)}</p>
                <div className="node-stats">
                  <span>{asText(session?.fingerprint, "no fingerprint")}</span>
                  <button type="button" className="text-button" onClick={(e) => { e.stopPropagation(); disconnectSsh(asText(session?.sessionId)); }}>断开</button>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="glass-panel ssh-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">REMOTE SSH WORKBENCH</p>
              <h3>远程控制台</h3>
            </div>
            <span className="chip">{selectedSession?.alias || "no session"}</span>
          </div>
          <div className={`handshake-banner ${lastHandshake?.approved ? "approved" : lastHandshake ? "denied" : ""}`}>
            <strong>Sovereign Handshake</strong>
            <span>{lastHandshake ? `${lastHandshake.approved ? "approved" : "denied"} | ${asText(lastHandshake.shieldMode, "unknown")} | heat ${asNumber(lastHandshake.kernelHeat)} | risk ${asNumber(lastHandshake.riskScore)}`
              : `required=${engineHandshake.required ? "yes" : "no"} | ttl ${asNumber(engineHandshake.ttlSeconds)}s`}</span>
          </div>
          <form className="connect-form" onSubmit={connectSsh}>
            <input placeholder="别名" value={sshForm.alias} onChange={(e) => setSshForm((c) => ({ ...c, alias: e.target.value }))} />
            <input placeholder="主机" required value={sshForm.host} onChange={(e) => setSshForm((c) => ({ ...c, host: e.target.value }))} />
            <input placeholder="端口" value={sshForm.port} onChange={(e) => setSshForm((c) => ({ ...c, port: e.target.value }))} />
            <input placeholder="用户" required value={sshForm.username} onChange={(e) => setSshForm((c) => ({ ...c, username: e.target.value }))} />
            <input placeholder="密码" type="password" value={sshForm.password} onChange={(e) => setSshForm((c) => ({ ...c, password: e.target.value }))} />
            <input placeholder="私钥路径" value={sshForm.privateKeyPath} onChange={(e) => setSshForm((c) => ({ ...c, privateKeyPath: e.target.value }))} />
            <button className="primary" type="submit">连接节点</button>
          </form>
          <form className="command-form" onSubmit={executeSsh}>
            <input placeholder="输入远程命令，例如 journalctl -u minecraft -n 50" value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)} />
            <button className="ghost" type="submit">执行</button>
          </form>
          <pre className="terminal-surface">{terminalLines.join("\n")}</pre>
        </section>

        <section className="glass-panel threat-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">THREAT TRACE</p>
              <h3>高风险来源与威慑</h3>
            </div>
            <span className="chip">critical {asNumber(network.criticalRiskIPs)}</span>
          </div>
          <div className="feed-stack">
            {(asArray(shield.topOffenders).length ? asArray(shield.topOffenders) : asArray(network.topRiskIPs)).slice(0, 10).map((offender, i) => (
              <article key={`${asText(offender?.ip, "unknown")}-${i}`} className={`feed-card ${severityClass(offender?.riskScore)}`}>
                <strong>{asText(offender?.ip, "unknown")}</strong>
                <p>{asText(offender?.riskLevel, "risk")} | score {asNumber(offender?.riskScore)}</p>
                <p>{asText(offender?.summary || offender?.reason, "suspicious pressure source")}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="glass-panel audit-panel">
          <div className="section-head">
            <div>
              <p className="eyebrow">AUDIT STREAM</p>
              <h3>审计与网络事件</h3>
            </div>
            <input className="filter-input" placeholder="筛选 audit / ip / workflow" value={auditFilter}
              onChange={(e) => setAuditFilter(e.target.value)} />
          </div>
          <div className="feed-stack">
            {auditItems.map((item) => (
              <article key={item.id} className={`feed-card ${severityClass(item.score)}`}>
                <strong>{item.title}</strong>
                <p>{item.details}</p>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

function MetricCard({ label, value, accent }) {
  return (
    <article className={`metric-card ${accent}`}>
      <span>{asText(label)}</span>
      <strong>{asText(value, "0")}</strong>
    </article>
  );
}

function ProgressMeter({ label, value }) {
  const normalized = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div className="progress-meter">
      <div className="meter-head"><span>{label}</span><strong>{normalized}</strong></div>
      <div className="meter-track"><span style={{ width: `${normalized}%` }} /></div>
    </div>
  );
}

function InfoPill({ label, value }) {
  return (
    <div className="info-pill"><span>{asText(label)}</span><strong>{asText(value, "-")}</strong></div>
  );
}

function SparkBar({ label, value, max, accent }) {
  const pct = Math.min(100, Math.max(0, (Number(value) || 0) / (max || 1) * 100));
  const level = pct > 80 ? "danger" : pct > 60 ? "warning" : "";
  return (
    <div className={`spark-bar ${level}`}>
      <div className="spark-head">
        <span>{label}</span>
        <strong>{asText(value, "0")}</strong>
      </div>
      <div className="spark-track">
        <span style={{ width: `${pct}%`, background: accent }} />
      </div>
    </div>
  );
}
