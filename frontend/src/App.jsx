import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
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

function appendLine(setTerminalLines, line) {
  setTerminalLines((current) => {
    const next = [...current, `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] ${asText(line, "event")}`];
    return next.slice(-120);
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asRecord(value) {
  return isRecord(value) ? value : {};
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function asText(value, fallback = "") {
  if (value === null || value === undefined) {
    return fallback;
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (isRecord(value)) {
    for (const key of ["summary", "message", "reason", "workflow", "mode", "status", "name", "id"]) {
      const nested = value[key];
      if (typeof nested === "string" || typeof nested === "number" || typeof nested === "boolean") {
        return String(nested);
      }
    }
    try {
      return JSON.stringify(value);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

function formatPercent(value) {
  return `${asNumber(value).toFixed(1)}%`;
}

function formatNumber(value, digits = 0) {
  return asNumber(value).toFixed(digits);
}

function severityClass(score) {
  const normalized = asNumber(score);
  if (normalized >= 85) return "danger";
  if (normalized >= 60) return "warning";
  return "";
}

export default function App() {
  const [overview, setOverview] = useState(null);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [terminalLines, setTerminalLines] = useState(["[aluer] nebula console booted"]);
  const [streamState, setStreamState] = useState("connecting");
  const [lastHandshake, setLastHandshake] = useState(null);
  const [auditFilter, setAuditFilter] = useState("");
  const [commandInput, setCommandInput] = useState("");
  const [sshForm, setSshForm] = useState({
    alias: "",
    host: "",
    port: "22",
    username: "",
    password: "",
    privateKeyPath: ""
  });
  const deferredAuditFilter = useDeferredValue(auditFilter);

  const refreshOverview = useEffectEvent(async (reason = "manual") => {
    try {
      const data = asRecord(await request("/api/console/overview"));
      startTransition(() => setOverview(data));
      if (reason !== "stream") {
        appendLine(setTerminalLines, `overview refreshed (${reason})`);
      }
    } catch (error) {
      appendLine(setTerminalLines, `refresh failed: ${error.message}`);
    }
  });

  useEffect(() => {
    refreshOverview("boot");
  }, [refreshOverview]);

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
      } catch {
        setStreamState("degraded");
      }
    });
    eventSource.onerror = () => {
      setStreamState("degraded");
    };
    return () => {
      eventSource.close();
    };
  }, []);

  useEffect(() => {
    const sessions = asArray(overview?.ssh?.sessions);
    if (!sessions.length) {
      setSelectedSessionId("");
      return;
    }
    if (!selectedSessionId || !sessions.some((session) => asText(session?.sessionId) === selectedSessionId)) {
      setSelectedSessionId(asText(sessions[0]?.sessionId));
    }
  }, [overview, selectedSessionId]);

  const safeOverview = asRecord(overview);
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
  const selectedSession = sessions.find((session) => asText(session?.sessionId) === selectedSessionId);
  const mergedAuditItems = [
    ...asArray(audit.events).map((event) => ({
      id: `${asText(event?.category, "event")}-${asText(event?.action, "action")}-${asText(event?.timestamp, Date.now())}`,
      title: `${asText(event?.category, "EVENT")} / ${asText(event?.action, "ACTION")}`,
      details: `${asText(event?.player, "system")} | ${asText(event?.details, "")}`,
      score: asText(event?.category).includes("ALERT") ? 90 : 45
    })),
    ...asArray(audit.networkIncidents).map((incident, index) => ({
      id: `${asText(incident?.type, "incident")}-${asText(incident?.ip, "unknown")}-${index}`,
      title: `${asText(incident?.type, "incident")} / ${asText(incident?.ip, "unknown")}`,
      details: asText(incident?.details || incident?.summary, "network anomaly"),
      score: asNumber(incident?.riskScore, 70)
    })),
    ...asArray(audit.shieldTransitions).map((transition, index) => ({
      id: `${asText(transition?.mode, "shield")}-${asText(transition?.timestamp, Date.now())}-${index}`,
      title: `SHIELD / ${asText(transition?.mode, "TRANSITION")}`,
      details: `${asText(transition?.reason, "policy update")} | risk ${asText(transition?.riskScore, 80)}`,
      score: asNumber(transition?.riskScore, 80)
    }))
  ];
  const auditQuery = deferredAuditFilter.trim().toLowerCase();
  const auditItems = !auditQuery
    ? mergedAuditItems.slice(0, 18)
    : mergedAuditItems.filter((item) =>
        `${item.title} ${item.details}`.toLowerCase().includes(auditQuery)
      ).slice(0, 18);

  async function handleShield(mode) {
    try {
      const result = await request("/api/console/shield/engage", {
        method: "POST",
        body: JSON.stringify({
          mode,
          reason: `react-console-${mode.toLowerCase()}`
        })
      });
      appendLine(setTerminalLines, `shield engaged: ${asText(result.mode, "unknown")}`);
      if (asText(result.deterrenceMessage)) {
        appendLine(setTerminalLines, result.deterrenceMessage);
      }
      refreshOverview("shield");
    } catch (error) {
      appendLine(setTerminalLines, `shield error: ${error.message}`);
    }
  }

  async function handleQuickAction(action) {
    try {
      const result = await request("/api/console/quick-action", {
        method: "POST",
        body: JSON.stringify({
          action,
          reason: `react-console-${action}`
        })
      });
      appendLine(setTerminalLines, `quick action ok: ${action}`);
      if (asText(result.mode)) {
        appendLine(setTerminalLines, `mode ${asText(result.mode)}`);
      }
      refreshOverview(action);
    } catch (error) {
      appendLine(setTerminalLines, `quick action failed: ${error.message}`);
    }
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
      appendLine(
        setTerminalLines,
        `handshake ${handshake.approved ? "approved" : "denied"} | mode=${asText(handshake.shieldMode, "unknown")} heat=${asNumber(handshake.kernelHeat)} risk=${asNumber(handshake.riskScore)}`
      );
      appendLine(setTerminalLines, asText(handshake.message, "handshake completed"));
      if (!handshake.approved) {
        return;
      }

      const payload = {
        ...sshForm,
        port: Number(sshForm.port || 22),
        handshakeToken: handshake.token
      };
      const result = await request("/api/console/ssh/connect", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      const session = asRecord(result.session);
      appendLine(setTerminalLines, `ssh connected: ${asText(session.alias, "remote-session")}`);
      setSelectedSessionId(asText(session.sessionId));
      setSshForm((current) => ({ ...current, password: "" }));
      refreshOverview("ssh-connect");
    } catch (error) {
      appendLine(setTerminalLines, `ssh connect failed: ${error.message}`);
    }
  }

  async function executeSsh(event) {
    event.preventDefault();
    if (!selectedSessionId || !commandInput.trim()) {
      appendLine(setTerminalLines, "select a session and enter a command first");
      return;
    }
    const command = commandInput.trim();
    setCommandInput("");
    appendLine(setTerminalLines, `${selectedSession?.alias || "session"} $ ${command}`);
    try {
      const result = await request("/api/console/ssh/execute", {
        method: "POST",
        body: JSON.stringify({
          sessionId: selectedSessionId,
          command
        })
      });
      const sshResult = asRecord(result.result);
      if (sshResult.flagged) {
        appendLine(setTerminalLines, `guard: ${asText(sshResult.guardType, "unknown")} severity=${asNumber(sshResult.guardSeverity)}`);
      }
      if (asText(sshResult.stdout)) {
        appendLine(setTerminalLines, sshResult.stdout);
      }
      if (asText(sshResult.stderr)) {
        appendLine(setTerminalLines, `stderr: ${asText(sshResult.stderr)}`);
      }
      appendLine(setTerminalLines, `exit=${asNumber(sshResult.exitStatus)} in ${asNumber(sshResult.durationMs)}ms`);
    } catch (error) {
      appendLine(setTerminalLines, `ssh execute failed: ${error.message}`);
    }
  }

  async function disconnectSsh(sessionId) {
    try {
      await request(`/api/console/ssh/${sessionId}`, { method: "DELETE" });
      appendLine(setTerminalLines, `ssh disconnected: ${asText(sessionId).slice(0, 8)}`);
      refreshOverview("ssh-disconnect");
    } catch (error) {
      appendLine(setTerminalLines, `disconnect failed: ${error.message}`);
    }
  }

  return (
    <div className="nebula-app">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <div className="mesh" />

      <aside className="command-rail glass-panel">
        <div>
          <p className="eyebrow">ALUER FABRIC</p>
          <h1>{asText(safeOverview.title, "Aluer Nebula Console")}</h1>
          <p className="muted">{asText(safeOverview.subtitle, "PaperMC defense and recovery fabric")}</p>
        </div>

        <div className="stream-badge">
          <span className={`stream-dot ${streamState}`} />
          <strong>{streamState === "live" ? "Live Stream" : "Polling Fallback"}</strong>
        </div>

        <div className="rail-actions">
          <button className="primary" type="button" onClick={() => refreshOverview("manual")}>刷新总览</button>
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
                <button
                  key={mode}
                  type="button"
                  className={mode === "SHELTER" ? "primary danger" : "primary"}
                  onClick={() => handleShield(mode)}
                >
                  {mode}
                </button>
              ))}
            </div>
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
            {modules.map((module) => (
              <article key={asText(module?.id, Math.random())} className={`module-card ${severityClass(module?.signal)}`}>
                <span className="module-id">{asText(module?.id, "module")}</span>
                <h4>{asText(module?.name, "Unnamed Module")}</h4>
                <p>{asText(module?.summary, "No summary available.")}</p>
                <div className="module-foot">
                  <strong>{asText(module?.status, "UNKNOWN")}</strong>
                  <span>signal {asNumber(module?.signal)}</span>
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
              <article
                key={asText(session?.sessionId, `${asText(session?.alias, "session")}-${asText(session?.host, "unknown")}`)}
                className={`node-card remote ${asText(session?.sessionId) === selectedSessionId ? "selected" : ""}`}
                onClick={() => setSelectedSessionId(asText(session?.sessionId))}
              >
                <strong>{asText(session?.alias, "remote-session")}</strong>
                <p>{asText(session?.username, "user")}@{asText(session?.host, "host")}:{asText(session?.port, 22)}</p>
                <div className="node-stats">
                  <span>{asText(session?.fingerprint, "no fingerprint")}</span>
                  <button
                    type="button"
                    className="text-button"
                    onClick={(event) => {
                      event.stopPropagation();
                      disconnectSsh(asText(session?.sessionId));
                    }}
                  >
                    断开
                  </button>
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
            <span>
              {lastHandshake
                ? `${lastHandshake.approved ? "approved" : "denied"} | ${asText(lastHandshake.shieldMode, "unknown")} | heat ${asNumber(lastHandshake.kernelHeat)} | risk ${asNumber(lastHandshake.riskScore)}`
                : `required=${engineHandshake.required ? "yes" : "no"} | ttl ${asNumber(engineHandshake.ttlSeconds)}s`}
            </span>
          </div>

          <form className="connect-form" onSubmit={connectSsh}>
            <input placeholder="别名" value={sshForm.alias} onChange={(event) => setSshForm((current) => ({ ...current, alias: event.target.value }))} />
            <input placeholder="主机" required value={sshForm.host} onChange={(event) => setSshForm((current) => ({ ...current, host: event.target.value }))} />
            <input placeholder="端口" value={sshForm.port} onChange={(event) => setSshForm((current) => ({ ...current, port: event.target.value }))} />
            <input placeholder="用户" required value={sshForm.username} onChange={(event) => setSshForm((current) => ({ ...current, username: event.target.value }))} />
            <input placeholder="密码" type="password" value={sshForm.password} onChange={(event) => setSshForm((current) => ({ ...current, password: event.target.value }))} />
            <input placeholder="私钥路径(可选)" value={sshForm.privateKeyPath} onChange={(event) => setSshForm((current) => ({ ...current, privateKeyPath: event.target.value }))} />
            <button className="primary" type="submit">连接节点</button>
          </form>

          <form className="command-form" onSubmit={executeSsh}>
            <input
              placeholder="输入远程命令，例如 journalctl -u minecraft -n 50"
              value={commandInput}
              onChange={(event) => setCommandInput(event.target.value)}
            />
            <button className="ghost" type="submit">执行命令</button>
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
            {(asArray(shield.topOffenders).length ? asArray(shield.topOffenders) : asArray(network.topRiskIPs)).slice(0, 8).map((offender, index) => (
              <article key={`${asText(offender?.ip, "unknown")}-${index}`} className={`feed-card ${severityClass(offender?.riskScore)}`}>
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
            <input
              className="filter-input"
              placeholder="筛选 audit / ip / workflow"
              value={auditFilter}
              onChange={(event) => setAuditFilter(event.target.value)}
            />
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
      <div className="meter-head">
        <span>{label}</span>
        <strong>{normalized}</strong>
      </div>
      <div className="meter-track">
        <span style={{ width: `${normalized}%` }} />
      </div>
    </div>
  );
}

function InfoPill({ label, value }) {
  return (
    <div className="info-pill">
      <span>{asText(label)}</span>
      <strong>{asText(value, "-")}</strong>
    </div>
  );
}
