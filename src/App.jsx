import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// API 베이스 URL 결정 우선순위:
//   1) VITE_EDR_API_BASE_URL 환경변수(설정 시 항상 우선)
//   2) 프로덕션 빌드: 백엔드로 직접 요청 (Cloudflare Pages 는 vercel.json
//      리라이트를 무시하므로 /edr-api 프록시가 동작하지 않는다. 백엔드는
//      ebpf-agent.com 오리진에 대해 CORS 를 허용한다.)
//   3) 로컬 개발: vite.config.js 의 /edr-api 프록시(→ 127.0.0.1:8888) 사용
const DEFAULT_API_BASE_URL = import.meta.env.PROD
  ? "https://asc4.jeonghuncompy.cloud"
  : "/edr-api";

const API_BASE_URL =
  import.meta.env.VITE_EDR_API_BASE_URL?.replace(/\/$/, "") ||
  DEFAULT_API_BASE_URL;

const EVENT_TYPES = [
  "all",
  "exec",
  "file_write",
  "file_delete",
  "file_rename",
  "net_connect",
  "net_bind",
  "dns",
  "ptrace",
  "memfd",
  "memory",
  "ns_unshare",
  "anomaly",
  "correlation",
];

const blankSeverity = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
};

function getInitialToken() {
  try {
    return localStorage.getItem("edrApiToken") || "";
  } catch {
    return "";
  }
}

function normalizeRecord(record) {
  if (record?.event) {
    return {
      ...record.event,
      record_id: record.id,
      created_at: record.created_at,
    };
  }

  return record;
}

function buildQuery(params) {
  const query = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "" && value !== false) {
      query.set(key, value);
    }
  });

  const text = query.toString();
  return text ? `?${text}` : "";
}

async function apiRequest(path, token, options = {}) {
  const headers = new Headers(options.headers);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      // JSON 오류 응답이 아닐 수 있습니다.
    }
    throw new Error(message);
  }

  return response.json();
}

function App() {
  const abortRef = useRef(null);
  const [events, setEvents] = useState([]);
  const [selectedType, setSelectedType] = useState("all");
  const [onlyAlerts, setOnlyAlerts] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [token, setToken] = useState(getInitialToken);
  const [serverStatus, setServerStatus] = useState("checking");
  const [statusMessage, setStatusMessage] = useState("백엔드 연결 확인 중");
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [totalCount, setTotalCount] = useState(0);
  const [summaryFromApi, setSummaryFromApi] = useState(null);

  const query = useMemo(
    () =>
      buildQuery({
        type: selectedType === "all" ? "" : selectedType,
        alerts_only: onlyAlerts ? "true" : "",
        q: search.trim(),
        limit: 100,
        sort: "desc",
      }),
    [onlyAlerts, search, selectedType],
  );

  const checkHealth = useCallback(async () => {
    try {
      const data = await apiRequest("/health", "");
      setServerStatus(data.status === "ok" ? "online" : "offline");
      setStatusMessage(data.status === "ok" ? "백엔드 연결됨" : "백엔드 상태 확인 필요");
    } catch (error) {
      setServerStatus("offline");
      setStatusMessage(`백엔드 연결 실패: ${error.message}`);
    }
  }, []);

  const loadSummary = useCallback(async () => {
    const data = await apiRequest("/api/v1/alerts/summary", token);
    const severity = { ...blankSeverity };
    data.items?.forEach((item) => {
      if (severity[item.severity] !== undefined) {
        severity[item.severity] = item.count;
      }
    });
    setSummaryFromApi(severity);
  }, [token]);

  const loadEvents = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest(`/api/v1/events${query}`, token);
      const nextEvents = (data.items || []).map(normalizeRecord);
      setEvents(nextEvents);
      setTotalCount(data.total ?? nextEvents.length);
      setSelectedEvent((prev) => {
        if (prev && nextEvents.some((event) => event.record_id === prev.record_id)) {
          return prev;
        }
        return nextEvents[0] || null;
      });
      setStatusMessage(`이벤트 ${nextEvents.length}건 로드됨`);
      await loadSummary();
    } catch (error) {
      setStatusMessage(`이벤트 조회 실패: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [loadSummary, query, token]);

  const stopStream = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsStreaming(false);
  }, []);

  const startStream = useCallback(async () => {
    if (isStreaming) return;

    stopStream();
    const controller = new AbortController();
    abortRef.current = controller;
    setIsStreaming(true);
    setStatusMessage("실시간 스트림 연결 중");

    try {
      const streamQuery = buildQuery({
        type: selectedType === "all" ? "" : selectedType,
        alerts_only: onlyAlerts ? "true" : "",
      });
      const response = await fetch(`${API_BASE_URL}/api/v1/events/stream${streamQuery}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });

      if (!response.ok || !response.body) {
        throw new Error(`${response.status} ${response.statusText}`);
      }

      setStatusMessage("실시간 스트림 수신 중");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() || "";

        chunks.forEach((chunk) => {
          const dataLine = chunk
            .split("\n")
            .find((line) => line.startsWith("data:"));
          if (!dataLine) return;

          const record = JSON.parse(dataLine.slice(5).trim());
          const event = normalizeRecord(record);
          setEvents((prev) => {
            const deduped = prev.filter((item) => item.record_id !== event.record_id);
            return [event, ...deduped].slice(0, 100);
          });
          setSelectedEvent((prev) => prev || event);
          setTotalCount((prev) => prev + 1);
        });
      }
    } catch (error) {
      if (error.name !== "AbortError") {
        setStatusMessage(`스트림 연결 실패: ${error.message}`);
      }
    } finally {
      setIsStreaming(false);
    }
  }, [isStreaming, onlyAlerts, selectedType, stopStream, token]);

  useEffect(() => {
    const timer = window.setTimeout(checkHealth, 0);
    return () => window.clearTimeout(timer);
  }, [checkHealth]);

  useEffect(() => {
    try {
      if (token) {
        localStorage.setItem("edrApiToken", token);
      } else {
        localStorage.removeItem("edrApiToken");
      }
    } catch {
      // localStorage를 사용할 수 없는 환경이면 입력 상태만 유지합니다.
    }
  }, [token]);

  useEffect(() => {
    const timer = window.setTimeout(loadEvents, 0);
    return () => window.clearTimeout(timer);
  }, [loadEvents]);

  useEffect(() => stopStream, [stopStream]);

  const filteredEvents = useMemo(() => {
    if (token) return events;

    return events.filter((event) => {
      const matchType = selectedType === "all" || event.type === selectedType;
      const matchAlert = !onlyAlerts || event.alerts?.length > 0;
      const matchSearch =
        search.trim() === "" ||
        JSON.stringify(event).toLowerCase().includes(search.toLowerCase());

      return matchType && matchAlert && matchSearch;
    });
  }, [events, onlyAlerts, search, selectedType, token]);

  const stats = useMemo(() => {
    const alertEvents = events.filter((event) => event.alerts?.length > 0);
    const severity = summaryFromApi || { ...blankSeverity };

    if (!summaryFromApi) {
      alertEvents.forEach((event) => {
        event.alerts?.forEach((alert) => {
          if (severity[alert.sev] !== undefined) {
            severity[alert.sev] += 1;
          }
        });
      });
    }

    const typeCount = events.reduce((acc, event) => {
      acc[event.type] = (acc[event.type] || 0) + 1;
      return acc;
    }, {});

    const topType =
      Object.entries(typeCount).sort((a, b) => b[1] - a[1])[0]?.[0] || "-";

    return {
      total: totalCount,
      alertCount: alertEvents.length,
      severity,
      topType,
    };
  }, [events, summaryFromApi, totalCount]);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const text = await file.text();
    const parsed = text
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => normalizeRecord(JSON.parse(line)));

    setEvents(parsed);
    setTotalCount(parsed.length);
    setSummaryFromApi(null);
    setSelectedEvent(parsed[0] || null);
    setStatusMessage(`로컬 로그 ${parsed.length}건 로드됨`);
  };

  const getSeverity = (event) => {
    if (!event.alerts || event.alerts.length === 0) return "-";
    return event.alerts.map((alert) => alert.sev).join(", ");
  };

  const getMainTarget = (event) => {
    return (
      event.path ||
      event.dst ||
      event.query ||
      event.name ||
      event.metric ||
      event.target_pid ||
      "-"
    );
  };

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>EDR Agent</h1>
          <p style={styles.subtitle}>이벤트 탐지 및 알람 모니터링</p>
          <p style={styles.connectionText}>
            {API_BASE_URL} · {statusMessage}
          </p>
        </div>

        <div style={styles.headerActions}>
          <span
            style={{
              ...styles.statusPill,
              ...(serverStatus === "online" ? styles.statusOnline : styles.statusOffline),
            }}
          >
            {serverStatus === "online" ? "ONLINE" : "OFFLINE"}
          </span>
          <button style={styles.actionButton} onClick={loadEvents} disabled={isLoading}>
            {isLoading ? "로딩 중" : "새로고침"}
          </button>
          <button
            style={{
              ...styles.actionButton,
              ...(isStreaming ? styles.stopButton : {}),
            }}
            onClick={isStreaming ? stopStream : startStream}
          >
            {isStreaming ? "스트림 중지" : "실시간 시작"}
          </button>
          <label style={styles.uploadButton}>
            <span style={styles.uploadIcon}>↥</span>
            로그 파일
            <input
              type="file"
              accept=".ndjson,.json,.log,.txt"
              onChange={handleFileUpload}
              style={{ display: "none" }}
            />
          </label>
        </div>
      </header>

      <section style={styles.connectionPanel}>
        <label style={styles.tokenWrap}>
          <span style={styles.typeSelectLabel}>Bearer Token</span>
          <input
            style={styles.tokenInput}
            type="password"
            placeholder="EDR_READ_TOKEN 또는 EDR_API_TOKEN"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </label>
      </section>

      <section style={styles.cardGrid}>
        <SummaryCard title="전체 이벤트" value={stats.total} />
        <SummaryCard title="알람 이벤트" value={stats.alertCount} danger />
        <SummaryCard title="가장 많은 타입" value={stats.topType} />
        <SummaryCard
          title="High 이상"
          value={stats.severity.critical + stats.severity.high}
          warning
        />
      </section>

      <section style={styles.severityBar}>
        <SeverityCard label="Critical" value={stats.severity.critical} total={stats.total} tone="critical" />
        <SeverityCard label="High" value={stats.severity.high} total={stats.total} tone="high" />
        <SeverityCard label="Medium" value={stats.severity.medium} total={stats.total} tone="medium" />
        <SeverityCard label="Low" value={stats.severity.low} total={stats.total} tone="low" />
      </section>

      <section style={styles.toolbar}>
        <label style={styles.searchWrap}>
          <Icon name="search" style={styles.searchIcon} />
          <input
            style={styles.searchInput}
            placeholder="프로세스명, 경로, IP, 도메인, 룰 이름 검색"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>

        <button
          aria-pressed={onlyAlerts}
          style={{
            ...styles.alertToggle,
            ...(onlyAlerts ? styles.alertToggleActive : {}),
          }}
          onClick={() => setOnlyAlerts((prev) => !prev)}
        >
          알람 이벤트만 보기
          <span
            style={{
              ...styles.toggleTrack,
              ...(onlyAlerts ? styles.toggleTrackActive : {}),
            }}
          >
            <span
              style={{
                ...styles.toggleThumb,
                ...(onlyAlerts ? styles.toggleThumbActive : {}),
              }}
            />
          </span>
        </button>

        <label style={styles.typeSelectWrap}>
          <span style={styles.typeSelectLabel}>이벤트 타입</span>
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            style={styles.typeSelect}
          >
            {EVENT_TYPES.map((type) => (
              <option key={type} value={type}>
                {type === "all" ? "ALL" : type}
              </option>
            ))}
          </select>
        </label>
      </section>

      <main style={styles.main}>
        <section style={styles.tableSection}>
          <h2 style={styles.sectionTitle}>이벤트 목록</h2>

          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>ID</th>
                  <th style={styles.th}>TS</th>
                  <th style={styles.th}>TYPE</th>
                  <th style={styles.th}>COMM</th>
                  <th style={styles.th}>PID</th>
                  <th style={styles.th}>UID</th>
                  <th style={styles.th}>TARGET</th>
                  <th style={styles.th}>SEVERITY</th>
                </tr>
              </thead>

              <tbody>
                {filteredEvents.map((event, index) => (
                  <tr
                    key={`${event.record_id || event.type}-${event.ts}-${index}`}
                    onClick={() => setSelectedEvent(event)}
                    style={{
                      ...styles.tr,
                      ...(event.alerts?.length > 0 ? styles.alertRow : {}),
                    }}
                  >
                    <td style={styles.td}>{event.record_id ?? "-"}</td>
                    <td style={styles.td}>{event.ts ?? "-"}</td>
                    <td style={styles.td}>
                      <span style={styles.badge}>{event.type}</span>
                    </td>
                    <td style={styles.td}>{event.comm ?? "-"}</td>
                    <td style={styles.td}>{event.pid ?? "-"}</td>
                    <td style={styles.td}>{event.uid ?? "-"}</td>
                    <td style={styles.td}>{getMainTarget(event)}</td>
                    <td style={styles.td}>{getSeverity(event)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filteredEvents.length === 0 && (
              <div style={styles.empty}>No events found</div>
            )}
          </div>
        </section>

        <aside style={styles.detailSection}>
          <h2 style={styles.sectionTitle}>이벤트 상세</h2>

          {selectedEvent ? (
            <>
              <div style={styles.detailHeader}>
                <span style={styles.badge}>{selectedEvent.type}</span>
                {selectedEvent.alerts?.length > 0 && (
                  <span style={styles.alertBadge}>ALERT</span>
                )}
              </div>

              {selectedEvent.alerts?.length > 0 && (
                <div style={styles.alertBox}>
                  {selectedEvent.alerts.map((alert) => (
                    <div key={alert.id} style={styles.alertItem}>
                      <strong>{alert.name}</strong>
                      <span>
                        {alert.id} / {alert.sev}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <pre style={styles.jsonBox}>
                <code style={styles.jsonCode}>
                  <HighlightedJson data={selectedEvent} />
                </code>
              </pre>
            </>
          ) : (
            <div style={styles.empty}>선택된 이벤트가 없습니다.</div>
          )}
        </aside>
      </main>
    </div>
  );
}

function SummaryCard({ title, value, danger, warning }) {
  return (
    <div style={styles.card}>
      <p style={styles.cardTitle}>{title}</p>
      <strong
        style={{
          ...styles.cardValue,
          color: danger || warning ? "#ef4444" : "#111827",
        }}
      >
        {value}
      </strong>
    </div>
  );
}

function SeverityCard({ label, value, total, tone }) {
  const toneStyle = styles.severityTone[tone] || styles.severityTone.low;
  const width = total > 0 ? Math.min(100, (value / total) * 100) : 0;

  return (
    <div style={styles.severityCard}>
      <div style={styles.severityTop}>
        <span style={{ ...styles.severityName, color: toneStyle.color }}>{label}</span>
        <span style={{ ...styles.severityNum, color: toneStyle.color }}>{value}</span>
      </div>
      <div style={styles.severityTrack}>
        <div
          style={{
            ...styles.severityFill,
            width: `${width}%`,
            background: toneStyle.fill,
          }}
        />
      </div>
    </div>
  );
}

function HighlightedJson({ data }) {
  const lines = JSON.stringify(data, null, 2).split("\n");

  return lines.map((line, index) => {
    const keyMatch = line.match(/^(\s*)"([^"]+)":(.*)$/);
    const pathMatch = line.match(/^(\s*)"([^"]*(?:\/|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[^"]*)"(,?)$/);

    if (keyMatch) {
      const [, indent, key, rest] = keyMatch;
      const keyStyle = key === "alerts" ? styles.jsonAlertKey : styles.jsonKey;
      const valueStyle =
        rest.includes("/") || rest.includes("203.0.113.1")
          ? styles.jsonPathValue
          : styles.jsonValue;

      return (
        <span key={`${line}-${index}`} style={styles.jsonLine}>
          {indent}
          <span style={keyStyle}>"{key}"</span>
          <span style={styles.jsonPunctuation}>:</span>
          <span style={valueStyle}>{rest}</span>
          {"\n"}
        </span>
      );
    }

    if (pathMatch) {
      const [, indent, value, comma] = pathMatch;
      return (
        <span key={`${line}-${index}`} style={styles.jsonLine}>
          {indent}
          <span style={styles.jsonPathValue}>"{value}"</span>
          {comma}
          {"\n"}
        </span>
      );
    }

    return (
      <span key={`${line}-${index}`} style={styles.jsonLine}>
        {line}
        {index < lines.length - 1 ? "\n" : ""}
      </span>
    );
  });
}

function Icon({ name, style }) {
  const common = {
    width: 16,
    height: 16,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    style,
  };

  const paths = {
    search: (
      <>
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </>
    ),
  };

  return <svg {...common}>{paths[name]}</svg>;
}

const styles = {
  page: {
    minHeight: "100vh",
    background: "var(--color-background)",
    color: "var(--color-text)",
    width: "100%",
    maxWidth: "100%",
    boxSizing: "border-box",
    padding: "22px 20px 28px",
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "16px",
    flexWrap: "wrap",
    marginBottom: "14px",
  },
  title: {
    margin: 0,
    fontSize: "28px",
    fontWeight: 800,
    lineHeight: 1.1,
  },
  subtitle: {
    margin: "6px 0 0",
    color: "#111827",
    fontSize: "16px",
  },
  connectionText: {
    margin: "8px 0 0",
    color: "#6b7280",
    fontSize: "13px",
  },
  headerActions: {
    display: "flex",
    alignItems: "center",
    justifyContent: "flex-end",
    gap: "8px",
    flexWrap: "wrap",
  },
  statusPill: {
    height: "38px",
    display: "inline-flex",
    alignItems: "center",
    padding: "0 12px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 800,
    border: "0.5px solid var(--color-border-tertiary)",
  },
  statusOnline: {
    color: "#166534",
    background: "#dcfce7",
  },
  statusOffline: {
    color: "#991b1b",
    background: "#fee2e2",
  },
  actionButton: {
    background: "#111827",
    color: "white",
    padding: "10px 14px",
    border: "1px solid #111827",
    borderRadius: "8px",
    cursor: "pointer",
    fontWeight: 700,
    fontSize: "13px",
    height: "38px",
  },
  stopButton: {
    background: "#991b1b",
    borderColor: "#991b1b",
  },
  uploadButton: {
    background: "white",
    color: "#111827",
    padding: "10px 14px",
    border: "1px solid #d1d5db",
    borderRadius: "8px",
    cursor: "pointer",
    fontWeight: 700,
    fontSize: "13px",
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
    height: "38px",
    boxSizing: "border-box",
  },
  uploadIcon: {
    fontSize: "16px",
    lineHeight: 1,
  },
  connectionPanel: {
    marginBottom: "16px",
    background: "var(--color-background-secondary)",
    border: "0.5px solid var(--color-border-tertiary)",
    borderRadius: "var(--border-radius-lg)",
    padding: "12px",
  },
  tokenWrap: {
    display: "flex",
    alignItems: "center",
    gap: "14px",
    width: "100%",
  },
  tokenInput: {
    flex: 1,
    minWidth: 0,
    height: "40px",
    border: "0.5px solid var(--color-border-tertiary)",
    borderRadius: "10px",
    padding: "0 12px",
    fontSize: "14px",
    outline: "none",
  },
  cardGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
    gap: "10px",
    marginBottom: "16px",
  },
  card: {
    background: "var(--color-background-secondary)",
    padding: "16px",
    border: "0.5px solid var(--color-border-tertiary)",
    borderRadius: "var(--border-radius-lg)",
    minHeight: "82px",
    boxShadow: "none",
  },
  cardTitle: {
    margin: 0,
    color: "var(--color-text-muted)",
    fontSize: "12px",
    fontWeight: 500,
  },
  cardValue: {
    display: "block",
    marginTop: "10px",
    fontSize: "26px",
    lineHeight: 1,
  },
  severityBar: {
    display: "grid",
    gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
    gap: "8px",
    marginBottom: "18px",
  },
  severityCard: {
    borderRadius: "var(--border-radius-lg)",
    border: "0.5px solid var(--color-border-tertiary)",
    padding: "10px 14px",
    display: "flex",
    flexDirection: "column",
    gap: "6px",
    minWidth: 0,
  },
  severityTop: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "12px",
  },
  severityName: {
    fontSize: "12px",
    fontWeight: 500,
  },
  severityNum: {
    fontSize: "20px",
    fontWeight: 500,
    lineHeight: 1,
  },
  severityTrack: {
    height: "4px",
    background: "var(--color-border-tertiary)",
    borderRadius: "2px",
    overflow: "hidden",
  },
  severityFill: {
    height: "100%",
    borderRadius: "2px",
  },
  severityTone: {
    critical: { color: "#791F1F", fill: "#E24B4A" },
    high: { color: "#633806", fill: "#EF9F27" },
    medium: { color: "#0C447C", fill: "#378ADD" },
    low: { color: "var(--color-text-muted)", fill: "#639922" },
  },
  toolbar: {
    display: "flex",
    gap: "12px",
    marginBottom: "20px",
    alignItems: "stretch",
    flexWrap: "wrap",
    width: "100%",
  },
  searchWrap: {
    flex: "1 1 320px",
    minWidth: "280px",
    height: "46px",
    position: "relative",
    display: "flex",
    alignItems: "center",
  },
  searchIcon: {
    position: "absolute",
    left: "14px",
    color: "var(--color-text-muted)",
    pointerEvents: "none",
  },
  searchInput: {
    width: "100%",
    height: "46px",
    boxSizing: "border-box",
    padding: "13px 14px 13px 42px",
    borderRadius: "12px",
    border: "0.5px solid var(--color-border-tertiary)",
    fontSize: "14px",
    outline: "none",
  },
  alertToggle: {
    border: "0.5px solid var(--color-border-tertiary)",
    background: "white",
    color: "#374151",
    borderRadius: "12px",
    padding: "0 10px 0 16px",
    width: "220px",
    height: "46px",
    boxSizing: "border-box",
    fontWeight: 600,
    cursor: "pointer",
    minHeight: "46px",
    display: "inline-flex",
    alignItems: "center",
    gap: "10px",
    outline: "none",
    boxShadow: "0 1px 2px rgba(17, 24, 39, 0.05)",
  },
  alertToggleActive: {
    background: "white",
    color: "#374151",
  },
  toggleTrack: {
    width: "42px",
    height: "24px",
    borderRadius: "999px",
    background: "#e5e7eb",
    position: "relative",
    transition: "background 160ms ease",
  },
  toggleTrackActive: {
    background: "#fee2e2",
  },
  toggleThumb: {
    position: "absolute",
    top: "3px",
    left: "3px",
    width: "18px",
    height: "18px",
    borderRadius: "999px",
    background: "white",
    boxShadow: "0 1px 3px rgba(17, 24, 39, 0.24)",
    transition: "transform 160ms ease",
  },
  toggleThumbActive: {
    transform: "translateX(18px)",
    background: "var(--color-text-danger)",
  },
  typeSelectWrap: {
    border: "0.5px solid var(--color-border-tertiary)",
    background: "white",
    color: "#374151",
    borderRadius: "12px",
    padding: "0 14px",
    width: "250px",
    height: "46px",
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "14px",
    boxShadow: "0 1px 2px rgba(17, 24, 39, 0.05)",
  },
  typeSelectLabel: {
    color: "#6b7280",
    fontSize: "12px",
    fontWeight: 800,
    whiteSpace: "nowrap",
  },
  typeSelect: {
    border: "none",
    outline: "none",
    background: "transparent",
    color: "#111827",
    cursor: "pointer",
    fontSize: "15px",
    fontWeight: 800,
    flex: 1,
    minWidth: 0,
  },
  main: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 520px), 1fr))",
    gap: "20px",
  },
  tableSection: {
    background: "white",
    border: "0.5px solid var(--color-border-tertiary)",
    borderRadius: "var(--border-radius-lg)",
    padding: "20px",
    boxShadow: "none",
  },
  detailSection: {
    background: "white",
    border: "0.5px solid var(--color-border-tertiary)",
    borderRadius: "var(--border-radius-lg)",
    padding: "20px",
    boxShadow: "none",
  },
  sectionTitle: {
    marginTop: 0,
    fontSize: "18px",
  },
  tableWrapper: {
    overflowX: "auto",
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: "14px",
  },
  th: {
    textAlign: "left",
    padding: "12px",
    borderBottom: "0.5px solid var(--color-border-tertiary)",
    background: "var(--color-background-secondary)",
    color: "var(--color-text-muted)",
    fontWeight: 700,
    fontSize: "11px",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
  },
  td: {
    padding: "12px",
    borderBottom: "0.5px solid var(--color-border-tertiary)",
    verticalAlign: "top",
  },
  tr: {
    cursor: "pointer",
  },
  alertRow: {
    background: "#fff7f7",
  },
  badge: {
    display: "inline-block",
    background: "#eef2ff",
    color: "#3730a3",
    padding: "4px 8px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 700,
  },
  alertBadge: {
    display: "inline-block",
    background: "#fee2e2",
    color: "#b91c1c",
    padding: "4px 8px",
    borderRadius: "999px",
    fontSize: "12px",
    fontWeight: 800,
  },
  detailHeader: {
    display: "flex",
    gap: "8px",
    marginBottom: "14px",
  },
  alertBox: {
    background: "#fff7f7",
    border: "0.5px solid #fecaca",
    borderRadius: "var(--border-radius-lg)",
    padding: "12px",
    marginBottom: "14px",
  },
  alertItem: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    fontSize: "14px",
  },
  jsonBox: {
    background: "#1a1c1e",
    color: "#e5e7eb",
    padding: "16px",
    border: "0.5px solid #2f3337",
    borderRadius: "var(--border-radius-lg)",
    overflowX: "auto",
    fontSize: "13px",
    lineHeight: 1.5,
  },
  jsonCode: {
    background: "transparent",
    color: "inherit",
    padding: 0,
    borderRadius: 0,
    display: "block",
    fontSize: "inherit",
    lineHeight: "inherit",
  },
  jsonLine: {
    whiteSpace: "pre",
  },
  jsonKey: {
    color: "#93c5fd",
  },
  jsonAlertKey: {
    color: "#fca5a5",
  },
  jsonPunctuation: {
    color: "#9ca3af",
  },
  jsonValue: {
    color: "#e5e7eb",
  },
  jsonPathValue: {
    color: "#fde68a",
  },
  empty: {
    padding: "24px",
    textAlign: "center",
    color: "#6b7280",
  },
};

export default App;
