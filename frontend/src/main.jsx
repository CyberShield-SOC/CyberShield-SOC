import React, { useMemo, useRef, useState } from 'react';

const SEVERITY_STYLE = {
  HIGH:   { border: '#EF4444', text: 'text-[#EF4444]' },
  MEDIUM: { border: '#F59E0B', text: 'text-[#F59E0B]' },
  LOW:    { border: '#6B7280', text: 'text-white/40'  },
};

const RULE_LABELS = {
  brute_force_login:        'Brute-Force Login',
  invalid_user_enumeration: 'Username Enumeration',
  sudo_failure:             'Sudo Failure',
};

function AlertCard({ alert }) {
  const style = SEVERITY_STYLE[alert.severity] || SEVERITY_STYLE.LOW;
  return (
    <div className="rounded-md border-l-2 bg-[#0D1117] px-3 py-2.5" style={{ borderColor: style.border }}>
      <p className={`text-[10px] font-bold uppercase tracking-wider ${style.text}`}>
        {alert.severity} — {RULE_LABELS[alert.rule] || alert.rule}
      </p>
      <p className="mt-1 text-xs leading-relaxed text-white/50">{alert.description}</p>
      {alert.source_ip && (
        <p className="mt-1 font-mono text-[10px] text-white/30">
          {alert.source_ip} · {alert.count} events · {alert.time_window_seconds}s window
        </p>
      )}
    </div>
  );
}
import { createRoot } from 'react-dom/client';
import './styles.css';

const ACCEPTED_EXTENSIONS = ['log', 'csv'];

const SAMPLE_LOGS = [
  { timestamp: 'Jun 14 02:11:43', ip: '203.0.113.4', username: 'root',  event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:11:45', ip: '203.0.113.4', username: 'root',  event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:11:47', ip: '203.0.113.4', username: 'root',  event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:11:49', ip: '203.0.113.4', username: 'root',  event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:11:51', ip: '203.0.113.4', username: 'root',  event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:12:01', ip: '203.0.113.4', username: 'admin', event: 'login_attempt',       status: 'FAILED'  },
  { timestamp: 'Jun 14 02:15:11', ip: '',             username: 'jdoe',  event: 'privilege_escalation', status: 'FAILED' },
  { timestamp: 'Jun 14 02:15:14', ip: '',             username: 'jdoe',  event: 'privilege_escalation', status: 'FAILED' },
  { timestamp: 'Jun 14 02:18:25', ip: '10.0.0.5',    username: 'jdoe',  event: 'login_attempt',       status: 'SUCCESS' },
  { timestamp: 'Jun 14 02:19:01', ip: '10.0.0.5',    username: '',      event: 'connection_closed',   status: 'INFO'    },
];

const extensionOf = (name) => name.split('.').pop()?.toLowerCase() || '';

function StatusBadge({ status }) {
  const cls =
    status === 'FAILED'  ? 'bg-[#B91C1C] text-white' :
    status === 'SUCCESS' ? 'bg-[#15803D] text-white' :
                           'bg-[#374151] text-white/60';
  return (
    <span className={`rounded px-2 py-0.5 text-[10px] font-mono font-semibold tracking-[.08em] ${cls}`}>
      {status}
    </span>
  );
}

function App() {
  const [files, setFiles]               = useState([]);
  const [logs, setLogs]                 = useState(SAMPLE_LOGS);
  const [alerts, setAlerts]             = useState([]);
  const [query, setQuery]               = useState('');
  const [logQuery, setLogQuery]         = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [dragging, setDragging]         = useState(false);
  const [message, setMessage]           = useState('Sample SOC logs are loaded. Upload files to analyze your own data.');
  const inputRef = useRef(null);

  const addFiles = async (fileList) => {
    const incoming  = Array.from(fileList || []);
    const supported = incoming.filter((f) => ACCEPTED_EXTENSIONS.includes(extensionOf(f.name)));
    const rejected  = incoming.length - supported.length;
    const parsedBatches = [];
    const fileSummaries = [];
    const allAlerts     = [];

    for (const file of supported) {
      const formData = new FormData();
      formData.append('logfile', file);
      try {
        const res  = await fetch('/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok || !data.success) {
          setMessage(data.detail?.error || data.error || `Failed to parse ${file.name}.`);
          continue;
        }
        const parsed = data.entries.map((entry) => ({
          timestamp: entry.parsed.timestamp   || '',
          ip:        entry.parsed.ip_address  || '',
          username:  entry.parsed.username    || '',
          event:     entry.parsed.event_type  || 'Log Entry',
          status:   (entry.parsed.status      || 'UNKNOWN').toUpperCase(),
        }));
        parsedBatches.push(...parsed);
        fileSummaries.push({ name: file.name, size: file.size, type: extensionOf(file.name), rows: parsed.length });
        allAlerts.push(...(data.alerts || []));
      } catch (err) {
        setMessage(`Error uploading ${file.name}: ${err.message}`);
      }
    }

    if (fileSummaries.length) {
      setFiles((cur) => [...fileSummaries, ...cur]);
      setLogs(parsedBatches);
      setAlerts(allAlerts);
      setMessage(`${fileSummaries.length} file(s) parsed successfully${rejected ? `; ${rejected} unsupported file(s) skipped` : ''}.`);
    } else if (rejected) {
      setMessage('Unsupported file type. Please upload .log or .csv files.');
    }
  };

  const stats = useMemo(() => {
    const failures  = logs.filter((l) => l.status === 'FAILED').length;
    const successes = logs.filter((l) => l.status === 'SUCCESS').length;
    const uniqueIps = new Set(logs.map((l) => l.ip).filter(Boolean)).size;
    const hotIps    = logs.reduce((acc, l) => (l.ip ? { ...acc, [l.ip]: (acc[l.ip] || 0) + 1 } : acc), {});
    const topIp     = Object.entries(hotIps).sort((a, b) => b[1] - a[1])[0];
    return { failures, successes, uniqueIps, topIp };
  }, [logs]);

  const filteredFiles = files.filter((f) => f.name.toLowerCase().includes(query.toLowerCase()));
  const filteredLogs  = logs.filter((l) => {
    const hay = Object.values(l).join(' ').toLowerCase();
    return hay.includes(logQuery.toLowerCase()) && (statusFilter === 'ALL' || l.status === statusFilter);
  });

  const total      = Math.max(logs.length, 1);
  const failPct    = Math.round((stats.failures  / total) * 100);
  const successPct = Math.round((stats.successes / total) * 100);
  const otherCount = logs.length - stats.failures - stats.successes;
  const otherPct   = 100 - failPct - successPct;
  // conic-gradient stop positions
  const failStop    = failPct;
  const successStop = failPct + successPct;

  return (
    <main className="min-h-screen bg-[#0D1117] text-white">
      <section className="mx-auto flex w-full max-w-7xl flex-col gap-5 px-4 py-5 sm:px-6 lg:px-8">

        {/* ── Hero ── */}
        <header className="rounded-xl border border-white/10 bg-[#161B22] overflow-hidden">
          <div className="grid gap-5 p-6 lg:grid-cols-[1.3fr_.65fr] lg:p-8">

            <div className="flex flex-col justify-center">
              <p className="mb-4 inline-flex w-fit items-center rounded border border-[#58A6FF]/25 bg-[#58A6FF]/10 px-2.5 py-1 text-[10px] font-bold tracking-[.16em] text-[#58A6FF]">
                CYBERSHIELD SOC — SPRINT 1
              </p>
              <h1 className="font-display text-3xl font-semibold leading-[1.15] tracking-[-0.02em] [text-shadow:none] sm:text-4xl lg:text-[2.75rem]">
                Centralized log monitoring and threat detection.
              </h1>
              <p className="mt-3 max-w-xl text-sm leading-relaxed text-white/45 sm:text-base">
                Upload .log or .csv files to detect failed logins, invalid users, privilege escalation, and connection events.
              </p>
            </div>

            {/* KPI tile */}
            <div className="rounded-lg border border-white/10 bg-[#0D1117] p-5">
              <p className="text-[9px] font-medium uppercase tracking-[.23em] text-white/35">
                Parsed Log Count
              </p>
              <hr className="my-3 border-white/10" />
              <p className="text-6xl font-mono font-bold tabular-nums leading-none">{logs.length}</p>
              <p className="mt-4 text-xs leading-relaxed text-white/40">{message}</p>
            </div>

          </div>
        </header>

        {/* ── Upload + File output ── */}
        <section className="grid gap-5 lg:grid-cols-[1fr_.85fr]">

          <div className="rounded-xl border border-white/10 bg-[#161B22] p-4 sm:p-5">
            <div
              className={`flex min-h-60 cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed p-6 text-center transition-colors ${
                dragging ? 'border-[#58A6FF]/40 bg-[#58A6FF]/5' : 'border-white/10 bg-[#0D1117]'
              }`}
              onClick={() => inputRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}
            >
              <div className="mb-4 rounded bg-white/5 p-3 text-xl text-white/50">⇪</div>
              <h2 className="text-sm font-semibold">Drag files here to upload</h2>
              <p className="mt-1 text-xs text-white/35">Accepts .log and .csv</p>
              <button
                className="mt-4 rounded-md bg-[#58A6FF] px-4 py-2 text-sm font-semibold text-[#0D1117] transition hover:opacity-90 active:opacity-75"
                type="button"
              >
                Select files
              </button>
              <input ref={inputRef} className="hidden" type="file" multiple accept=".log,.csv" onChange={(e) => addFiles(e.target.files)} />
            </div>
          </div>

          <aside className="rounded-xl border border-white/10 bg-[#161B22] p-4 sm:p-5">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-white">File output</h2>
                <p className="text-xs text-white/35">Parsed file results</p>
              </div>
              <span className="rounded border border-white/10 bg-[#0D1117] px-2.5 py-1 text-xs font-semibold text-white/50">
                {files.length} files
              </span>
            </div>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search files…"
              className="mb-3 w-full rounded-md border border-white/10 bg-[#0D1117] px-3 py-2 text-sm text-white placeholder-white/20 outline-none transition focus:border-[#58A6FF]/40"
            />
            <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
              {filteredFiles.length
                ? filteredFiles.map((file) => (
                    <div key={`${file.name}-${file.size}-${file.rows}`} className="rounded-md border border-white/8 bg-[#0D1117] px-3 py-2.5">
                      <p className="truncate text-sm font-semibold text-white">{file.name}</p>
                      <p className="mt-0.5 text-xs text-white/35">
                        {file.type.toUpperCase()} · {(file.size / 1024).toFixed(1)} KB · {file.rows} rows
                      </p>
                    </div>
                  ))
                : <p className="rounded-md bg-[#0D1117] p-4 text-xs text-white/30">No uploaded files yet. Sample logs shown below.</p>}
            </div>
          </aside>

        </section>

        {/* ── Stat cards ── */}
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            ['Failed events',     stats.failures,                                                  '#B91C1C'],
            ['Successful logins', stats.successes,                                                 '#15803D'],
            ['Unique IPs',        stats.uniqueIps,                                                '#3B82F6'],
            ['Top source IP',     stats.topIp ? `${stats.topIp[0]} (×${stats.topIp[1]})` : '—', '#475569'],
          ].map(([label, value, accent]) => (
            <article
              key={label}
              className="rounded-lg border border-white/10 bg-[#161B22] p-4"
              style={{ borderTop: `2px solid ${accent}` }}
            >
              <p className="text-[9px] font-medium uppercase tracking-[.10em] text-white/35">{label}</p>
              <p className="mt-2 break-words text-3xl font-mono font-bold tabular-nums">{value}</p>
            </article>
          ))}
        </section>

        {/* ── Threat analysis + Parsed logs ── */}
        <section className="grid gap-5 xl:grid-cols-[.7fr_1.3fr]">

          {/* Threat analysis */}
          <div className="rounded-xl border border-white/10 bg-[#161B22] p-5">
            <h2 className="text-[9px] font-medium uppercase tracking-[.20em] text-white/40">
              Threat Analysis
            </h2>

            {/* Donut + inline legend */}
            <div className="mt-5 flex items-center gap-6">
              <div className="shrink-0">
                <div
                  className="grid size-40 place-items-center rounded-full"
                  style={{
                    background: `conic-gradient(#B91C1C 0 ${failStop}%, #15803D 0 ${successStop}%, #374151 0 100%)`,
                  }}
                  aria-label="Event status distribution"
                >
                  <div className="grid size-24 place-items-center rounded-full bg-[#161B22] text-center">
                    <span className="text-2xl font-mono font-bold tabular-nums leading-none">{logs.length}</span>
                    <span className="mt-0.5 text-[9px] uppercase tracking-wider text-white/35">events</span>
                  </div>
                </div>
              </div>

              {/* Legend beside donut */}
              <div className="flex-1 space-y-3">
                {[
                  ['Failed',  stats.failures,  failPct,    '#B91C1C'],
                  ['Success', stats.successes, successPct, '#15803D'],
                  ['Other',   otherCount,      otherPct,   '#374151'],
                ].map(([label, count, pct, color]) => (
                  <div key={label} className="flex items-center gap-2">
                    <span className="h-2 w-2 shrink-0 rounded-sm" style={{ backgroundColor: color }} />
                    <span className="flex-1 text-xs text-white/50">{label}</span>
                    <span className="text-sm font-mono font-semibold tabular-nums">{count}</span>
                    <span className="w-8 text-right text-xs font-mono text-white/30">{pct}%</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Alert notices — driven by backend detection engine */}
            <div className="mt-5 space-y-2">
              {alerts.length > 0
                ? alerts.map((a, i) => <AlertCard key={i} alert={a} />)
                : (
                  <div className="rounded-md border-l-2 border-[#374151] bg-[#0D1117] px-3 py-2.5">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-white/40">
                      No Threats Detected
                    </p>
                    <p className="mt-1 text-xs leading-relaxed text-white/40">
                      Upload a log file to run the detection engine.
                    </p>
                  </div>
                )
              }
            </div>
          </div>

          {/* Parsed logs table */}
          <div className="rounded-xl border border-white/10 bg-[#161B22] p-4 sm:p-5">
            <div className="mb-3 flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
              <div>
                <h2 className="text-[9px] font-medium uppercase tracking-[.20em] text-white/40">
                  Parsed Logs
                </h2>
                <p className="mt-0.5 text-xs text-white/25">Timestamp · IP · user · event · status</p>
              </div>
              <span className="text-xs font-mono font-semibold text-[#58A6FF]">
                {filteredLogs.length} / {logs.length} records
              </span>
            </div>

            <div className="mb-3 grid gap-2 sm:grid-cols-[1fr_auto]">
              <input
                value={logQuery}
                onChange={(e) => setLogQuery(e.target.value)}
                placeholder="Filter logs…"
                className="rounded-md border border-white/10 bg-[#0D1117] px-3 py-2 text-sm text-white placeholder-white/20 outline-none transition focus:border-[#58A6FF]/40"
              />
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="rounded-md border border-white/10 bg-[#0D1117] px-3 py-2 text-sm font-semibold text-white outline-none transition focus:border-[#58A6FF]/40"
              >
                {['ALL', 'FAILED', 'SUCCESS', 'INFO', 'UNKNOWN'].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>

            <div className="max-h-[26rem] overflow-auto rounded-md border border-white/10">
              <table className="min-w-[680px] w-full text-left text-xs">
                <thead className="sticky top-0 border-b border-white/10 bg-[#0D1117]">
                  <tr>
                    {['Timestamp', 'IP Address', 'Username', 'Event', 'Status'].map((h) => (
                      <th key={h} className="px-3 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-white/35">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log, i) => (
                    <tr
                      key={`${log.timestamp}-${log.event}-${i}`}
                      className="border-t border-white/5 transition-colors hover:bg-white/[0.03] odd:bg-[#0D1117]/50"
                    >
                      <td className="px-3 py-2 font-mono text-white/40">{log.timestamp || '—'}</td>
                      <td className="px-3 py-2 font-mono text-white/55">{log.ip || '—'}</td>
                      <td className="px-3 py-2 font-mono text-white/65">{log.username || '—'}</td>
                      <td className="px-3 py-2 font-mono font-medium text-white/90">{log.event}</td>
                      <td className="px-3 py-2">
                        <StatusBadge status={log.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
