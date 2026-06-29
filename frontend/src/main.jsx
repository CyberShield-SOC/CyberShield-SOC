import React, { useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const ACCEPTED_EXTENSIONS = ['log', 'csv'];

const SAMPLE_LOGS = [
  { timestamp: 'Jun 14 02:11:43', ip: '203.0.113.4', username: 'root', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:11:45', ip: '203.0.113.4', username: 'root', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:11:47', ip: '203.0.113.4', username: 'root', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:11:49', ip: '203.0.113.4', username: 'root', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:11:51', ip: '203.0.113.4', username: 'root', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:12:01', ip: '203.0.113.4', username: 'admin', event: 'login_attempt', status: 'FAILED' },
  { timestamp: 'Jun 14 02:15:11', ip: '', username: 'jdoe', event: 'privilege_escalation', status: 'FAILED' },
  { timestamp: 'Jun 14 02:15:14', ip: '', username: 'jdoe', event: 'privilege_escalation', status: 'FAILED' },
  { timestamp: 'Jun 14 02:18:25', ip: '10.0.0.5', username: 'jdoe', event: 'login_attempt', status: 'SUCCESS' },
  { timestamp: 'Jun 14 02:19:01', ip: '10.0.0.5', username: '', event: 'connection_closed', status: 'INFO' },
];

const extensionOf = (name) => name.split('.').pop()?.toLowerCase() || '';

function App() {
  const [files, setFiles] = useState([]);
  const [logs, setLogs] = useState(SAMPLE_LOGS);
  const [query, setQuery] = useState('');
  const [logQuery, setLogQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [dragging, setDragging] = useState(false);
  const [message, setMessage] = useState('Sample SOC logs are loaded. Upload files to analyze your own data.');
  const inputRef = useRef(null);

  const addFiles = async (fileList) => {
    const incoming = Array.from(fileList || []);
    const supported = incoming.filter((file) => ACCEPTED_EXTENSIONS.includes(extensionOf(file.name)));
    const rejected = incoming.length - supported.length;
    const parsedBatches = [];
    const fileSummaries = [];

    for (const file of supported) {
      const formData = new FormData();
      formData.append('logfile', file);
      try {
        const res = await fetch('/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok || !data.success) {
          setMessage(data.detail?.error || data.error || `Failed to parse ${file.name}.`);
          continue;
        }
        const parsed = data.entries.map((entry) => ({
          timestamp: entry.parsed.timestamp || '',
          ip: entry.parsed.ip_address || '',
          username: entry.parsed.username || '',
          event: entry.parsed.event_type || 'Log Entry',
          status: (entry.parsed.status || 'UNKNOWN').toUpperCase(),
        }));
        parsedBatches.push(...parsed);
        fileSummaries.push({ name: file.name, size: file.size, type: extensionOf(file.name), rows: parsed.length });
      } catch (err) {
        setMessage(`Error uploading ${file.name}: ${err.message}`);
      }
    }

    if (fileSummaries.length) {
      setFiles((current) => [...fileSummaries, ...current]);
      setLogs(parsedBatches);
      setMessage(`${fileSummaries.length} file(s) parsed successfully${rejected ? `; ${rejected} unsupported file(s) skipped` : ''}.`);
    } else if (rejected) {
      setMessage('Unsupported file type. Please upload .log or .csv files.');
    }
  };

  const stats = useMemo(() => {
    const failures = logs.filter((log) => log.status === 'FAILED').length;
    const successes = logs.filter((log) => log.status === 'SUCCESS').length;
    const uniqueIps = new Set(logs.map((log) => log.ip).filter(Boolean)).size;
    const hotIps = logs.reduce((acc, log) => (log.ip ? { ...acc, [log.ip]: (acc[log.ip] || 0) + 1 } : acc), {});
    const topIp = Object.entries(hotIps).sort((a, b) => b[1] - a[1])[0];
    return { failures, successes, uniqueIps, topIp };
  }, [logs]);

  const filteredFiles = files.filter((file) => file.name.toLowerCase().includes(query.toLowerCase()));
  const filteredLogs = logs.filter((log) => {
    const haystack = Object.values(log).join(' ').toLowerCase();
    return haystack.includes(logQuery.toLowerCase()) && (statusFilter === 'ALL' || log.status === statusFilter);
  });

  return <main className="min-h-screen bg-[#F1F1F1] text-[#1C1C1C]">
    <section className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-5 sm:px-6 lg:px-8">
      <header className="overflow-hidden rounded-[2rem] bg-[#1C1C1C] text-white shadow-2xl">
        <div className="grid gap-6 p-6 sm:p-8 lg:grid-cols-[1.2fr_.8fr] lg:p-10">
          <div>
            <p className="mb-3 inline-flex rounded-full bg-[#FE5729] px-4 py-2 text-sm font-semibold">CyberShield SOC — Sprint 1</p>
            <h1 className="max-w-3xl text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">Upload logs. Parse events. Spot threats faster.</h1>
            <p className="mt-4 max-w-2xl text-base text-white/70 sm:text-lg">Upload .log or .csv files to detect failed logins, invalid users, privilege escalation, and connection events.</p>
          </div>
          <div className="rounded-[2rem] bg-gradient-to-br from-[#FE5729] via-[#FFBC99] to-[#D4B5FF] p-5 text-[#1C1C1C]">
            <p className="text-sm font-semibold uppercase tracking-[.2em]">Parsed log count</p>
            <p className="mt-4 text-7xl font-bold">{logs.length}</p>
            <p className="mt-2 text-sm font-semibold">{message}</p>
          </div>
        </div>
      </header>

      <section className="grid gap-6 lg:grid-cols-[1fr_.85fr]">
        <div className="rounded-[1.5rem] bg-[#1C1C1C] p-4 text-white shadow-xl sm:p-6">
          <div
            className={`flex min-h-72 cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed p-6 text-center transition ${dragging ? 'border-[#FE5729] bg-[#FE5729]/10' : 'border-white/25 bg-[#0d1117]'}`}
            onClick={() => inputRef.current?.click()}
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => { event.preventDefault(); setDragging(false); addFiles(event.dataTransfer.files); }}
          >
            <div className="mb-5 rounded-2xl bg-white/10 p-4 text-4xl">⇪</div>
            <h2 className="text-2xl font-bold">Drag files here to add them to CyberShield</h2>
            <p className="mt-2 text-sm text-white/60">or choose your files</p>
            <button className="mt-5 rounded-full bg-[#FE5729] px-6 py-3 font-bold text-white shadow-lg shadow-[#FE5729]/30" type="button">Select .log or .csv</button>
            <input ref={inputRef} className="hidden" type="file" multiple accept=".log,.csv" onChange={(event) => addFiles(event.target.files)} />
          </div>
        </div>

        <aside className="rounded-[1.5rem] bg-white p-4 shadow-xl sm:p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div><h2 className="text-xl font-bold">File output</h2><p className="text-sm text-black/50">Search uploaded parsing results</p></div>
            <span className="rounded-full bg-[#FFBC99] px-3 py-1 text-sm font-bold">{files.length} files</span>
          </div>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search files..." className="mb-4 w-full rounded-2xl border border-black/10 bg-[#F1F1F1] px-4 py-3 outline-none focus:border-[#FE5729]" />
          <div className="max-h-72 space-y-3 overflow-y-auto pr-2">
            {filteredFiles.length ? filteredFiles.map((file) => <div key={`${file.name}-${file.size}-${file.rows}`} className="rounded-2xl border border-black/5 bg-[#F1F1F1] p-4">
              <p className="truncate font-bold">{file.name}</p><p className="text-sm text-black/50">{file.type.toUpperCase()} • {(file.size / 1024).toFixed(1)} KB • {file.rows} parsed rows</p>
            </div>) : <p className="rounded-2xl bg-[#F1F1F1] p-5 text-sm text-black/50">No uploaded files yet. Sample logs are displayed below.</p>}
          </div>
        </aside>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[['Failed events', stats.failures, '#FE5729'], ['Successful logins', stats.successes, '#2EB679'], ['Unique IPs', stats.uniqueIps, '#D4B5FF'], ['Top source', stats.topIp ? `${stats.topIp[0]} (${stats.topIp[1]})` : 'N/A', '#FFBC99']].map(([label, value, color]) => <article key={label} className="rounded-[1.5rem] bg-white p-5 shadow-lg">
          <div className="mb-6 h-2 rounded-full" style={{ backgroundColor: color }} /><p className="text-sm font-semibold text-black/50">{label}</p><p className="mt-2 break-words text-3xl font-bold">{value}</p>
        </article>)}
      </section>

      <section className="grid gap-6 xl:grid-cols-[.7fr_1.3fr]">
        <div className="rounded-[1.5rem] bg-[#1C1C1C] p-5 text-white shadow-xl">
          <h2 className="text-xl font-bold">Threat analysis</h2>
          <div className="mx-auto mt-6 grid max-w-xs place-items-center">
            <div
              className="grid size-56 place-items-center rounded-full"
              style={{ background: `conic-gradient(#FE5729 0 ${Math.round((stats.failures / Math.max(logs.length, 1)) * 100)}%, #2EB679 0 ${Math.round(((stats.failures + stats.successes) / Math.max(logs.length, 1)) * 100)}%, #D4B5FF 0 100%)` }}
              aria-label="Threat status distribution chart"
            >
              <div className="grid size-32 place-items-center rounded-full bg-[#1C1C1C] text-center">
                <span className="text-3xl font-bold">{logs.length}</span>
                <span className="text-xs text-white/60">events</span>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap justify-center gap-3 text-xs text-white/70">
              <span><b className="text-[#FE5729]">●</b> Failed</span>
              <span><b className="text-[#2EB679]">●</b> Success</span>
              <span><b className="text-[#D4B5FF]">●</b> Other</span>
            </div>
          </div>
          <div className="mt-5 space-y-3">
            <p className="rounded-2xl bg-[#FE5729]/20 p-4"><strong>High risk:</strong> {stats.failures >= 5 ? 'Repeated failures indicate brute-force behavior.' : 'No brute-force threshold reached.'}</p>
            <p className="rounded-2xl bg-[#D4B5FF]/20 p-4"><strong>Investigation:</strong> Review invalid users and sudo failures for privilege escalation attempts.</p>
          </div>
        </div>

        <div className="rounded-[1.5rem] bg-white p-4 shadow-xl sm:p-6">
          <div className="mb-4 flex flex-col justify-between gap-2 sm:flex-row sm:items-end"><div><h2 className="text-xl font-bold">Parsed logs</h2><p className="text-sm text-black/50">Search by timestamp, IP, user, event, or status</p></div><span className="font-bold text-[#FE5729]">{filteredLogs.length}/{logs.length} records</span></div>
          <div className="mb-4 grid gap-3 sm:grid-cols-[1fr_auto]">
            <input value={logQuery} onChange={(event) => setLogQuery(event.target.value)} placeholder="Filter parsed logs..." className="rounded-2xl border border-black/10 bg-[#F1F1F1] px-4 py-3 outline-none focus:border-[#FE5729]" />
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="rounded-2xl border border-black/10 bg-[#F1F1F1] px-4 py-3 font-semibold outline-none focus:border-[#FE5729]">
              {['ALL', 'FAILED', 'SUCCESS', 'INFO', 'UNKNOWN'].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div className="max-h-[28rem] overflow-auto rounded-2xl border border-black/10">
            <table className="min-w-[760px] w-full text-left text-sm">
              <thead className="sticky top-0 bg-[#1C1C1C] text-white"><tr>{['Timestamp', 'IP', 'Username', 'Event', 'Status'].map((head) => <th key={head} className="px-4 py-3 font-semibold">{head}</th>)}</tr></thead>
              <tbody>{filteredLogs.map((log, index) => <tr key={`${log.timestamp}-${log.event}-${index}`} className="border-t border-black/5 odd:bg-[#F1F1F1]"><td className="px-4 py-3">{log.timestamp || '—'}</td><td className="px-4 py-3">{log.ip || '—'}</td><td className="px-4 py-3">{log.username || '—'}</td><td className="px-4 py-3 font-semibold">{log.event}</td><td className="px-4 py-3"><span className={`rounded-full px-3 py-1 text-xs font-bold ${log.status === 'FAILED' ? 'bg-[#FE5729] text-white' : log.status === 'SUCCESS' ? 'bg-[#2EB679] text-white' : log.status === 'INFO' ? 'bg-[#FFBC99]' : 'bg-[#D4B5FF]'}`}>{log.status}</span></td></tr>)}</tbody>
            </table>
          </div>
        </div>
      </section>
    </section>
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
