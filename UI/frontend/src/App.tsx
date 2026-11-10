import { useEffect, useState, useMemo } from "react";
import { EventsOn } from "../wailsjs/runtime/runtime";
import { SendAction, GetDaemonStatus } from "../wailsjs/go/main/App";
import {
  ShieldAlert,
  Activity,
  Terminal,
  Cpu,
  Skull,
  Snowflake,
  Search,
  Trash2,
  CheckCircle2,
  XCircle,
} from "lucide-react";

interface AlertItem {
  id: string;
  rule: string;
  severity: number;
  mitre: string;
  tgid: number;
  ppid: number;
  comm: string;
  exe: string;
  detail: string;
  ts: string;
}

export default function App() {
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selected, setSelected] = useState<AlertItem | null>(null);
  const [daemonOnline, setDaemonOnline] = useState<boolean>(false);
  const [search, setSearch] = useState("");
  const [minSev, setMinSev] = useState<number>(0);

  useEffect(() => {
    GetDaemonStatus().then(setDaemonOnline).catch(() => {});

    const offStatus = EventsOn("daemon:status", (status: boolean) => {
      setDaemonOnline(status);
    });

    const offBatch = EventsOn("alerts:batch", (batch: Omit<AlertItem, "id">[]) => {
      const enriched = batch.map((b) => ({
        ...b,
        id: `${b.ts}-${b.tgid}-${b.rule}-${Math.random().toString(36).slice(2, 7)}`,
      }));
      setAlerts((prev) => [...enriched.reverse(), ...prev].slice(0, 2000));
    });

    return () => {
      offStatus();
      offBatch();
    };
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return alerts.filter((a) => {
      if (a.severity < minSev) return false;
      if (!q) return true;
      return (
        a.rule.toLowerCase().includes(q) ||
        a.comm.toLowerCase().includes(q) ||
        a.mitre.toLowerCase().includes(q) ||
        a.detail.toLowerCase().includes(q) ||
        String(a.tgid).includes(q)
      );
    });
  }, [alerts, search, minSev]);

  const stats = useMemo(() => {
    let critical = 0;
    let high = 0;
    const mitreSet = new Set<string>();
    for (const a of alerts) {
      if (a.severity >= 5) critical++;
      else if (a.severity === 4) high++;
      if (a.mitre) mitreSet.add(a.mitre);
    }
    return { total: alerts.length, critical, high, mitreCount: mitreSet.size };
  }, [alerts]);

  const sevBadge = (sev: number) => {
    if (sev >= 5)
      return "bg-rose-500/15 text-rose-400 border border-rose-500/40";
    if (sev === 4)
      return "bg-amber-500/15 text-amber-400 border border-amber-500/40";
    return "bg-sky-500/15 text-sky-400 border border-sky-500/40";
  };

  return (
    <div className="h-screen w-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans select-none overflow-hidden">
      {/* Top Navbar */}
      <header className="h-14 border-b border-zinc-800/80 bg-zinc-900/50 px-6 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-rose-500" />
          </div>
          <div>
            <span className="font-bold tracking-wider text-sm text-white">
              OBLIVION
            </span>
            <span className="ml-2 text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 font-mono">
              eBPF LSM EDR
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800">
            {daemonOnline ? (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-emerald-400">DAEMON CONNECTED (UNIX SOCK)</span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-rose-500" />
                <span className="text-rose-400">WAITING FOR DAEMON (/tmp/oblivion.sock)</span>
              </>
            )}
          </div>
        </div>
      </header>

      {/* KPI Cards */}
      <section className="grid grid-cols-4 gap-4 p-5 shrink-0">
        <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-zinc-400 uppercase tracking-wider">Total Alerts</p>
            <p className="text-2xl font-bold font-mono mt-1">{stats.total}</p>
          </div>
          <Activity className="w-8 h-8 text-zinc-700" />
        </div>

        <div className="bg-zinc-900/60 border border-rose-950/60 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-rose-400/80 uppercase tracking-wider">Critical (Sev 5)</p>
            <p className="text-2xl font-bold font-mono text-rose-400 mt-1">{stats.critical}</p>
          </div>
          <ShieldAlert className="w-8 h-8 text-rose-500/30" />
        </div>

        <div className="bg-zinc-900/60 border border-amber-950/60 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-amber-400/80 uppercase tracking-wider">High (Sev 4)</p>
            <p className="text-2xl font-bold font-mono text-amber-400 mt-1">{stats.high}</p>
          </div>
          <Cpu className="w-8 h-8 text-amber-500/30" />
        </div>

        <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-4 flex items-center justify-between">
          <div>
            <p className="text-xs text-zinc-400 uppercase tracking-wider">MITRE Techniques Triggered</p>
            <p className="text-2xl font-bold font-mono text-indigo-400 mt-1">{stats.mitreCount}</p>
          </div>
          <Terminal className="w-8 h-8 text-indigo-500/30" />
        </div>
      </section>

      {/* Main Split View: Alert Table + Process Inspector */}
      <div className="flex-1 flex gap-4 px-5 pb-5 min-h-0">
        {/* Left: Live Alert Stream */}
        <div className="flex-1 bg-zinc-900/40 border border-zinc-800/80 rounded-xl flex flex-col min-w-0">
          {/* Toolbar */}
          <div className="p-3 border-b border-zinc-800/80 flex items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter by rule, comm, PID, MITRE (e.g. T1486, nginx)..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600"
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setMinSev(minSev === 5 ? 0 : 5)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition cursor-pointer ${
                  minSev === 5
                    ? "bg-rose-500/20 border-rose-500 text-rose-300"
                    : "bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200"
                }`}
              >
                Critical Only
              </button>
              <button
                onClick={() => {
                  setAlerts([]);
                  setSelected(null);
                }}
                className="p-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-rose-400 transition cursor-pointer"
                title="Clear Alerts"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Table Header */}
          <div className="grid grid-cols-12 px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500 border-b border-zinc-800/60 bg-zinc-900/30">
            <div className="col-span-2">Time</div>
            <div className="col-span-1">Sev</div>
            <div className="col-span-2">MITRE</div>
            <div className="col-span-2">Process (PID)</div>
            <div className="col-span-5">Rule / Telemetry Detail</div>
          </div>

          {/* Scrollable Alert Rows */}
          <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/40 font-mono text-xs">
            {filtered.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-zinc-600">
                <CheckCircle2 className="w-10 h-10 mb-2 stroke-1" />
                <p>No security alerts matching current filter</p>
              </div>
            ) : (
              filtered.map((a) => {
                const isSel = selected?.id === a.id;
                return (
                  <div
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className={`grid grid-cols-12 px-4 py-2.5 items-center cursor-pointer transition ${
                      isSel
                        ? "bg-zinc-800/90 border-l-2 border-rose-500"
                        : "hover:bg-zinc-900/80"
                    }`}
                  >
                    <div className="col-span-2 text-zinc-400">
                      {new Date(a.ts).toLocaleTimeString()}
                    </div>
                    <div className="col-span-1">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${sevBadge(a.severity)}`}>
                        S{a.severity}
                      </span>
                    </div>
                    <div className="col-span-2 text-indigo-400 font-semibold">
                      {a.mitre || "N/A"}
                    </div>
                    <div className="col-span-2 text-zinc-200 truncate pr-2">
                      {a.comm} <span className="text-zinc-500">({a.tgid})</span>
                    </div>
                    <div className="col-span-5 truncate">
                      <span className="text-zinc-100 font-semibold mr-2">[{a.rule}]</span>
                      <span className="text-zinc-400">{a.detail}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Incident & Process Response Drawer */}
        <div className="w-96 bg-zinc-900/60 border border-zinc-800/80 rounded-xl p-5 flex flex-col shrink-0">
          {selected ? (
            <>
              <div className="flex items-start justify-between border-b border-zinc-800 pb-4">
                <div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${sevBadge(selected.severity)}`}>
                    SEVERITY {selected.severity}
                  </span>
                  <h2 className="text-base font-bold text-white mt-2 font-mono">
                    {selected.rule}
                  </h2>
                  <p className="text-xs text-indigo-400 font-mono mt-0.5">
                    MITRE ATT&CK: {selected.mitre || "Unmapped"}
                  </p>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="text-zinc-500 hover:text-zinc-300 cursor-pointer"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              </div>

              {/* Process Genealogy Visual */}
              <div className="my-4 p-3 rounded-lg bg-zinc-950 border border-zinc-800/80 font-mono text-xs space-y-2">
                <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-sans font-semibold">
                  Process Lineage
                </p>
                <div className="flex items-center gap-2 text-zinc-400">
                  <span className="px-2 py-1 rounded bg-zinc-900 border border-zinc-800">
                    Parent PID: {selected.ppid}
                  </span>
                </div>
                <div className="pl-4 border-l-2 border-rose-500/50 ml-3 py-1">
                  <div className="px-2.5 py-1.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300">
                    <div className="font-bold">{selected.comm} (PID: {selected.tgid})</div>
                    <div className="text-[11px] text-zinc-400 break-all mt-0.5">
                      {selected.exe || "N/A"}
                    </div>
                  </div>
                </div>
              </div>

              {/* Telemetry Details */}
              <div className="flex-1 space-y-3 text-xs font-mono overflow-y-auto">
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80">
                  <p className="text-[10px] uppercase text-zinc-500 mb-1 font-sans font-semibold">
                    Detection Evidence
                  </p>
                  <p className="text-zinc-200 leading-relaxed break-words">
                    {selected.detail}
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80 space-y-1">
                  <div className="flex justify-between">
                    <span className="text-zinc-500">Timestamp:</span>
                    <span className="text-zinc-300">{new Date(selected.ts).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">TGID / PID:</span>
                    <span className="text-zinc-300">{selected.tgid}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-500">PPID:</span>
                    <span className="text-zinc-300">{selected.ppid}</span>
                  </div>
                </div>
              </div>

              {/* Active Response Actions */}
              <div className="pt-4 border-t border-zinc-800 mt-4 space-y-2">
                <p className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">
                  Active EDR Response
                </p>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => SendAction("kill", selected.tgid)}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition cursor-pointer"
                  >
                    <Skull className="w-4 h-4" />
                    Kill (SIGKILL)
                  </button>
                  <button
                    onClick={() => SendAction("stop", selected.tgid)}
                    className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 font-semibold text-xs transition cursor-pointer"
                  >
                    <Snowflake className="w-4 h-4" />
                    Freeze (SIGSTOP)
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center text-zinc-600 px-4">
              <ShieldAlert className="w-12 h-12 mb-3 stroke-1" />
              <p className="text-sm text-zinc-400 font-medium">No Incident Selected</p>
              <p className="text-xs mt-1">
                Click any alert row on the left to inspect the process lineage and trigger active response actions.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
