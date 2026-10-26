import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  Server,
  Activity,
  AlertTriangle,
  Play,
  Pause,
  Filter,
  Search,
  Zap,
  Info,
  CloudLightning,
  Lock,
  Layers
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  AreaChart,
  Area,
  CartesianGrid
} from 'recharts';
import { ThreatEvent, ThreatSummary, BlockedIp, AuditLog } from './types';

const API_BASE = 'http://localhost:5000/api';
const WS_URL = 'ws://localhost:5000/ws';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#FF0055',
  HIGH: '#FF7700',
  MEDIUM: '#FFB800',
  LOW: '#00F0FF'
};

export const App: React.FC = () => {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [isLivePaused, setIsLivePaused] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [searchIp, setSearchIp] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [isSimulating, setIsSimulating] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [showDocModal, setShowDocModal] = useState(false);
  const [activeTab, setActiveTab] = useState<'stream' | 'blocked' | 'audit'>('stream');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const demoIntervalRef = useRef<any>(null);

  // Fetch initial summary & threats
  const fetchSummary = async () => {
    try {
      const res = await fetch(`${API_BASE}/threats/summary`);
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (err) {
      console.warn('Backend summary offline or loading...');
    }
  };

  const fetchThreats = async () => {
    try {
      let url = `${API_BASE}/threats?limit=50`;
      if (severityFilter !== 'ALL') url += `&severity=${severityFilter}`;
      if (searchIp) url += `&ip=${encodeURIComponent(searchIp)}`;
      
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setThreats(data.data || []);
      }
    } catch (err) {
      console.warn('Backend threats API offline or loading...');
    }
  };

  const fetchBlockedIps = async () => {
    try {
      const res = await fetch(`${API_BASE}/blocked-ips`);
      if (res.ok) {
        const data = await res.json();
        setBlockedIps(data);
      }
    } catch (err) {}
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/audit-logs`);
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (err) {}
  };

  // Connect WebSocket
  useEffect(() => {
    const connectWs = () => {
      try {
        const ws = new WebSocket(WS_URL);
        socketRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'NEW_THREAT_EVENT') {
              const newThreat: ThreatEvent = msg.payload;
              if (!isLivePaused) {
                setThreats((prev) => [newThreat, ...prev.slice(0, 99)]);
                fetchSummary();
                fetchBlockedIps();
                fetchAuditLogs();
                triggerToast(`THREAT ALERT [${newThreat.severity}]: ${newThreat.attackType} from ${newThreat.sourceIp}`);
              }
            }
          } catch (e) {
            console.error('Error parsing WS message', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          setTimeout(connectWs, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (e) {
        setWsConnected(false);
      }
    };

    connectWs();
    fetchSummary();
    fetchThreats();
    fetchBlockedIps();
    fetchAuditLogs();

    const pollInterval = setInterval(() => {
      fetchSummary();
      fetchBlockedIps();
    }, 10000);

    return () => {
      if (socketRef.current) socketRef.current.close();
      clearInterval(pollInterval);
    };
  }, [isLivePaused]);

  useEffect(() => {
    fetchThreats();
  }, [severityFilter, searchIp]);

  // Demo auto-simulation loop
  useEffect(() => {
    if (demoMode) {
      const types = ['brute_force', 'port_scan', 'ddos_surge', 'sql_injection'];
      demoIntervalRef.current = setInterval(() => {
        const randomType = types[Math.floor(Math.random() * types.length)];
        triggerSimulation(randomType);
      }, 5000);
    } else {
      if (demoIntervalRef.current) clearInterval(demoIntervalRef.current);
    }
    return () => {
      if (demoIntervalRef.current) clearInterval(demoIntervalRef.current);
    };
  }, [demoMode]);

  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 4000);
  };

  const triggerSimulation = async (type: string) => {
    setIsSimulating(true);
    try {
      const res = await fetch(`${API_BASE}/threats/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      if (res.ok) {
        await res.json();
        fetchSummary();
        fetchBlockedIps();
        fetchAuditLogs();
      }
    } catch (err) {
      triggerToast('Simulation failed: Backend unreachable');
    } finally {
      setIsSimulating(false);
    }
  };

  // Chart data calculations
  const severityPieData = summary
    ? [
        { name: 'Critical', value: summary.severityBreakdown.CRITICAL || 0, color: SEVERITY_COLORS.CRITICAL },
        { name: 'High', value: summary.severityBreakdown.HIGH || 0, color: SEVERITY_COLORS.HIGH },
        { name: 'Medium', value: summary.severityBreakdown.MEDIUM || 0, color: SEVERITY_COLORS.MEDIUM },
        { name: 'Low', value: summary.severityBreakdown.LOW || 0, color: SEVERITY_COLORS.LOW }
      ].filter(d => d.value > 0)
    : [];

  const timelineData = threats.slice(0, 10).reverse().map((t) => ({
    time: new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    score: Math.round(t.anomalyScore * 100),
    rate: t.requestRatePerMin
  }));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans cyber-grid selection:bg-cyan-500 selection:text-black">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-4 right-4 z-50 bg-red-950/90 border border-red-500/80 text-red-200 px-4 py-3 rounded shadow-2xl flex items-center space-x-3 backdrop-blur animate-bounce">
          <AlertTriangle className="w-5 h-5 text-red-400 animate-pulse" />
          <span className="font-mono text-sm tracking-wide">{toastMessage}</span>
        </div>
      )}

      {/* Navigation Header */}
      <header className="border-b border-cyan-900/40 bg-slate-900/80 backdrop-blur sticky top-0 z-40 px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <ShieldAlert className="w-9 h-9 text-cyan-400" />
              <div className="absolute -inset-1 bg-cyan-500/20 blur rounded-full animate-pulse"></div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-display font-bold text-xl tracking-wider text-cyan-300">
                  CYBER-SENTINEL
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-400">
                  ML SOC v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Real-Time Cloud Cybersecurity Telemetry & Isolation Forest Engine
              </p>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-3">
            {/* WebSocket Pulse */}
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-800/80 border border-slate-700 text-xs font-mono">
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-red-500'}`} />
              <span className={wsConnected ? 'text-emerald-300' : 'text-red-400'}>
                {wsConnected ? 'LIVE FEED ACTIVE' : 'GATEWAY DISCONNECTED'}
              </span>
            </div>

            {/* Demo Mode Toggle */}
            <button
              onClick={() => setDemoMode(!demoMode)}
              className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-all flex items-center space-x-1.5 border ${
                demoMode
                  ? 'bg-purple-900/40 border-purple-400 text-purple-300 shadow-[0_0_15px_rgba(168,85,247,0.3)]'
                  : 'bg-slate-800/80 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Zap className={`w-3.5 h-3.5 ${demoMode ? 'text-purple-400 animate-spin' : ''}`} />
              <span>{demoMode ? 'DEMO INJECTION: ON' : 'AUTO DEMO: OFF'}</span>
            </button>

            {/* Architecture Modal Button */}
            <button
              onClick={() => setShowDocModal(true)}
              className="px-3 py-1.5 rounded text-xs font-mono font-semibold bg-slate-800 border border-slate-700 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 transition-colors flex items-center space-x-1.5"
            >
              <Info className="w-3.5 h-3.5" />
              <span>SOC SPECS</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 md:px-6 py-6 space-y-6">
        {/* Top SOC Metrics */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 relative overflow-hidden backdrop-blur">
            <div className="absolute top-0 left-0 w-1 h-full bg-cyan-500" />
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
              <span>Total Threats Detected</span>
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="mt-2 text-3xl font-display font-bold text-white tracking-wider">
              {summary?.totalThreats ?? threats.length}
            </div>
            <div className="mt-1 text-[11px] text-cyan-400/80 font-mono">
              Aggregated across all sensor endpoints
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 relative overflow-hidden backdrop-blur">
            <div className="absolute top-0 left-0 w-1 h-full bg-rose-500" />
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
              <span>High & Critical Incidents</span>
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            </div>
            <div className="mt-2 text-3xl font-display font-bold text-rose-400 tracking-wider">
              {summary?.highCriticalCount ?? 0}
            </div>
            <div className="mt-1 text-[11px] text-rose-400/80 font-mono">
              Auto-isolated or escalated to Tier 2
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 relative overflow-hidden backdrop-blur">
            <div className="absolute top-0 left-0 w-1 h-full bg-amber-500" />
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
              <span>Active Quarantined IPs</span>
              <Lock className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-2 text-3xl font-display font-bold text-amber-400 tracking-wider">
              {summary?.blockedIpCount ?? blockedIps.length}
            </div>
            <div className="mt-1 text-[11px] text-amber-400/80 font-mono">
              Firewall ACL drops currently enforced
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 relative overflow-hidden backdrop-blur">
            <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500" />
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono uppercase">
              <span>Isolation Forest Latency</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="mt-2 text-3xl font-display font-bold text-emerald-400 tracking-wider">
              {summary?.avgDetectionLatencyMs ?? 14.2} <span className="text-base font-normal">ms</span>
            </div>
            <div className="mt-1 text-[11px] text-emerald-400/80 font-mono">
              FastAPI Python model inference latency
            </div>
          </div>
        </section>

        {/* Live Attack Simulator Toolbar */}
        <section className="bg-slate-900/80 border border-cyan-900/40 rounded-lg p-4 shadow-xl">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center space-x-2">
              <CloudLightning className="w-5 h-5 text-cyan-400" />
              <div>
                <h2 className="text-sm font-display font-bold tracking-wider text-cyan-300">
                  RED-TEAM ATTACK SIMULATOR & TELEMETRY INJECTOR
                </h2>
                <p className="text-xs text-slate-400 font-mono">
                  Inject synthetic adversary payloads to test real-time ML detection & auto-mitigation
                </p>
              </div>
            </div>

            <div className="flex items-center flex-wrap gap-2">
              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation('brute_force')}
                className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-rose-950/60 border border-rose-700/60 text-rose-300 hover:bg-rose-900/60 transition disabled:opacity-50"
              >
                Simulate Brute Force
              </button>
              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation('port_scan')}
                className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-amber-950/60 border border-amber-700/60 text-amber-300 hover:bg-amber-900/60 transition disabled:opacity-50"
              >
                Simulate Port Scan
              </button>
              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation('ddos_surge')}
                className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-cyan-950/60 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-900/60 transition disabled:opacity-50"
              >
                Simulate DDoS Surge
              </button>
              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation('sql_injection')}
                className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-purple-950/60 border border-purple-700/60 text-purple-300 hover:bg-purple-900/60 transition disabled:opacity-50"
              >
                Simulate SQLi Attack
              </button>
            </div>
          </div>
        </section>

        {/* Analytics & SOC Visualizations */}
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Severity Breakdown Donut */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
            <h3 className="text-xs font-display font-semibold tracking-wider text-slate-300 uppercase mb-4 flex items-center justify-between">
              <span>Severity Distribution</span>
              <Layers className="w-4 h-4 text-slate-400" />
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: '#0B132B', borderColor: '#1C2541', borderRadius: '4px' }}
                    itemStyle={{ color: '#00F0FF', fontFamily: 'monospace' }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    iconSize={8}
                    wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '10px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Anomaly Trend Area Chart */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
            <h3 className="text-xs font-display font-semibold tracking-wider text-slate-300 uppercase mb-4 flex items-center justify-between">
              <span>Real-Time Anomaly Score Trend</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="scoreColor" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#00F0FF" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c2541" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: '#0B132B', borderColor: '#1C2541' }}
                    labelStyle={{ color: '#00F0FF', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="score" stroke="#00F0FF" fillOpacity={1} fill="url(#scoreColor)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top Targeted Endpoints */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
            <h3 className="text-xs font-display font-semibold tracking-wider text-slate-300 uppercase mb-4 flex items-center justify-between">
              <span>Top Targeted Endpoints</span>
              <Server className="w-4 h-4 text-purple-400" />
            </h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary?.topTargetedEndpoints || []} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#1c2541" />
                  <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis
                    dataKey="endpoint"
                    type="category"
                    width={110}
                    stroke="#64748b"
                    tick={{ fontSize: 9, fill: '#94a3b8' }}
                  />
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: '#0B132B', borderColor: '#1C2541' }}
                    itemStyle={{ color: '#00F0FF', fontFamily: 'monospace' }}
                  />
                  <Bar dataKey="count" fill="#7928CA" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        {/* Filter & Stream Controls */}
        <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          {/* Tabs */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveTab('stream')}
              className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition ${
                activeTab === 'stream'
                  ? 'bg-cyan-950 border border-cyan-500/60 text-cyan-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              THREAT STREAM ({threats.length})
            </button>
            <button
              onClick={() => setActiveTab('blocked')}
              className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition ${
                activeTab === 'blocked'
                  ? 'bg-amber-950 border border-amber-500/60 text-amber-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              QUARANTINED IPS ({blockedIps.length})
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition ${
                activeTab === 'audit'
                  ? 'bg-purple-950 border border-purple-500/60 text-purple-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              SOC AUDIT LOGS ({auditLogs.length})
            </button>
          </div>

          {/* Filtering */}
          <div className="flex items-center flex-wrap gap-3 w-full md:w-auto">
            <div className="relative flex-1 md:w-56">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search IP or endpoint..."
                value={searchIp}
                onChange={(e) => setSearchIp(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center space-x-1 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs font-mono">
              <Filter className="w-3 h-3 text-slate-400 mr-1" />
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded text-[10px] font-bold transition ${
                    severityFilter === sev
                      ? 'bg-cyan-500 text-black'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Live Feed Toggle */}
            <button
              onClick={() => setIsLivePaused(!isLivePaused)}
              className={`p-1.5 rounded border ${
                isLivePaused
                  ? 'bg-amber-950 border-amber-600 text-amber-300'
                  : 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white'
              }`}
              title={isLivePaused ? 'Resume live WebSocket stream' : 'Pause live stream'}
            >
              {isLivePaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            </button>
          </div>
        </section>

        {/* Tab 1: Live Threat Stream */}
        {activeTab === 'stream' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg overflow-hidden shadow-2xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
                  <tr>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Attack Type</th>
                    <th className="py-3 px-4">Source IP</th>
                    <th className="py-3 px-4">Target Endpoint</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">State</th>
                    <th className="py-3 px-4">ML Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-slate-500">
                        No active security events found matching current filter
                      </td>
                    </tr>
                  ) : (
                    threats.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {new Date(t.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold inline-block"
                            style={{
                              backgroundColor: `${SEVERITY_COLORS[t.severity]}15`,
                              border: `1px solid ${SEVERITY_COLORS[t.severity]}40`,
                              color: SEVERITY_COLORS[t.severity]
                            }}
                          >
                            {t.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-200 whitespace-nowrap">
                          {t.attackType}
                        </td>
                        <td className="py-3 px-4 text-cyan-400 font-bold whitespace-nowrap">
                          {t.sourceIp}
                          {t.geoCountry && (
                            <span className="ml-1.5 text-[10px] text-slate-500 font-normal">
                              ({t.geoCountry})
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-300 max-w-[150px] truncate">
                          {t.targetEndpoint}
                        </td>
                        <td className="py-3 px-4 font-bold text-amber-300">
                          {(t.anomalyScore * 100).toFixed(0)}%
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              t.status === 'BLOCKED'
                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            }`}
                          >
                            {t.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px] max-w-[280px] truncate" title={t.explanation}>
                          {t.explanation}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 2: Quarantined IPs */}
        {activeTab === 'blocked' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-display font-semibold text-slate-200">
                ACTIVE FIREWALL QUARANTINE TABLE
              </h3>
              <span className="text-xs font-mono text-slate-400">
                {blockedIps.length} IPs currently blocked
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">IP Address</th>
                    <th className="py-2.5 px-3">Quarantine Reason</th>
                    <th className="py-2.5 px-3">Blocked Time</th>
                    <th className="py-2.5 px-3">Triggered By</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {blockedIps.map((b) => (
                    <tr key={b.id} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 text-rose-400 font-bold">{b.ipAddress}</td>
                      <td className="py-2.5 px-3 text-slate-300">{b.reason}</td>
                      <td className="py-2.5 px-3 text-slate-400">{new Date(b.blockedAt).toLocaleTimeString()}</td>
                      <td className="py-2.5 px-3 text-cyan-400">{b.blockedBy}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Audit Logs */}
        {activeTab === 'audit' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-display font-semibold text-slate-200 mb-4">
              SECURITY OPERATIONS AUDIT TRAIL
            </h3>
            <div className="space-y-2 font-mono text-xs">
              {auditLogs.map((log) => (
                <div key={log.id} className="p-3 bg-slate-950/80 border border-slate-800 rounded flex items-center justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-cyan-300">{log.action}</span>
                      <span className="text-slate-500">by</span>
                      <span className="text-amber-400 font-semibold">{log.actor}</span>
                    </div>
                    <div className="text-slate-300 mt-1">{log.details}</div>
                  </div>
                  <div className="text-slate-500 text-[11px] whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* SOC Architecture Modal */}
      {showDocModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-500/60 rounded-xl max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="font-display font-bold text-lg text-cyan-300">
                SYSTEM SPECIFICATIONS & ARCHITECTURE
              </h2>
              <button
                onClick={() => setShowDocModal(false)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                [ESC / CLOSE]
              </button>
            </div>
            
            <div className="space-y-4 text-xs font-mono text-slate-300 leading-relaxed">
              <p>
                <strong>Cyber-Sentinel</strong> is an enterprise cloud-native cybersecurity telemetry
                platform designed to detect advanced persistent threats (APT), distributed volumetric attacks,
                and credential compromise in real time.
              </p>

              <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-2">
                <div className="text-cyan-400 font-bold uppercase text-[11px]">Core Architecture Components</div>
                <ul className="list-disc pl-4 space-y-1 text-slate-300">
                  <li><strong>FastAPI ML Microservice (Port 8001):</strong> Isolation Forest unsupervised anomaly model trained on synthetic network attack profiles.</li>
                  <li><strong>Express/TypeScript Gateway (Port 5000):</strong> Ingests network events, performs token authentication, communicates with ML service, and broadcasts over WebSockets.</li>
                  <li><strong>Real-Time WebSocket Feed (/ws):</strong> Sub-15ms broadcast to connected SOC analyst browser dashboards.</li>
                  <li><strong>Automatic Quarantine Engine:</strong> Evaluates threat scores (&gt; 0.85 or &gt; 20 failed logins) and injects dynamic firewall drop rules.</li>
                </ul>
              </div>

              <div className="bg-slate-950 p-4 rounded border border-slate-800">
                <div className="text-amber-400 font-bold uppercase text-[11px] mb-2">Pre-Configured Credentials</div>
                <div className="grid grid-cols-2 gap-2 text-slate-400">
                  <div>Admin User: <span className="text-slate-200">admin / admin123</span></div>
                  <div>Analyst User: <span className="text-slate-200">analyst / analyst123</span></div>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowDocModal(false)}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-black font-bold font-mono text-xs rounded transition"
              >
                ACKNOWLEDGE & RETURN
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
