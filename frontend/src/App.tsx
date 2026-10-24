import { AnimatePresence,motion } from 'framer-motion';
import {
ArrowUpRight,
Check,
CheckCircle2,
ChevronDown,
ChevronRight,
Clock3,
Download,
FileCheck2,
FileText,
KeyRound,
LayoutDashboard,
Menu,
MessageSquareText,
Play,
Radar,
RefreshCw,
Settings2,
ShieldAlert,
ShieldCheck,
} from 'lucide-react';
import { useEffect,useMemo,useState,type ReactNode } from 'react';
import { fetchAIHealth,fetchDashboardStats,fetchScanHistory,generateReport,type AskContext,type FindingExplanation } from './api';
import { HistoryPage,ReportsPage,SecretsPage,SettingsPage } from './components/ActivityPages';
import { AskAntiFinePage } from './components/AskAntiFine';
import { ScanWorkspace } from './components/ScanWorkspace';
import {PageHeader,SeverityBadge} from './components/WorkstationUI';

import { RemediationModal } from './components/RemediationModal';
import { useFindings } from './hooks/useFindings';
import {FindingsPanel} from './components/FindingsPanel';
import {FindingDrawer} from './components/FindingDrawer';
import {CoveragePanel} from './components/CoveragePanel';
import type { Page } from './types';
import { type Finding,type Severity } from './types';
const navGroups = [
  {
    label: 'Workspace',
    items: [
      { id: 'overview' as Page, label: 'Overview', icon: LayoutDashboard },
      { id: 'scan' as Page, label: 'Scan', icon: Radar },
      { id: 'findings' as Page, label: 'Findings', icon: ShieldAlert },
    ],
  },
  {
    label: 'Posture',
    items: [
      { id: 'compliance' as Page, label: 'Compliance', icon: FileCheck2 },
      { id: 'secrets' as Page, label: 'Secrets', icon: KeyRound },
    ],
  },
  {
    label: 'Activity',
    items: [
      { id: 'history' as Page, label: 'Scan history', icon: Clock3 },
      { id: 'reports' as Page, label: 'Reports', icon: FileText },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'ai' as Page, label: 'Ask AntiFine', icon: MessageSquareText },
    ],
  },
];

function AppShell({
  page,
  setPage,
  children,
}: {
  page: Page;
  setPage: (page: Page) => void;
  children: ReactNode;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [health, setHealth] = useState<Awaited<ReturnType<typeof fetchAIHealth>> | null>(null);
  const [stats, setStats] = useState<Awaited<ReturnType<typeof fetchDashboardStats>> | null>(null);

  useEffect(() => {
    void fetchAIHealth().then(setHealth).catch(() => setHealth({
      enabled: false,
      available: false,
      provider: 'ollama',
      model: 'qwen2.5:7b',
      error: 'Backend unavailable',
    }));
    void fetchDashboardStats().then(setStats).catch(() => {});
  }, []);
  const currentLabel = navGroups.flatMap((group) => group.items).find((item) => item.id === page)?.label;

  const navigate = (nextPage: Page) => {
    setPage(nextPage);
    setMobileOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={17} /></div>
          <span>AntiFine</span>
        </div>
        <div className="workspace-switcher">
          <div className="workspace-icon">AF</div>
          <div><strong>AntiFine</strong><small>LOCAL WORKSPACE</small></div>
          <ChevronDown size={14} className="muted" />
        </div>
        <nav className="side-nav" aria-label="Primary navigation">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              {group.items.map((item) => {
                const Icon = item.icon;
                const dynamicCount = item.id === 'findings' ? stats?.total_findings : item.id === 'secrets' ? stats?.total_secrets : undefined;
                return (
                  <button key={item.id} onClick={() => navigate(item.id)} className={`nav-item ${page === item.id ? 'nav-item-active' : ''}`} aria-current={page === item.id ? 'page' : undefined}>
                    <Icon size={17} strokeWidth={page === item.id ? 2.3 : 1.8} />
                    <span>{item.label}</span>
                    {dynamicCount ? <span className="nav-count">{dynamicCount}</span> : null}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-status-footer">
            <span className="local-status-label">Local Engine</span>
            <span className="local-status-value"><i className={health ? 'status-live' : 'status-idle'} />FastAPI · 127.0.0.1:8000</span>
            <span className="local-status-label">Local AI</span>
            <span className="local-status-value muted"><i className={health?.available ? 'status-live' : 'status-idle'} />{health?.available ? `Ollama · ${health.model}` : health?.enabled === false ? 'Ollama · Offline' : 'Ollama · Checking'}</span>
          </div>
          <button className={`nav-item ${page === 'settings' ? 'nav-item-active' : ''}`} onClick={() => navigate('settings')} aria-current={page === 'settings' ? 'page' : undefined}><Settings2 size={17} /><span>Settings</span></button>
        </div>
      </aside>
      {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-title"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button><strong>{currentLabel}</strong></div>
          <div className="topbar-actions"><div className="topbar-local">LOCAL WORKSPACE</div></div>
        </header>
        <div className="page-content">{children}</div>
      </main>
    </div>
  );
}

function Overview({ findings, onNavigate, onSelect }: { findings: Finding[]; onNavigate: (page: Page) => void; onSelect: (finding: Finding) => void }) {
  const [history, setHistory] = useState<any[]>([]);
  useEffect(() => {
    fetchScanHistory().then((res) => setHistory(res.scans)).catch(() => {});
  }, []);
  const latestScan = history.length > 0 ? history[0] : null;

  const openFindings = useMemo(() => findings.filter((finding) => finding.status === 'Open'), [findings]);
  const counts = useMemo(() => openFindings.reduce<Record<Severity, number>>((acc, finding) => { acc[finding.severity] += 1; return acc; }, { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, Unknown: 0 }), [openFindings]);
  return <div className="content-stack workstation-overview">
    <PageHeader eyebrow="Local workspace" title="Overview" description="Current scan state and findings requiring engineering review." action={<button className="button button-primary" onClick={() => onNavigate('scan')}><Play size={14} fill="currentColor" />Run scan</button>} />
    <section className="ops-strip" aria-label="Operational state">
      <div><span className="ops-label">LAST SCAN</span><strong>IaC Config Audit</strong><code>{latestScan?.id ?? 'No scans'}</code><span>{latestScan?.time ? new Date(latestScan.time.replace(' ', 'T') + 'Z').toLocaleString() : '—'}</span></div>
      <div><span className="ops-label">ENGINE</span><strong className={latestScan ? 'state-ok' : ''}>{latestScan ? String(latestScan.status).toUpperCase() : 'IDLE'}</strong><span>{latestScan ? `${latestScan.findings} findings` : '—'}</span></div>
      <div><span className="ops-label">SERVICES</span><span className="service-state">FastAPI · 127.0.0.1:8000</span><span className="service-state">See local status in shell</span></div>
    </section>
    <section className="overview-findings panel">
      <div className="console-heading"><div><span className="section-kicker">WORK QUEUE</span><h2>Open findings</h2></div><div className="console-summary"><span className="severity-count critical">{counts.Critical} critical</span><span className="severity-count high">{counts.High} high</span><button className="text-button" onClick={() => onNavigate('findings')}>Open findings <ArrowUpRight size={13} /></button></div></div>
      <div className="overview-finding-list">{openFindings.slice(0, 5).map((finding) => <button className="overview-finding-row" key={finding.id} onClick={() => onSelect(finding)}><SeverityBadge severity={finding.severity} /><code className="rule-id">{finding.id}</code><strong>{finding.rule_name}</strong><span className="file-ref">{finding.file}:{finding.line}</span><span className="framework-ref">{finding.framework}</span><ChevronRight size={14} /></button>)}</div>
    </section>
    <div className="overview-lower-grid">
      <section className="console-panel"><div className="console-heading"><div><span className="section-kicker">SCAN STATE</span><h2>Latest activity</h2></div><button className="text-button" onClick={() => onNavigate('history')}>History <ArrowUpRight size={13} /></button></div><div className="activity-list compact-activity">
      {history.slice(0, 2).map((scan) => (
        <div key={scan.id} className="activity-row">
          <div className="activity-status success"><Check size={13} /></div>
          <div><strong>{scan.type} completed</strong><span>{scan.findings} findings · {scan.target}</span></div>
          <time>{new Date(scan.time).toLocaleString()}</time>
        </div>
      ))}
      {history.length === 0 && <div className="activity-row"><div><strong>No recent activity</strong><span>Run a scan to see history</span></div></div>}
      </div></section>
      <section className="console-panel"><div className="console-heading"><div><span className="section-kicker">SEVERITY</span><h2>Finding distribution</h2></div><button className="text-button" onClick={() => onNavigate('findings')}>Filter <ArrowUpRight size={13} /></button></div><div className="severity-console">{(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((severity) => <button key={severity} onClick={() => onNavigate('findings')}><SeverityBadge severity={severity} /><strong>{counts[severity]}</strong><span>{severity === 'Critical' ? 'immediate review' : severity === 'High' ? 'priority queue' : 'remaining queue'}</span></button>)}</div></section>
    </div>
  </div>;
}

function CompliancePage({ findings }: { findings: Finding[] }) {
  const mappings = Array.from(new Set(findings.flatMap((finding) => finding.frameworks))).sort();
  const [exporting, setExporting] = useState(false);
  const [message, setMessage] = useState('');
  const exportEvidence = async () => {
    setExporting(true); setMessage('');
    try {
      const result = await generateReport('markdown');
      setMessage(result.message);
    } catch {
      setMessage('Evidence export failed. Check the local API and try again.');
    } finally { setExporting(false); }
  };
  return <div className="content-stack"><PageHeader eyebrow="Posture management" title="Compliance" description="Authoritative mappings supplied by the deterministic scanner." action={<button className="button button-secondary" onClick={() => void exportEvidence()} disabled={exporting}>{exporting ? <><RefreshCw size={15} className="spin" />Exporting…</> : <><Download size={15} />Export evidence</>}</button>} />{message && <div className="toast" role="status"><CheckCircle2 size={17} />{message}</div>}<div className="compliance-summary"><div className="compliance-stat"><span>Findings mapped</span><strong>{findings.filter((finding) => finding.frameworks.length > 0).length}</strong><small>Current scan findings</small></div><div className="compliance-stat"><span>Mapped controls</span><strong>{mappings.length}</strong><small>Unique authoritative mappings</small></div><div className="compliance-stat"><span>Open findings</span><strong>{findings.filter((finding) => finding.status === 'Open').length}</strong><small>Mapping does not imply compliance</small></div></div>{mappings.length === 0 ? <div className="panel empty-state"><ShieldCheck size={22} /><strong>No authoritative mappings available</strong><span>Run a deterministic scan to populate compliance evidence.</span></div> : <div className="framework-grid">{mappings.map((mapping) => <div className="panel framework-card" key={mapping}><div className="framework-card-top"><div className="framework-icon blue"><ShieldCheck size={18} /></div></div><h3>{mapping}</h3><div className="framework-score"><strong>{findings.filter((finding) => finding.frameworks.includes(mapping)).length}</strong><span>mapped finding(s)</span></div><p className="muted">Mapped control evidence only; no compliance pass is inferred.</p></div>)}</div>}</div>;
}

export default function App() {
  const [page, setPage] = useState<Page>(() => { const stored = sessionStorage.getItem('antifine-page'); return ['overview','scan','findings','compliance','secrets','history','reports','ai','settings'].includes(stored ?? '') ? stored as Page : 'overview'; });
  useEffect(() => { sessionStorage.setItem('antifine-page', page); }, [page]);
  const { findings, setFindings, reloadFindings, findingError, coverage, latestScan, loading } = useFindings();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [remediationFinding, setRemediationFinding] = useState<Finding | null>(null);
  const [explanationCache, setExplanationCache] = useState<Record<string, FindingExplanation>>({});
  const [assistantContext, setAssistantContext] = useState<AskContext>();
  const [assistantQuestion, setAssistantQuestion] = useState('');
  const [target, setTarget] = useState('examples/terraform-workflow');
  const selectFinding = (finding: Finding) => { sessionStorage.setItem('antifine-selected', finding.id); setSelectedFinding(finding); };
  useEffect(() => { const id = sessionStorage.getItem('antifine-selected'); if (id) { const current = findings.find(f => f.id === id); if (current) Promise.resolve().then(() => setSelectedFinding(current)); } }, [findings]);
  const askAboutFinding = (finding: Finding) => {
    setAssistantContext({
      finding_id: finding.id,
      rule_id: finding.rule_id,
      title: finding.rule_name,
      severity: finding.severity,
      technology: finding.file.endsWith('.tf') ? 'terraform' : finding.file.endsWith('.yaml') || finding.file.endsWith('.yml') ? 'kubernetes' : 'docker',
      framework: finding.framework,
      frameworks: finding.frameworks,
      file: finding.file,
      line: finding.line,
      status: finding.status,
      description: finding.description,
      remediation: finding.remediation,
      code_context: finding.before,
    });
    setAssistantQuestion('Explain this finding and why AntiFine classified it this way.');
    setSelectedFinding(null);
    setPage('ai');
  };
  const completeScan = async (nextFindings: Finding[]) => { setFindings(nextFindings); setPage('findings'); await reloadFindings(); };
  const markApplied = () => { sessionStorage.removeItem('antifine-selected'); void reloadFindings(); setSelectedFinding(null); };
  return <AppShell page={page} setPage={(nextPage) => { if (nextPage !== 'ai') { setAssistantContext(undefined); setAssistantQuestion(''); } setPage(nextPage); }}>{findingError && <div className="modal-callout-error" role="alert">{findingError}<button className="button button-secondary" onClick={() => void reloadFindings()}>Retry loading evidence</button></div>}{loading && <p role="status">Loading persisted evidence…</p>}<p className="coverage-notice" role="status">{coverage}</p>{page === 'findings' && latestScan && <CoveragePanel coverage={latestScan.coverage} scanId={latestScan.id} status={latestScan.status}/>}<AnimatePresence mode="wait"><motion.div key={page} className="page-transition" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: 0.16 }}>{page === 'overview' && <Overview findings={findings} onNavigate={setPage} onSelect={selectFinding} />}{page === 'scan' && <ScanWorkspace onComplete={completeScan} onViewFindings={() => setPage('findings')} onOpenFinding={selectFinding} target={target} setTarget={setTarget} />}{page === 'findings' && <FindingsPanel findings={findings} onSelect={selectFinding} />}{page === 'compliance' && <CompliancePage findings={findings} />}{page === 'secrets' && <SecretsPage />}{page === 'history' && <HistoryPage />}{page === 'reports' && <ReportsPage />}{page === 'ai' && <AskAntiFinePage context={assistantContext} initialQuestion={assistantQuestion} onClearContext={() => { setAssistantContext(undefined); setAssistantQuestion(''); }} onNewChat={() => { setAssistantContext(undefined); setAssistantQuestion(''); }} />}{page === 'settings' && <SettingsPage onNavigate={setPage} />}</motion.div></AnimatePresence><AnimatePresence>{selectedFinding && !remediationFinding && <FindingDrawer finding={selectedFinding} onClose={() => { sessionStorage.removeItem('antifine-selected'); setSelectedFinding(null); }} onRemediate={() => setRemediationFinding(selectedFinding)} onAsk={() => askAboutFinding(selectedFinding)} explanationCache={explanationCache} onExplanation={(id, result) => setExplanationCache((current) => ({ ...current, [id]: result }))} />}{remediationFinding && <RemediationModal key={remediationFinding.id} finding={remediationFinding} onClose={() => setRemediationFinding(null)} onApplied={markApplied} />}</AnimatePresence></AppShell>;
}
