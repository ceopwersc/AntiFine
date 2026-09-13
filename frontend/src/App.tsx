import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Copy,
  Download,
  FileCheck2,
  FileCode2,
  FileText,
  FilePlus2,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Menu,
  MessageSquareText,
  Play,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Send,
  Trash2,
  Upload,
  WifiOff,
  Terminal,
  X,
} from 'lucide-react';
import { askAntiFine, explainFinding, explainRemediation, fetchAIHealth, fetchSecretFindings, generateReport, remediateFinding, runScan, type AskContext, type AskMessage, type AskResponse, type FindingExplanation, type RemediationExplanation } from './api';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
type Page = 'overview' | 'scan' | 'findings' | 'compliance' | 'secrets' | 'history' | 'reports' | 'ai' | 'settings';

interface Finding {
  id: string;
  rule_name: string;
  severity: Severity;
  framework: string;
  frameworks: string[];
  file: string;
  line: number;
  description: string;
  remediation: string;
  compliance_framework?: string;
  before: string;
  after: string;
  status: 'Open' | 'Fixed' | 'Accepted';
  detected: string;
}

const navGroups = [
  {
    label: 'Workspace',
    items: [
      { id: 'overview' as Page, label: 'Overview', icon: LayoutDashboard },
      { id: 'scan' as Page, label: 'Scan', icon: Radar },
      { id: 'findings' as Page, label: 'Findings', icon: ShieldAlert, count: 5 },
    ],
  },
  {
    label: 'Posture',
    items: [
      { id: 'compliance' as Page, label: 'Compliance', icon: FileCheck2 },
      { id: 'secrets' as Page, label: 'Secrets', icon: KeyRound, count: 2 },
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

const severityStyles: Record<Severity, string> = {
  Critical: 'severity-critical',
  High: 'severity-high',
  Medium: 'severity-medium',
  Low: 'severity-low',
};

function normalizeSeverity(value: unknown): Severity {
  const normalized = String(value ?? 'Medium').toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'low' || normalized === 'informational' || normalized === 'info') return 'Low';
  return 'Medium';
}

function findingTechnology(file: string) {
  if (file.endsWith('.tf')) return 'Terraform';
  if (file.endsWith('.yaml') || file.endsWith('.yml')) return 'Kubernetes';
  if (file.toLowerCase().includes('dockerfile')) return 'Dockerfile';
  return 'Infrastructure';
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge ${severityStyles[severity]}`}><span className="severity-dot" />{severity}</span>;
}

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
  useEffect(() => {
    void fetchAIHealth().then(setHealth).catch(() => setHealth({
      enabled: false,
      available: false,
      provider: 'ollama',
      model: 'qwen2.5:7b',
      error: 'Backend unavailable',
    }));
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
                return (
                  <button key={item.id} onClick={() => navigate(item.id)} className={`nav-item ${page === item.id ? 'nav-item-active' : ''}`} aria-current={page === item.id ? 'page' : undefined}>
                    <Icon size={17} strokeWidth={page === item.id ? 2.3 : 1.8} />
                    <span>{item.label}</span>
                    {item.count ? <span className="nav-count">{item.count}</span> : null}
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

function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow ?? 'Security posture'}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

function Overview({ findings, onNavigate, onSelect }: { findings: Finding[]; onNavigate: (page: Page) => void; onSelect: (finding: Finding) => void }) {
  const openFindings = useMemo(() => findings.filter((finding) => finding.status === 'Open'), [findings]);
  const counts = useMemo(() => openFindings.reduce<Record<Severity, number>>((acc, finding) => { acc[finding.severity] += 1; return acc; }, { Critical: 0, High: 0, Medium: 0, Low: 0 }), [openFindings]);
  return <div className="content-stack workstation-overview">
    <PageHeader eyebrow="Local workspace" title="Overview" description="Current scan state and findings requiring engineering review." action={<button className="button button-primary" onClick={() => onNavigate('scan')}><Play size={14} fill="currentColor" />Run scan</button>} />
    <section className="ops-strip" aria-label="Operational state">
      <div><span className="ops-label">LAST SCAN</span><strong>IaC Config Audit</strong><code>scan_8f31c2</code><span>12 min ago</span></div>
      <div><span className="ops-label">ENGINE</span><strong className="state-ok">COMPLETE</strong><span>128 files · 6 findings</span></div>
      <div><span className="ops-label">SERVICES</span><span className="service-state">FastAPI · 127.0.0.1:8000</span><span className="service-state">See local status in shell</span></div>
    </section>
    <section className="overview-findings panel">
      <div className="console-heading"><div><span className="section-kicker">WORK QUEUE</span><h2>Open findings</h2></div><div className="console-summary"><span className="severity-count critical">{counts.Critical} critical</span><span className="severity-count high">{counts.High} high</span><button className="text-button" onClick={() => onNavigate('findings')}>Open findings <ArrowUpRight size={13} /></button></div></div>
      <div className="overview-finding-list">{openFindings.slice(0, 5).map((finding) => <button className="overview-finding-row" key={finding.id} onClick={() => onSelect(finding)}><SeverityBadge severity={finding.severity} /><code className="rule-id">{finding.id}</code><strong>{finding.rule_name}</strong><span className="file-ref">{finding.file}:{finding.line}</span><span className="framework-ref">{finding.framework}</span><ChevronRight size={14} /></button>)}</div>
    </section>
    <div className="overview-lower-grid">
      <section className="console-panel"><div className="console-heading"><div><span className="section-kicker">SCAN STATE</span><h2>Latest activity</h2></div><button className="text-button" onClick={() => onNavigate('history')}>History <ArrowUpRight size={13} /></button></div><div className="activity-list compact-activity"><div className="activity-row"><div className="activity-status success"><Check size={13} /></div><div><strong>IaC audit completed</strong><span>6 findings · deterministic engine</span></div><time>12 min ago</time></div><div className="activity-row"><div className="activity-status"><GitBranch size={13} /></div><div><strong>Repository scan ready</strong><span>Local workspace · read-only</span></div><time>2 hr ago</time></div></div></section>
      <section className="console-panel"><div className="console-heading"><div><span className="section-kicker">SEVERITY</span><h2>Finding distribution</h2></div><button className="text-button" onClick={() => onNavigate('findings')}>Filter <ArrowUpRight size={13} /></button></div><div className="severity-console">{(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((severity) => <button key={severity} onClick={() => onNavigate('findings')}><SeverityBadge severity={severity} /><strong>{counts[severity]}</strong><span>{severity === 'Critical' ? 'immediate review' : severity === 'High' ? 'priority queue' : 'remaining queue'}</span></button>)}</div></section>
    </div>
  </div>;
}

type ScanQueueItem = {
  id: string;
  name: string;
  size: number;
  type: 'Terraform' | 'Kubernetes' | 'Docker' | 'Unknown';
  status: 'Added' | 'Ready' | 'Error';
  error?: string;
};

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function queuedFileType(name: string): ScanQueueItem['type'] {
  if (name.endsWith('.tf')) return 'Terraform';
  if (name.endsWith('.yaml') || name.endsWith('.yml')) return 'Kubernetes';
  if (name.toLowerCase() === 'dockerfile' || name.toLowerCase().includes('dockerfile')) return 'Docker';
  return 'Unknown';
}

function ScanWorkspace({ onComplete, target, setTarget, onViewFindings, onOpenFinding }: { onComplete: (findings: Finding[]) => void; target: string; setTarget: (target: string) => void; onViewFindings: () => void; onOpenFinding: (finding: Finding) => void }) {
  const [scanType, setScanType] = useState('IaC Config Audit');
  const [scanning, setScanning] = useState(false);
  const [scanLog, setScanLog] = useState<string[]>(['Ready. Add a server-local file path to begin.']);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const [queue, setQueue] = useState<ScanQueueItem[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [scanResult, setScanResult] = useState<{ findings: Finding[]; durationMs: number; target: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const addFiles = (files: FileList | File[]) => {
    const additions = Array.from(files).map((file) => {
      const type = queuedFileType(file.name);
      return {
        id: `${file.name}-${file.size}-${file.lastModified}`,
        name: file.name,
        size: file.size,
        type,
        status: type === 'Unknown' ? 'Error' as const : 'Ready' as const,
        error: type === 'Unknown' ? 'Unsupported file type' : undefined,
      };
    });
    setQueue((current) => [...current, ...additions.filter((item) => !current.some((existing) => existing.id === item.id))]);
    const firstValid = additions.find((item) => item.status === 'Ready');
    if (firstValid && queue.length === 0) setTarget(firstValid.name);
    setError('');
  };
  const validQueue = queue.filter((item) => item.status === 'Ready');
  const removeFile = (id: string) => setQueue((current) => current.filter((item) => item.id !== id));
  const clearQueue = () => { setQueue([]); setScanResult(null); setDone(false); };
  const startScan = async () => {
    if (!target.trim() || validQueue.length === 0 || scanning) return;
    setScanning(true); setDone(false); setError(''); setScanResult(null);
    const startedAt = performance.now();
    setScanLog(['Initializing local scan context…', `Target: ${target.trim()}`, `Protocol: ${scanType}`, 'Parsing configuration…']);
    try {
      const result = await runScan(target.trim(), scanType);
      const returned = Array.isArray(result?.findings) ? result.findings : [];
      const durationMs = Math.round(performance.now() - startedAt);
      const mappedFindings = returned.map((item: Partial<Finding>, index: number) => {
        return {
          ...item,
          id: item.id ?? `AF-${1100 + index}`,
          severity: normalizeSeverity(item.severity),
          frameworks: item.frameworks?.length ? item.frameworks : item.framework ? [item.framework] : item.compliance_framework ? [item.compliance_framework] : [],
          framework: item.framework ?? item.compliance_framework ?? 'Unmapped',
          file: item.file ?? target,
          line: item.line ?? 0,
          description: item.description ?? item.rule_name ?? 'No description supplied by the scan engine.',
          remediation: item.remediation ?? 'No deterministic remediation supplied.',
          before: item.before ?? '',
          after: item.after ?? '',
          status: item.status ?? 'Open',
          detected: item.detected ?? 'just now',
        } as Finding;
      });
      onComplete(mappedFindings);
      setScanResult({ findings: mappedFindings, durationMs, target: result?.target ?? target.trim() });
      setScanLog((current) => [...current, 'Rules evaluated.', 'Compliance mappings resolved.', `Scan complete · ${returned.length} findings`]);
      setDone(true);
    } catch (requestError: any) {
      const detail = requestError?.response?.data?.detail;
      setError(detail || 'The scan backend could not complete this request.');
      setScanLog((current) => [...current, 'Scan failed · no findings were loaded.']);
    } finally { setScanning(false); }
  };
  return <div className="content-stack scan-workspace"><PageHeader eyebrow="Local security engine" title="New security scan" description="Analyze infrastructure locally before deployment." /><div className="scan-layout"><section className="panel scan-config"><div className="panel-heading"><div><h2>Files</h2><p>Server-local paths are scanned read-only by FastAPI.</p></div><div className="secure-label"><ShieldCheck size={14} /> Local</div></div><div className={`drop-zone ${dragActive ? 'drop-zone-active' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); setDragActive(false); addFiles(event.dataTransfer.files); }}><Upload size={18} /><strong>Drop files here</strong><span>or</span><button type="button" className="button button-secondary" onClick={() => fileInputRef.current?.click()}><FilePlus2 size={14} />Choose files</button><small>Supported: .tf · .yaml · .yml · Dockerfile</small><input ref={fileInputRef} type="file" multiple accept=".tf,.yaml,.yml,Dockerfile" hidden onChange={(event) => { if (event.target.files) addFiles(event.target.files); event.currentTarget.value = ''; }} /></div><div className="queue-heading"><span>Scan queue <strong>{queue.length}</strong></span>{queue.length > 0 && <button type="button" className="text-button" onClick={clearQueue}>Clear all</button>}</div><div className="scan-queue">{queue.length === 0 ? <div className="queue-empty">No files queued.</div> : queue.map((file) => <div className={`queue-row ${file.status === 'Error' ? 'queue-error' : ''}`} key={file.id}><FileCode2 size={15} /><div><strong>{file.name}</strong><span>{file.type} · {formatFileSize(file.size)}</span></div><span className={`queue-status ${file.status.toLowerCase()}`}>{file.status}</span>{file.error && <span className="queue-error-text">{file.error}</span>}<button type="button" className="icon-button small" aria-label={`Remove ${file.name}`} onClick={() => removeFile(file.id)}><X size={14} /></button></div>)}</div><label className="field-label" htmlFor="target">Server-local target path</label><div className="input-with-icon"><FileCode2 size={17} /><input id="target" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void startScan(); }} placeholder="e.g. infra/production.tf" /></div><label className="field-label" htmlFor="protocol">Scan protocol</label><div className="select-wrap"><Radar size={17} /><select id="protocol" value={scanType} onChange={(event) => setScanType(event.target.value)}><option>IaC Config Audit</option><option>SSRF Web Audit</option></select><ChevronDown size={15} /></div><div className="scan-summary"><span>Files <strong>{validQueue.length}</strong></span><span>Technologies <strong>{Array.from(new Set(validQueue.map((item) => item.type))).join(' · ') || '—'}</strong></span><span>Rules <strong>Backend reported</strong></span></div><button className="button button-primary scan-button" onClick={() => void startScan()} disabled={scanning || !target.trim() || validQueue.length === 0}>{scanning ? <><RefreshCw size={16} className="spin" />Scanning…</> : <><Play size={16} fill="currentColor" />Run scan</>}</button>{error && <div className="inline-error"><AlertTriangle size={15} />{error}</div>}</section><section className={`panel terminal-panel ${scanning ? 'terminal-active' : ''}`}><div className="terminal-header"><span><span className="terminal-dot red" /><span className="terminal-dot yellow" /><span className="terminal-dot green" /></span><span className="terminal-title"><Terminal size={14} /> scan output</span><span className="terminal-live">{scanning ? 'LIVE' : done ? 'COMPLETE' : 'IDLE'}</span></div><div className="terminal-body">{scanLog.map((line, index) => <div key={`${line}-${index}`} className={line.includes('complete') || line.includes('findings') ? 'terminal-success' : index === scanLog.length - 1 && scanning ? 'terminal-current' : ''}><span className="terminal-prefix">{index === scanLog.length - 1 && scanning ? '›' : '✓'}</span>{line}</div>)}{scanning && <div className="terminal-cursor">▌</div>}{scanResult && <><div className="scan-completion"><div><span className="section-kicker">SCAN COMPLETE</span><strong>{scanResult.findings.length} findings</strong><span>{scanResult.target}</span><span>{scanResult.durationMs} ms · rules evaluated by backend</span></div><div className="completion-actions"><button type="button" className="button button-primary" onClick={onViewFindings}>View findings</button><button type="button" className="button button-secondary" onClick={() => { setDone(false); setScanResult(null); }}>Run again</button></div></div><div className="scan-output-findings">{scanResult.findings.slice(0, 5).map((finding) => <button type="button" key={finding.id} onClick={() => onOpenFinding(finding)}><SeverityBadge severity={finding.severity} /><code>{finding.id}</code><span>{finding.rule_name}</span><span>{finding.file}:{finding.line}</span><ChevronRight size={13} /></button>)}</div></>}</div><div className="terminal-footer"><span><Activity size={14} /> FastAPI · 127.0.0.1:8000</span><span>Read-only scan</span></div></section></div><div className="scan-trust-row"><ShieldCheck size={17} /><span>Local security engine</span><span className="muted">Deterministic scanner · no file mutation</span></div></div>;
}

function FindingsPage({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'All'>('All');
  const [status, setStatus] = useState<'All' | Finding['status']>('All');
  const [sortBy, setSortBy] = useState<'severity' | 'file' | 'status'>('severity');
  const severityOrder: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const filtered = findings
    .filter((finding) => (severity === 'All' || finding.severity === severity) && (status === 'All' || finding.status === status) && `${finding.id} ${finding.rule_name} ${finding.file} ${finding.frameworks.join(' ')}`.toLowerCase().includes(query.toLowerCase()))
    .sort((left, right) => sortBy === 'severity'
      ? severityOrder[left.severity] - severityOrder[right.severity]
      : sortBy === 'file'
        ? left.file.localeCompare(right.file)
        : left.status.localeCompare(right.status));
  return <div className="content-stack workstation-findings"><PageHeader eyebrow="Finding queue" title="Findings" description="Deterministic findings, code locations, and review state." /><div className="finding-workflow"><span>Finding</span><ChevronRight size={13} /><span>Code</span><ChevronRight size={13} /><span>Rule</span><ChevronRight size={13} /><span>Compliance</span><ChevronRight size={13} /><span>Remediation</span><ChevronRight size={13} /><span>Diff</span><ChevronRight size={13} /><span>Apply</span><ChevronRight size={13} /><span>Rescan</span></div><div className="finding-toolbar"><div className="search-input"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search rule IDs, files, paths, frameworks" /><kbd>⌘ K</kbd></div><div className="filter-group"><SlidersHorizontal size={15} className="muted" /><select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | 'All')} aria-label="Filter by severity"><option value="All">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><select value={status} onChange={(event) => setStatus(event.target.value as 'All' | Finding['status'])} aria-label="Filter by status"><option value="All">All status</option><option>Open</option><option>Fixed</option><option>Accepted</option></select><select value={sortBy} onChange={(event) => setSortBy(event.target.value as typeof sortBy)} aria-label="Sort findings"><option value="severity">Sort: severity</option><option value="file">Sort: file</option><option value="status">Sort: status</option></select></div></div><div className="panel table-panel"><div className="table-meta"><span><strong>{filtered.length}</strong> findings in current scan</span><span><code>scan_8f31c2</code> · <span className="live-text">LOCAL DATA</span></span></div><div className="table-scroll"><table className="findings-table workstation-table"><thead><tr><th>Severity</th><th>Rule / finding</th><th>Code location</th><th>Framework</th><th>Evidence</th><th>Status</th><th aria-label="Actions" /></tr></thead><tbody>{filtered.map((finding) => <tr key={finding.id} tabIndex={0} role="button" onClick={() => onSelect(finding)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(finding); } }}><td><SeverityBadge severity={finding.severity} /></td><td><div className="finding-cell"><div><code className="rule-id">{finding.id}</code><strong>{finding.rule_name}</strong></div></div></td><td><code>{finding.file}</code><span className="line-number">:{finding.line}</span><pre className="table-code">{finding.before.split('\n')[0]}</pre></td><td><span className="framework-pill">{finding.framework}</span></td><td><span className="evidence-text">detected {finding.detected}</span></td><td><span className={`status-badge ${finding.status.toLowerCase()}`}><span />{finding.status}</span></td><td><ChevronRight size={15} className="muted" /></td></tr>)}</tbody></table></div>{filtered.length === 0 && <div className="empty-state"><Search size={22} /><strong>No findings match these filters</strong><span>Try a rule ID, file path, or framework.</span></div>}<div className="table-footer"><span>Showing {filtered.length} of {findings.length} · click a row to inspect code and remediation</span><div><button className="pagination-button" disabled>Previous</button><button className="pagination-button active">1</button><button className="pagination-button" disabled>Next</button></div></div></div></div>;
}

function renderExplanation(explanation: string) {
  return explanation.split(/\n+/).map((line, index) => {
    const heading = line.replace(/[*#]/g, '').replace(/:$/, '').trim();
    const section = /^(What was detected|Why it matters|Compliance impact|Recommended action|Developer takeaway)$/i.test(heading);
    return section
      ? <h4 key={`${line}-${index}`}>{heading}</h4>
      : line.trim() ? <p key={`${line}-${index}`}>{line.replace(/^\s*[-*]\s*/, '')}</p> : null;
  });
}

type AssistantMessage = AskMessage & { sources?: AskResponse['sources'] };

function renderMarkdown(markdown: string) {
  const renderInline = (value: string) => value.split(/(`[^`]+`)/g).map((part, partIndex) => part.startsWith('`') && part.endsWith('`')
    ? <code key={partIndex}>{part.slice(1, -1)}</code>
    : part);
  const lines = markdown.split(/\r?\n/);
  const nodes: ReactNode[] = [];
  let inCode = false;
  let codeLines: string[] = [];
  let listItems: ReactNode[] = [];
  const flushList = () => {
    if (listItems.length) {
      nodes.push(<ul key={`list-${nodes.length}`}>{listItems}</ul>);
      listItems = [];
    }
  };
  lines.forEach((line, index) => {
    if (line.trim().startsWith('```')) {
      if (inCode) {
        nodes.push(<pre className="assistant-code" key={`code-${index}`}><code>{codeLines.join('\n')}</code></pre>);
        codeLines = [];
      }
      inCode = !inCode;
      return;
    }
    if (inCode) {
      codeLines.push(line);
      return;
    }
    const content = line.replace(/^\s*[-*]\s/, '');
    if (!line.trim()) return;
    if (/^#{1,3}\s/.test(line)) {
      flushList();
      nodes.push(<h4 key={index}>{line.replace(/^#{1,3}\s/, '')}</h4>);
    } else if (/^\s*[-*]\s/.test(line)) {
      listItems.push(<li key={index}>{renderInline(content)}</li>);
    } else {
      flushList();
      nodes.push(<p key={index}>{renderInline(content)}</p>);
    }
  });
  flushList();
  return nodes;
}

function AskAntiFinePage({
  context,
  initialQuestion,
  onClearContext,
  onNewChat,
}: {
  context?: AskContext;
  initialQuestion?: string;
  onClearContext: () => void;
  onNewChat: () => void;
}) {
  const [health, setHealth] = useState<Awaited<ReturnType<typeof fetchAIHealth>> | null>(null);
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [question, setQuestion] = useState(initialQuestion ?? '');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const suggestions = [
    'How does AntiFine detect high-entropy secrets?',
    'Why is TF-AWS-004 critical?',
    'Which CIS controls are currently failing?',
    'How does deterministic remediation work?',
    'What does PSS Restricted require?',
  ];

  const checkHealth = async () => {
    try {
      setHealth(await fetchAIHealth());
    } catch {
      setHealth({ enabled: true, available: false, provider: 'ollama', model: 'qwen2.5:7b', error: 'Backend unavailable' });
    }
  };
  useEffect(() => { void checkHealth(); }, []);
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        composerRef.current?.focus();
      }
      if (event.key === 'Escape' && context) onClearContext();
    };
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, [context, onClearContext]);

  const sendQuestion = async (value = question) => {
    const trimmed = value.trim();
    if (!trimmed || loading) return;
    setQuestion('');
    setError('');
    const previousMessages = messages.map(({ role, content }) => ({ role, content })).slice(-10);
    setMessages((current) => [...current, { role: 'user', content: trimmed }]);
    setLoading(true);
    try {
      const response = await askAntiFine(trimmed, context, previousMessages);
      if (!response.answer?.trim()) throw new Error('The assistant returned an empty response.');
      setMessages((current) => [...current, { role: 'assistant', content: response.answer, sources: response.sources }]);
    } catch (requestError: any) {
      setError(requestError?.response?.data?.detail || 'Local AI is unavailable.');
    } finally {
      setLoading(false);
    }
  };
  const retry = () => {
    const lastQuestion = [...messages].reverse().find((message) => message.role === 'user')?.content;
    if (lastQuestion) void sendQuestion(lastQuestion);
  };
  const newChat = () => { setMessages([]); setError(''); setQuestion(''); onNewChat(); };
  const copyAnswer = async (content: string) => {
    if (!navigator.clipboard) {
      setError('Copy is unavailable in this browser context.');
      return;
    }
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setError('AntiFine could not copy this response.');
    }
  };
  const available = health?.available === true;

  return <div className="content-stack assistant-page">
    <div className="assistant-header">
      <div><div className="eyebrow">Local intelligence</div><h1>Ask AntiFine</h1><p>Local security intelligence for your infrastructure.</p></div>
      <div className="assistant-actions"><button className="button button-secondary" onClick={newChat}><MessageSquareText size={14} />New chat</button><button className="button button-secondary" onClick={() => { setMessages([]); setError(''); }} disabled={!messages.length}><Trash2 size={14} />Clear conversation</button></div>
    </div>
    <div className={`assistant-status ${available ? 'assistant-online' : 'assistant-offline'}`}>
      {available ? <Bot size={17} /> : <WifiOff size={17} />}
      <div><strong>{available ? 'Local AI ready' : health?.enabled === false ? 'Local AI disabled' : health ? 'Ollama unavailable' : 'Checking local AI…'}</strong><span>Answers are generated locally using Ollama and AntiFine’s local knowledge.</span></div>
      <span className="assistant-model">{health?.provider ?? 'ollama'} · {health?.model ?? 'qwen2.5:7b'}</span>
      {!available && health?.enabled !== false && <button className="text-button" onClick={() => void checkHealth()}>Retry connection</button>}
    </div>
    {context && <div className="assistant-context"><div><span>Analyzing</span><strong>{context.rule_id || context.finding_id}</strong></div><SeverityBadge severity={normalizeSeverity(context.severity)} /><code>{context.technology} · {context.finding_id}</code><button className="icon-button small" aria-label="Remove finding context" onClick={onClearContext}><X size={14} /></button></div>}
    <section className="panel assistant-panel">
      <div className="assistant-conversation" aria-live="polite">
        {!messages.length && <div className="assistant-empty"><div className="assistant-empty-icon"><MessageSquareText size={20} /></div><h2>What can I help you investigate?</h2><p>Ask about AntiFine rules, compliance mappings, remediation behavior, or a finding.</p><div className="suggestion-grid">{suggestions.map((suggestion) => <button key={suggestion} onClick={() => void sendQuestion(suggestion)}>{suggestion}<Send size={13} /></button>)}</div></div>}
        {messages.map((message, index) => <div className={`assistant-message ${message.role}`} key={`${message.role}-${index}`}><div className="message-meta">{message.role === 'user' ? 'You' : 'AntiFine · local assistant'}</div><div className="message-body">{message.role === 'assistant' ? renderMarkdown(message.content) : <p>{message.content}</p>}</div>{message.role === 'assistant' && <>{message.sources?.length ? <div className="source-list"><span className="source-label">Sources</span>{message.sources.map((source) => <div className="source-item" key={`${source.source}-${source.title}`}><BookOpen size={13} /><div><strong>{source.title}</strong><span>{source.source}{source.rule_id ? ` · ${source.rule_id}` : ''}</span></div></div>)}</div> : null}<div className="message-actions"><button className="text-button" onClick={() => void copyAnswer(message.content)}><Copy size={13} />{copied ? 'Copied' : 'Copy answer'}</button><button className="text-button" onClick={retry}><RefreshCw size={13} />Regenerate</button></div></>}</div>)}
        {loading && <div className="assistant-message assistant"><div className="message-meta">AntiFine · local assistant</div><div className="assistant-loading"><RefreshCw size={14} className="spin" />Analyzing locally…</div></div>}
        {error && <div className="assistant-error"><strong>Local AI is unavailable.</strong><span>AntiFine’s deterministic security engine remains fully operational.</span><button className="text-button" onClick={retry}>Retry</button></div>}
      </div>
      <div className="assistant-composer"><textarea ref={composerRef} value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void sendQuestion(); } }} placeholder="Ask about AntiFine, a finding, compliance rule, or remediation…" aria-label="Ask AntiFine a question" /><div className="composer-footer"><span><kbd>Enter</kbd> send · <kbd>Shift + Enter</kbd> newline · <kbd>⌘ K</kbd> focus</span><button className="button button-primary" onClick={() => void sendQuestion()} disabled={loading || !question.trim()}>{loading ? <><RefreshCw size={14} className="spin" />Analyzing…</> : <><Send size={14} />Send</>}</button></div></div>
    </section>
  </div>;
}

function remediationDiff(before: string, after: string) {
  return `--- deterministic before\n+++ deterministic after\n${before.split('\n').map((line) => `- ${line}`).join('\n')}\n${after.split('\n').map((line) => `+ ${line}`).join('\n')}`;
}

function FindingDrawer({
  finding,
  onClose,
  onRemediate,
  onAsk,
  explanationCache,
  onExplanation,
}: {
  finding: Finding;
  onClose: () => void;
  onRemediate: () => void;
  onAsk: () => void;
  explanationCache: Record<string, FindingExplanation>;
  onExplanation: (findingId: string, explanation: FindingExplanation) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiError, setAIError] = useState('');
  const explanation = explanationCache[finding.id];
  const deterministicFixAvailable = Boolean(finding.remediation) &&
    !/no action required|no deterministic remediation|not available/i.test(finding.remediation);
  const copy = () => { void navigator.clipboard?.writeText(finding.remediation); setCopied(true); window.setTimeout(() => setCopied(false), 1500); };
  const requestExplanation = async () => {
    setLoadingAI(true); setAIError('');
    try {
      const result = await explainFinding({
        rule_name: finding.rule_name,
        severity: finding.severity.toUpperCase(),
        filename: finding.file,
        frameworks: finding.frameworks,
        remediation: finding.remediation,
        description: finding.description,
      }, finding.before);
      onExplanation(finding.id, result);
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      setAIError(detail || 'Local AI unavailable');
    } finally { setLoadingAI(false); }
  };
  return <><motion.button className="drawer-scrim" onClick={onClose} aria-label="Close finding details" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} /><motion.aside className="detail-drawer" role="dialog" aria-modal="true" aria-label="Finding details" initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', damping: 28, stiffness: 260 }}><div className="drawer-header"><div><span className="drawer-eyebrow">Finding <code>{finding.id}</code></span><h2>{finding.rule_name}</h2><div className="drawer-meta-line"><span>{findingTechnology(finding.file)}</span><span>{finding.file}:{finding.line}</span></div></div><button className="icon-button" onClick={onClose} aria-label="Close"><X size={19} /></button></div><div className="drawer-content"><div className="drawer-badges"><SeverityBadge severity={finding.severity} /><span className={`status-badge ${finding.status.toLowerCase()}`}><span />{finding.status}</span></div><section className="drawer-section"><h3>Detection</h3><p>{finding.description}</p></section><section className="drawer-section"><h3>Code</h3><div className="drawer-code"><div><span>{finding.file}</span><span>line {finding.line}</span></div><pre>{finding.before}</pre></div></section><section className="drawer-section"><h3>Compliance mapping</h3><div className="framework-list">{finding.frameworks.length ? finding.frameworks.map((framework) => <span key={framework} className="framework-pill">{framework}</span>) : <span className="muted">No authoritative mapping supplied</span>}</div></section><section className="drawer-section remediation-preview"><div className="section-heading-row"><h3>Deterministic remediation</h3>{deterministicFixAvailable && <button className="text-button" onClick={copy}>{copied ? <><Check size={13} />Copied</> : <><Copy size={13} />Copy</>}</button>}</div><p>{finding.remediation || 'No deterministic remediation available.'}</p>{finding.after && <pre>{finding.after}</pre>}</section><section className="drawer-section ai-explanation" aria-live="polite"><div className="section-heading-row"><div><h3>Local AI</h3><span className="ai-label">Ollama · secondary explanation</span></div>{explanation && <button className="text-button" onClick={() => void requestExplanation()} disabled={loadingAI}>{loadingAI ? 'Analyzing locally…' : 'Regenerate'}</button>}</div><p className="ai-disclaimer">AI explains the deterministic finding; it does not change the rule result or remediation.</p>{aiError ? <div className="ai-error"><strong>Local AI unavailable</strong><span>AntiFine's deterministic security analysis is still available.</span><button className="text-button" onClick={() => void requestExplanation()} disabled={loadingAI}>Retry</button></div> : explanation ? <div className="ai-response"><span className="ai-model">{explanation.model} · generated locally</span>{renderExplanation(explanation.explanation)}</div> : <button className="button button-secondary ai-explain-button" onClick={() => void requestExplanation()} disabled={loadingAI}>{loadingAI ? <><RefreshCw size={15} className="spin" />Analyzing locally…</> : <><Sparkles size={15} />Explain with Local AI</>}</button>}<button className="button button-secondary ai-ask-button" onClick={onAsk}><MessageSquareText size={14} />Ask AntiFine about this</button></section></div><div className="drawer-footer"><button className="button button-secondary" onClick={onClose}>Close</button>{deterministicFixAvailable && finding.status === 'Open' && <button className="button button-primary" onClick={onRemediate}><Sparkles size={15} />Review fix</button>}</div></motion.aside></>;
}

function RemediationModal({ finding, onClose, onApplied }: { finding: Finding; onClose: () => void; onApplied: () => void }) {
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState(false);
  const [remediationError, setRemediationError] = useState('');
  const [reviewExplanation, setReviewExplanation] = useState<RemediationExplanation | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState('');
  const [verification, setVerification] = useState<{ backup?: string; findings_count?: number } | null>(null);
  const apply = async () => {
    setApplying(true);
    setRemediationError('');
    try {
      const result = await remediateFinding(finding.file, finding.rule_name);
      setVerification(result);
      if (result.findings_count === 0) {
        setApplied(true);
        onApplied();
      } else {
        setRemediationError(`Verification failed: ${result.findings_count} finding${result.findings_count === 1 ? '' : 's'} remain open. The finding was not marked remediated.`);
      }
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      setRemediationError(detail || 'AntiFine could not apply this deterministic fix.');
    } finally {
      setApplying(false);
    }
  };
  const explainFix = async () => {
    setReviewLoading(true);
    setReviewError('');
    try {
      const result = await explainRemediation({
        finding: {
          rule_name: finding.rule_name,
          severity: finding.severity.toUpperCase(),
          filename: finding.file,
          frameworks: finding.frameworks,
          remediation: finding.remediation,
          description: finding.description,
        },
        before: finding.before,
        after: finding.after,
        diff: remediationDiff(finding.before, finding.after),
        remediation: finding.remediation,
        frameworks: finding.frameworks,
      });
      setReviewExplanation(result);
    } catch (error: any) {
      setReviewError(error?.response?.data?.detail || 'Local AI unavailable');
    } finally {
      setReviewLoading(false);
    }
  };
  return <motion.div className="modal-scrim" role="dialog" aria-modal="true" aria-label="Review remediation" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><motion.div className="remediation-modal" initial={{ opacity: 0, y: 16, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}><div className="modal-header"><div><span className="drawer-eyebrow">Deterministic remediation</span><h2>Review proposed fix</h2><p>Inspect the exact change before applying it to <code>{finding.file}</code>.</p></div><button className="icon-button" onClick={onClose} aria-label="Close"><X size={19} /></button></div><div className="diff-meta"><span><FileCode2 size={15} />{finding.file}</span><span>Line {finding.line}</span><span className="diff-safe"><ShieldCheck size={14} />Deterministic proposal</span></div><div className="diff-view"><div className="diff-column"><div className="diff-column-header removed">Before <span>−</span></div><pre>{finding.before.split('\n').map((line, index) => <div key={`${line}-${index}`} className="diff-line removed-line"><span>{String(index + 1).padStart(2, '0')}</span>{line || ' '}</div>)}</pre></div><div className="diff-column"><div className="diff-column-header added">After <span>＋</span></div><pre>{finding.after.split('\n').map((line, index) => <div key={`${line}-${index}`} className="diff-line added-line"><span>{String(index + 1).padStart(2, '0')}</span>{line || ' '}</div>)}</pre></div></div><section className="remediation-ai-review" aria-live="polite"><div className="section-heading-row"><div><h3>AI explanation</h3><span className="ai-label">Local AI · Ollama</span></div>{reviewExplanation && <button className="text-button" onClick={() => void explainFix()} disabled={reviewLoading}>{reviewLoading ? 'Analyzing remediation locally…' : 'Regenerate'}</button>}</div><p className="ai-disclaimer">Optional review of the deterministic AntiFine proposal. AI does not approve or apply this fix.</p>{reviewError ? <div className="ai-error"><strong>Local AI unavailable</strong><span>AntiFine can still preview, apply, and verify this deterministic fix.</span><button className="text-button" onClick={() => void explainFix()} disabled={reviewLoading}>Retry</button></div> : reviewExplanation ? <div className="ai-response"><span className="ai-model">{reviewExplanation.model} · generated locally</span>{renderExplanation(reviewExplanation.explanation)}</div> : <button className="button button-secondary ai-explain-button" onClick={() => void explainFix()} disabled={reviewLoading}>{reviewLoading ? <><RefreshCw size={15} className="spin" />Analyzing remediation locally…</> : <><Sparkles size={15} />Explain this Fix</>}</button>}</section>  {verification && <div className={`modal-callout${verification.findings_count === 0 ? '' : ' modal-callout-error'}`}><ShieldCheck size={17} /><div><strong>{verification.findings_count === 0 ? 'Verification completed' : 'Verification failed'}</strong><span>{verification.findings_count === 0 ? `Finding no longer detected. Backup: ${verification.backup ?? 'created'}.` : `${verification.findings_count} finding(s) remain open; the finding was not marked remediated.`}</span></div></div>}<div className={`modal-callout${remediationError ? ' modal-callout-error' : ''}`}><ShieldCheck size={17} /><div><strong>{remediationError ? 'Remediation failed' : 'Before you apply'}</strong><span>{remediationError || '1 file will change · 1 backup will be created · 1 deterministic rule will be remediated.'}</span></div></div><div className="modal-footer"><button className="button button-secondary" onClick={onClose}>Cancel</button>{applied ? <button className="button button-success" onClick={onClose}><Check size={15} />Fix applied</button> : <button className="button button-primary" disabled={applying} onClick={() => void apply()}>{applying ? <><RefreshCw size={15} className="spin" />Applying fix…</> : <><Sparkles size={15} />Apply deterministic fix</>}</button>}</div></motion.div></motion.div>;
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

function SecretsPage() {
  const [secrets, setSecrets] = useState<Awaited<ReturnType<typeof fetchSecretFindings>>['findings']>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    void fetchSecretFindings().then((result) => setSecrets(result.findings)).catch(() => setError('Secret findings unavailable. Connect the local API and run a scan.'));
  }, []);
  return <div className="content-stack"><PageHeader eyebrow="Posture management" title="Secrets" description="Persisted secret findings with values intentionally withheld." /><div className="secret-banner"><div className="secret-banner-icon"><ShieldAlert size={19} /></div><div><strong>{secrets.length} secret finding{secrets.length === 1 ? '' : 's'} need attention</strong><span>Rotate exposed credentials, then verify the deterministic finding is gone.</span></div></div>{error ? <div className="panel empty-state"><WifiOff size={22} /><strong>{error}</strong></div> : secrets.length === 0 ? <div className="panel empty-state"><ShieldCheck size={22} /><strong>No persisted secret findings</strong><span>Run a deterministic scan to check local infrastructure.</span></div> : <div className="panel table-panel"><div className="table-meta"><span><strong>Open secrets</strong></span><span>Values withheld</span></div><div className="table-scroll"><table className="findings-table secrets-table"><thead><tr><th>Rule</th><th>Location</th><th>Severity</th><th>Detected</th><th>Status</th></tr></thead><tbody>{secrets.map((secret) => <tr key={`${secret.filename}-${secret.rule_name}`}><td><div className="finding-cell"><div className="finding-icon critical"><KeyRound size={15} /></div><div><strong>{secret.rule_name}</strong><span>Safe metadata only</span></div></div></td><td><code>{secret.filename}</code></td><td><span className="severity-badge critical"><span className="severity-dot" />{secret.severity}</span></td><td>{secret.detected}</td><td><span className={`status-badge ${secret.status.toLowerCase()}`}><span />{secret.status}</span></td></tr>)}</tbody></table></div></div>}<div className="secret-trust"><ShieldCheck size={17} /><div><strong>Privacy by design</strong><span>AntiFine never returns secret values. Only rule, location, severity, and lifecycle metadata are shown.</span></div></div></div>;
}

function HistoryPage() {
  const scans = [{ id: 'scan_8f31c2', target: 'acme-infrastructure', type: 'IaC Config Audit', findings: 6, status: 'Completed', time: '12 min ago', duration: '18.4s' }, { id: 'scan_3a10b9', target: 'acme/web · PR #418', type: 'IaC Config Audit', findings: 2, status: 'Completed', time: '2 hr ago', duration: '11.2s' }, { id: 'scan_887bc1', target: 'staging ingress', type: 'SSRF Web Audit', findings: 0, status: 'Completed', time: 'Yesterday', duration: '7.8s' }, { id: 'scan_11ac72', target: 'acme-infrastructure', type: 'IaC Config Audit', findings: 8, status: 'Completed', time: 'Sep 08, 2026', duration: '20.1s' }];
  const [exporting, setExporting] = useState(false);
  const [message, setMessage] = useState('');
  const exportHistory = async () => {
    setExporting(true); setMessage('');
    try { setMessage((await generateReport('markdown')).message); } catch { setMessage('History export failed. Check the local API and try again.'); } finally { setExporting(false); }
  };
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Scan history" description="A complete audit trail of local scans." action={<button className="button button-secondary" onClick={() => void exportHistory()} disabled={exporting}>{exporting ? <><RefreshCw size={15} className="spin" />Exporting…</> : <><Download size={15} />Export history</>}</button>} />{message && <div className="toast" role="status"><CheckCircle2 size={17} />{message}</div>}<div className="panel table-panel"><div className="table-meta"><span><strong>Recent scans</strong></span><div className="filter-group"><select aria-label="Filter scan type"><option>All scan types</option><option>IaC Config Audit</option><option>SSRF Web Audit</option></select></div></div><div className="table-scroll"><table className="findings-table history-table"><thead><tr><th>Target</th><th>Scan type</th><th>Findings</th><th>Status</th><th>Run time</th></tr></thead><tbody>{scans.map((scan) => <tr key={scan.id}><td><div className="finding-cell"><div className="finding-icon blue"><GitBranch size={15} /></div><div><strong>{scan.target}</strong><span>{scan.id} · {scan.duration}</span></div></div></td><td><span className="muted">{scan.type}</span></td><td><span className={scan.findings ? 'finding-count' : 'finding-count clean'}>{scan.findings || 'Clean'}</span></td><td><span className="status-badge fixed"><span />{scan.status}</span></td><td>{scan.time}</td></tr>)}</tbody></table></div></div></div>;
}

function ReportsPage() {
  const [loading, setLoading] = useState('');
  const [message, setMessage] = useState('');
  const createReport = async (format: string) => { setLoading(format); setMessage(''); try { const result = await generateReport(format); setMessage(result.message ?? 'Report generated successfully.'); if (result.downloadUrl) { const link = document.createElement('a'); link.href = result.downloadUrl; link.download = 'antifine-results.sarif'; link.click(); } } catch { setMessage('Report queued. Connect the API to download the generated artifact.'); } finally { setLoading(''); } };
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Reports" description="Generate audit-ready evidence for engineering, security, and compliance teams." /><div className="report-grid"><div className="panel report-card"><div className="report-icon blue"><FileText size={20} /></div><h2>Executive summary</h2><p>A concise Markdown report with posture score, finding trends, and recommended priorities.</p><div className="report-meta"><span><Clock3 size={14} />Generated from latest scan</span><span><FileText size={14} />Markdown</span></div><button className="button button-secondary" onClick={() => void createReport('markdown')} disabled={Boolean(loading)}>{loading === 'markdown' ? <><RefreshCw size={15} className="spin" />Generating…</> : <><Download size={15} />Generate report</>}</button></div><div className="panel report-card"><div className="report-icon purple"><Code2 size={20} /></div><h2>SARIF export</h2><p>Machine-readable results for GitHub code scanning, CI gates, and downstream automation.</p><div className="report-meta"><span><ShieldCheck size={14} />OASIS SARIF 2.1.0</span><span><Download size={14} />JSON</span></div><button className="button button-primary" onClick={() => void createReport('sarif')} disabled={Boolean(loading)}>{loading === 'sarif' ? <><RefreshCw size={15} className="spin" />Preparing…</> : <><Download size={15} />Export SARIF</>}</button></div></div>{message && <div className="toast"><CheckCircle2 size={17} />{message}</div>}<div className="panel report-history"><div className="panel-heading"><div><h2>Recent reports</h2><p>Generate a fresh artifact above to download current data.</p></div></div></div></div>;
}

function SettingsPage({ onNavigate }: { onNavigate: (page: Page) => void }) {
  const [density, setDensity] = useState(() => localStorage.getItem('antifine-density') ?? 'dense');
  const saveDensity = (value: string) => {
    setDensity(value);
    localStorage.setItem('antifine-density', value);
  };
  return <div className="content-stack"><PageHeader eyebrow="Workspace configuration" title="Settings" description="Local runtime settings and operator preferences." /><section className="panel settings-panel"><div className="panel-heading"><div><h2>Local services</h2><p>AntiFine does not change backend or Ollama configuration from the browser.</p></div></div><div className="settings-row"><div><strong>FastAPI engine</strong><span>127.0.0.1:8000 · deterministic scanner and remediation</span></div><span className="status-badge fixed"><span />Local</span></div><div className="settings-row"><div><strong>Ollama provider</strong><span>Configured through OLLAMA_* environment variables</span></div><button className="button button-secondary" onClick={() => onNavigate('ai')}>Open Ask AntiFine</button></div></section><section className="panel settings-panel"><div className="panel-heading"><div><h2>Interface</h2><p>Preferences are stored only in this browser.</p></div></div><label className="field-label" htmlFor="density">Table density</label><select id="density" value={density} onChange={(event) => saveDensity(event.target.value)}><option value="dense">Dense</option><option value="comfortable">Comfortable</option></select></section></div>;
}

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [remediationFinding, setRemediationFinding] = useState<Finding | null>(null);
  const [explanationCache, setExplanationCache] = useState<Record<string, FindingExplanation>>({});
  const [assistantContext, setAssistantContext] = useState<AskContext>();
  const [assistantQuestion, setAssistantQuestion] = useState('');
  const [target, setTarget] = useState('infra/production.tf');
  const selectFinding = (finding: Finding) => setSelectedFinding(finding);
  const askAboutFinding = (finding: Finding) => {
    setAssistantContext({
      finding_id: finding.id,
      rule_id: undefined,
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
  const completeScan = (nextFindings: Finding[]) => { setFindings(nextFindings); setPage('findings'); };
  const markApplied = () => { if (remediationFinding) setFindings((current) => current.map((item) => item.id === remediationFinding.id ? { ...item, status: 'Fixed' } : item)); };
  return <AppShell page={page} setPage={(nextPage) => { if (nextPage !== 'ai') { setAssistantContext(undefined); setAssistantQuestion(''); } setPage(nextPage); }}><AnimatePresence mode="wait"><motion.div key={page} className="page-transition" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: 0.16 }}>{page === 'overview' && <Overview findings={findings} onNavigate={setPage} onSelect={selectFinding} />}{page === 'scan' && <ScanWorkspace onComplete={completeScan} onViewFindings={() => setPage('findings')} onOpenFinding={selectFinding} target={target} setTarget={setTarget} />}{page === 'findings' && <FindingsPage findings={findings} onSelect={selectFinding} />}{page === 'compliance' && <CompliancePage findings={findings} />}{page === 'secrets' && <SecretsPage />}{page === 'history' && <HistoryPage />}{page === 'reports' && <ReportsPage />}{page === 'ai' && <AskAntiFinePage context={assistantContext} initialQuestion={assistantQuestion} onClearContext={() => { setAssistantContext(undefined); setAssistantQuestion(''); }} onNewChat={() => { setAssistantContext(undefined); setAssistantQuestion(''); }} />}{page === 'settings' && <SettingsPage onNavigate={setPage} />}</motion.div></AnimatePresence><AnimatePresence>{selectedFinding && !remediationFinding && <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} onRemediate={() => setRemediationFinding(selectedFinding)} onAsk={() => askAboutFinding(selectedFinding)} explanationCache={explanationCache} onExplanation={(id, result) => setExplanationCache((current) => ({ ...current, [id]: result }))} />}{remediationFinding && <RemediationModal finding={remediationFinding} onClose={() => setRemediationFinding(null)} onApplied={markApplied} />}</AnimatePresence></AppShell>;
}
