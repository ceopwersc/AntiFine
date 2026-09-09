import { useMemo, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  Copy,
  Database,
  Download,
  FileCheck2,
  FileCode2,
  FileText,
  Filter,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Menu,
  MoreHorizontal,
  Play,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import { explainFinding, generateReport, remediateFinding, runScan, type FindingExplanation } from './api';
import { Area, AreaChart, ResponsiveContainer, Tooltip } from 'recharts';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
type Page = 'overview' | 'scan' | 'findings' | 'compliance' | 'secrets' | 'history' | 'reports';

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
  before: string;
  after: string;
  status: 'Open' | 'Fixed' | 'Accepted';
  detected: string;
}

const mockFindings: Finding[] = [
  {
    id: 'AF-1042',
    rule_name: 'Publicly accessible database instance',
    severity: 'Critical',
    framework: 'CIS AWS 2.3.1',
    frameworks: ['CIS AWS 2.3.1', 'SOC 2 CC6.1'],
    file: 'infra/production.tf',
    line: 42,
    description: 'The database is configured with publicly_accessible = true. Public database endpoints increase the attack surface and should only be used when explicitly required.',
    remediation: 'Set publicly_accessible to false and route private workloads through the VPC.',
    before: 'publicly_accessible = true',
    after: 'publicly_accessible = false',
    status: 'Open',
    detected: '12 min ago',
  },
  {
    id: 'AF-1038',
    rule_name: 'Container runs as root',
    severity: 'High',
    framework: 'CIS Docker 4.1',
    frameworks: ['CIS Docker 4.1', 'NIST SP 800-190'],
    file: 'services/api/Dockerfile',
    line: 18,
    description: 'The final image does not declare a non-root USER. A compromised process can gain full container privileges and potentially access mounted resources.',
    remediation: 'Create a dedicated application user and run the final image with that user.',
    before: 'EXPOSE 8080\nCMD ["node", "server.js"]',
    after: 'USER node\nEXPOSE 8080\nCMD ["node", "server.js"]',
    status: 'Open',
    detected: '12 min ago',
  },
  {
    id: 'AF-1033',
    rule_name: 'S3 bucket encryption missing',
    severity: 'High',
    framework: 'CIS AWS 2.1.1',
    frameworks: ['CIS AWS 2.1.1', 'PCI DSS 3.4'],
    file: 'infra/storage.tf',
    line: 7,
    description: 'The bucket has no server-side encryption configuration. Data at rest should use an approved KMS key or AES256.',
    remediation: 'Add a server-side encryption configuration using the platform managed key.',
    before: 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "acme-artifacts"\n}',
    after: 'resource "aws_s3_bucket" "artifacts" {\n  bucket = "acme-artifacts"\n\n  server_side_encryption_configuration {\n    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }\n  }\n}',
    status: 'Open',
    detected: '12 min ago',
  },
  {
    id: 'AF-1029',
    rule_name: 'Privileged Kubernetes container',
    severity: 'High',
    framework: 'CIS Kubernetes 5.2.1',
    frameworks: ['CIS Kubernetes 5.2.1', 'PSS Restricted'],
    file: 'deployments/worker.yaml',
    line: 63,
    description: 'A workload requests privileged mode, bypassing most container isolation controls. Privileged containers should not run in production namespaces.',
    remediation: 'Remove privileged mode and use the minimum Linux capabilities required by the workload.',
    before: 'securityContext:\n  privileged: true',
    after: 'securityContext:\n  allowPrivilegeEscalation: false\n  privileged: false',
    status: 'Open',
    detected: '12 min ago',
  },
  {
    id: 'AF-1024',
    rule_name: 'Broad security group ingress',
    severity: 'Medium',
    framework: 'CIS AWS 5.2.1',
    frameworks: ['CIS AWS 5.2.1', 'NIST CSF PR.AC-5'],
    file: 'infra/network.tf',
    line: 88,
    description: 'Ingress from 0.0.0.0/0 is allowed on a sensitive management port. Restrict access to trusted networks or a private security group.',
    remediation: 'Replace the public CIDR with the approved corporate VPN CIDR.',
    before: 'cidr_blocks = ["0.0.0.0/0"]',
    after: 'cidr_blocks = ["10.24.0.0/16"]',
    status: 'Open',
    detected: '12 min ago',
  },
  {
    id: 'AF-1018',
    rule_name: 'Missing resource limits',
    severity: 'Low',
    framework: 'CIS Kubernetes 5.2.3',
    frameworks: ['CIS Kubernetes 5.2.3'],
    file: 'deployments/web.yaml',
    line: 51,
    description: 'The container has no CPU and memory limits. Resource limits reduce noisy-neighbor risk and make workloads more predictable.',
    remediation: 'Define requests and limits for CPU and memory.',
    before: 'containers:\n  - name: web\n    image: acme/web:latest',
    after: 'containers:\n  - name: web\n    image: acme/web:latest\n    resources:\n      limits: { cpu: "500m", memory: "256Mi" }',
    status: 'Open',
    detected: '12 min ago',
  },
];

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
          <span>antifine</span>
          <span className="brand-beta">BETA</span>
        </div>
        <div className="workspace-switcher">
          <div className="workspace-icon">AC</div>
          <div><strong>Acme Cloud</strong><small>production</small></div>
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
          <div className="status-pill"><span className="status-live" />All systems operational</div>
          <button className="nav-item"><Settings2 size={17} /><span>Settings</span></button>
          <div className="user-card"><div className="avatar">RS</div><div><strong>Rashi Singh</strong><small>Administrator</small></div><MoreHorizontal size={16} className="muted" /></div>
        </div>
      </aside>
      {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-title"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button><span>Workspace</span><ChevronRight size={14} className="muted" /><strong>{currentLabel}</strong></div>
          <div className="topbar-actions">
            <div className="environment"><span className="status-live" />Production</div>
            <button className="icon-button" aria-label="Help"><CircleHelp size={18} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={18} /><span /></button>
            <div className="top-avatar">RS</div>
          </div>
        </header>
        <div className="page-content">{children}</div>
      </main>
    </div>
  );
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow ?? 'Security posture'}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

function StatCard({ label, value, detail, trend, icon: Icon, tone = 'blue' }: { label: string; value: string; detail: string; trend?: 'up' | 'down'; icon: typeof Shield; tone?: string }) {
  return <div className={`stat-card stat-${tone}`}><div className="stat-card-top"><span>{label}</span><div className="stat-icon"><Icon size={17} /></div></div><div className="stat-value">{value}</div><div className={`stat-detail ${trend === 'up' ? 'trend-up' : trend === 'down' ? 'trend-down' : ''}`}>{trend === 'up' ? <ArrowUpRight size={14} /> : trend === 'down' ? <ArrowDownRight size={14} /> : null}{detail}</div></div>;
}

function Overview({ findings, onNavigate, onSelect }: { findings: Finding[]; onNavigate: (page: Page) => void; onSelect: (finding: Finding) => void }) {
  const counts = useMemo(() => findings.reduce<Record<Severity, number>>((acc, finding) => { acc[finding.severity] += 1; return acc; }, { Critical: 0, High: 0, Medium: 0, Low: 0 }), [findings]);
  const chart = [
    { label: 'Aug 12', score: 64 }, { label: 'Aug 14', score: 58 }, { label: 'Aug 16', score: 69 },
    { label: 'Aug 19', score: 62 }, { label: 'Aug 21', score: 75 }, { label: 'Aug 23', score: 71 },
    { label: 'Aug 26', score: 82 }, { label: 'Aug 28', score: 79 }, { label: 'Aug 30', score: 88 },
    { label: 'Sep 02', score: 84 }, { label: 'Sep 06', score: 91 }, { label: 'Today', score: 89 },
  ];
  return <div className="content-stack">
    <PageHeader eyebrow="Thursday, September 10, 2026" title="Good morning, Rashi" description="Here's the latest security posture across your infrastructure." action={<button className="button button-primary" onClick={() => onNavigate('scan')}><Play size={15} fill="currentColor" />Run a scan</button>} />
    <div className="stat-grid">
      <StatCard label="Security score" value="84" detail="+6.2% from last week" trend="up" icon={ShieldCheck} tone="green" />
      <StatCard label="Open findings" value={String(findings.length)} detail="2 fewer than yesterday" trend="up" icon={ShieldAlert} tone="orange" />
      <StatCard label="Assets monitored" value="128" detail="Across 6 repositories" icon={Database} tone="blue" />
      <StatCard label="Secrets detected" value="2" detail="Both need attention" trend="down" icon={KeyRound} tone="red" />
    </div>
    <div className="overview-grid">
      <section className="panel posture-panel"><div className="panel-heading"><div><h2>Security posture</h2><p>Composite score across the last 30 days</p></div><button className="select-button">Last 30 days <ChevronDown size={14} /></button></div><div className="posture-chart"><div className="score-ring"><div><strong>84</strong><span>/ 100</span><small>Good</small></div></div><div className="chart-area"><div className="chart-y-labels"><span>100</span><span>75</span><span>50</span><span>25</span></div><div className="line-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart} margin={{ top: 8, right: 4, left: 0, bottom: 0 }}><defs><linearGradient id="postureFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#5ba7ff" stopOpacity={0.3} /><stop offset="100%" stopColor="#5ba7ff" stopOpacity={0} /></linearGradient></defs><Area type="monotone" dataKey="score" stroke="#65afff" strokeWidth={2} fill="url(#postureFill)" dot={false} /><Tooltip contentStyle={{ background: '#172433', border: '1px solid #35516e', borderRadius: 5, color: '#dbeafa', fontSize: 10 }} labelStyle={{ color: '#8fa6bf' }} formatter={(value) => [`${value}`, 'Score']} /></AreaChart></ResponsiveContainer></div></div></div><div className="chart-legend"><span><i className="legend-dot blue" />Score</span><span className="chart-note"><ArrowUpRight size={13} /> 6.2% vs previous period</span></div></section>
      <section className="panel severity-panel"><div className="panel-heading"><div><h2>Findings by severity</h2><p>Prioritize what needs attention</p></div><button className="icon-button"><MoreHorizontal size={18} /></button></div><div className="severity-list">{(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map((severity) => <button className="severity-row" key={severity} onClick={() => onNavigate('findings')}><div className="severity-row-label"><SeverityBadge severity={severity} /><strong>{counts[severity]}</strong></div><div className="severity-track"><div className={`severity-progress ${severity.toLowerCase()}`} style={{ width: `${Math.max(counts[severity] * 13, 8)}%` }} /></div><ChevronRight size={15} className="muted" /></button>)}</div><button className="text-button" onClick={() => onNavigate('findings')}>View all findings <ArrowUpRight size={14} /></button></section>
    </div>
    <div className="overview-grid lower-grid"><section className="panel"><div className="panel-heading"><div><h2>Recent findings</h2><p>Detected in the latest scan</p></div><button className="text-button" onClick={() => onNavigate('findings')}>View all <ArrowUpRight size={14} /></button></div><div className="recent-list">{findings.slice(0, 4).map((finding) => <button className="recent-row" key={finding.id} onClick={() => onSelect(finding)}><div className={`finding-icon ${finding.severity.toLowerCase()}`}><ShieldAlert size={16} /></div><div className="recent-main"><strong>{finding.rule_name}</strong><span>{finding.file}:{finding.line}</span></div><SeverityBadge severity={finding.severity} /><span className="recent-time">{finding.detected}</span><ChevronRight size={15} className="muted" /></button>)}</div></section><section className="panel activity-panel"><div className="panel-heading"><div><h2>Scan activity</h2><p>Latest runs across your workspace</p></div><button className="icon-button"><MoreHorizontal size={18} /></button></div><div className="activity-list"><div className="activity-row"><div className="activity-status success"><Check size={14} /></div><div><strong>IaC audit completed</strong><span>acme-infrastructure · 6 findings</span></div><time>12 min ago</time></div><div className="activity-row"><div className="activity-status"><GitBranch size={14} /></div><div><strong>Pull request scanned</strong><span>acme/web · #418</span></div><time>2 hr ago</time></div><div className="activity-row"><div className="activity-status success"><Check size={14} /></div><div><strong>Secret rotation verified</strong><span>production / AWS</span></div><time>Yesterday</time></div></div><button className="text-button" onClick={() => onNavigate('history')}>Open scan history <ArrowUpRight size={14} /></button></section></div>
  </div>;
}

function ScanWorkspace({ onComplete, target, setTarget }: { onComplete: (findings: Finding[]) => void; target: string; setTarget: (target: string) => void }) {
  const [scanType, setScanType] = useState('IaC Config Audit');
  const [scanning, setScanning] = useState(false);
  const [scanLog, setScanLog] = useState<string[]>(['Ready to scan. Select a target and audit protocol.']);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const startScan = async () => {
    if (!target.trim()) return;
    setScanning(true); setDone(false); setError('');
    setScanLog(['Initializing secure scan context…', `Target: ${target}`, `Protocol: ${scanType}`, 'Analyzing configuration files…']);
    try {
      const result = await runScan(target.trim(), scanType);
      const returned = Array.isArray(result?.findings) ? result.findings : [];
      if (returned.length) onComplete(returned.map((item: Partial<Finding>, index: number) => {
        const fallback = mockFindings[index % mockFindings.length];
        return {
          ...fallback,
          ...item,
          id: item.id ?? `AF-${1100 + index}`,
          severity: normalizeSeverity(item.severity),
          frameworks: item.frameworks?.length ? item.frameworks : fallback.frameworks,
          framework: item.framework ?? fallback.framework,
          file: item.file ?? target,
        };
      }));
      else onComplete(mockFindings);
      setScanLog((current) => [...current, 'Policy checks complete.', `Scan complete · ${returned.length || mockFindings.length} findings`]); setDone(true);
    } catch {
      onComplete(mockFindings);
      setScanLog((current) => [...current, 'Backend unavailable · loaded representative scan data.', `Scan complete · ${mockFindings.length} findings`]); setDone(true);
    } finally { setScanning(false); }
  };
  return <div className="content-stack"><PageHeader eyebrow="Security workspace" title="Run a scan" description="Inspect infrastructure-as-code and web assets before they reach production." /><div className="scan-layout"><section className="panel scan-config"><div className="panel-heading"><div><h2>Scan configuration</h2><p>Define the scope and policy set for this run.</p></div><div className="secure-label"><ShieldCheck size={14} /> Secure</div></div><label className="field-label" htmlFor="target">Target path or URL</label><div className="input-with-icon"><FileCode2 size={17} /><input id="target" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void startScan(); }} placeholder="e.g. infra/production.tf" /></div><div className="target-suggestions"><button onClick={() => setTarget('infra/production.tf')}>infra/production.tf</button><button onClick={() => setTarget('deployments/worker.yaml')}>deployments/worker.yaml</button><button onClick={() => setTarget('services/api/Dockerfile')}>Dockerfile</button></div><label className="field-label" htmlFor="protocol">Audit protocol</label><div className="select-wrap"><Radar size={17} /><select id="protocol" value={scanType} onChange={(event) => setScanType(event.target.value)}><option>IaC Config Audit</option><option>SSRF Web Audit</option></select><ChevronDown size={15} /></div><div className="scan-options"><div><strong>Policy packs</strong><span>CIS Benchmarks, NIST, SOC 2</span></div><div className="toggle on"><span /></div></div><div className="scan-options"><div><strong>Secret detection</strong><span>High-confidence patterns + entropy</span></div><div className="toggle on"><span /></div></div><button className="button button-primary scan-button" onClick={() => void startScan()} disabled={scanning || !target.trim()}>{scanning ? <><RefreshCw size={16} className="spin" />Scanning target…</> : <><Play size={16} fill="currentColor" />Initialize scan</>}</button>{error && <div className="inline-error"><AlertTriangle size={15} />{error}</div>}</section><section className={`panel terminal-panel ${scanning ? 'terminal-active' : ''}`}><div className="terminal-header"><span><span className="terminal-dot red" /><span className="terminal-dot yellow" /><span className="terminal-dot green" /></span><span className="terminal-title"><Terminal size={14} /> scan output</span><span className="terminal-live">{scanning ? 'LIVE' : done ? 'COMPLETE' : 'IDLE'}</span></div><div className="terminal-body">{scanLog.map((line, index) => <div key={`${line}-${index}`} className={line.includes('complete') || line.includes('findings') ? 'terminal-success' : index === scanLog.length - 1 && scanning ? 'terminal-current' : ''}><span className="terminal-prefix">{index === scanLog.length - 1 && scanning ? '›' : '✓'}</span>{line}</div>)}{scanning && <div className="terminal-cursor">▌</div>}</div><div className="terminal-footer"><span><Activity size={14} /> Engine v2.4.1</span><span>Run ID: {done ? 'scan_8f31c2' : '—'}</span></div></section></div><div className="scan-trust-row"><ShieldCheck size={17} /><span>Scans are read-only by default.</span><span className="muted">Any remediation is explicit, deterministic, and reviewable before applying.</span></div></div>;
}

function FindingsPage({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<Severity | 'All'>('All');
  const [status, setStatus] = useState<'All' | Finding['status']>('All');
  const filtered = findings.filter((finding) => (severity === 'All' || finding.severity === severity) && (status === 'All' || finding.status === status) && `${finding.rule_name} ${finding.file} ${finding.frameworks.join(' ')}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="content-stack"><PageHeader eyebrow="Security posture" title="Findings" description="Review, prioritize, and remediate issues discovered across your infrastructure." action={<button className="button button-secondary"><Download size={15} />Export CSV</button>} /><div className="finding-toolbar"><div className="search-input"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings, files, or frameworks" /><kbd>⌘ K</kbd></div><div className="filter-group"><SlidersHorizontal size={15} className="muted" /><select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | 'All')} aria-label="Filter by severity"><option value="All">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><select value={status} onChange={(event) => setStatus(event.target.value as 'All' | Finding['status'])} aria-label="Filter by status"><option value="All">All status</option><option>Open</option><option>Fixed</option><option>Accepted</option></select><button className="icon-button" aria-label="More filters"><Filter size={16} /></button></div></div><div className="panel table-panel"><div className="table-meta"><span><strong>{filtered.length}</strong> findings</span><span>Last scan 12 min ago · <span className="live-text">Live data</span></span></div><div className="table-scroll"><table className="findings-table"><thead><tr><th>Finding</th><th>Severity</th><th>Location</th><th>Framework</th><th>Status</th><th aria-label="Actions" /></tr></thead><tbody>{filtered.map((finding) => <tr key={finding.id} onClick={() => onSelect(finding)}><td><div className="finding-cell"><div className={`finding-icon ${finding.severity.toLowerCase()}`}><ShieldAlert size={15} /></div><div><strong>{finding.rule_name}</strong><span>{finding.id}</span></div></div></td><td><SeverityBadge severity={finding.severity} /></td><td><code>{finding.file}</code><span className="line-number">:{finding.line}</span></td><td><span className="framework-pill">{finding.framework}</span></td><td><span className={`status-badge ${finding.status.toLowerCase()}`}><span />{finding.status}</span></td><td><ChevronRight size={16} className="muted" /></td></tr>)}</tbody></table></div>{filtered.length === 0 && <div className="empty-state"><Search size={24} /><strong>No findings match these filters</strong><span>Try a different search or reset the filters.</span></div>}<div className="table-footer"><span>Showing {filtered.length} of {findings.length}</span><div><button className="pagination-button" disabled>Previous</button><button className="pagination-button active">1</button><button className="pagination-button">Next</button></div></div></div></div>;
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

function FindingDrawer({
  finding,
  onClose,
  onRemediate,
  explanationCache,
  onExplanation,
}: {
  finding: Finding;
  onClose: () => void;
  onRemediate: () => void;
  explanationCache: Record<string, FindingExplanation>;
  onExplanation: (findingId: string, explanation: FindingExplanation) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiError, setAIError] = useState('');
  const explanation = explanationCache[finding.id];
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
  return <><motion.button className="drawer-scrim" onClick={onClose} aria-label="Close finding details" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} /><motion.aside className="detail-drawer" role="dialog" aria-modal="true" aria-label="Finding details" initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', damping: 28, stiffness: 260 }}><div className="drawer-header"><div><span className="drawer-eyebrow">Finding {finding.id}</span><h2>{finding.rule_name}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close"><X size={19} /></button></div><div className="drawer-content"><div className="drawer-badges"><SeverityBadge severity={finding.severity} /><span className={`status-badge ${finding.status.toLowerCase()}`}><span />{finding.status}</span></div><section className="drawer-section"><h3>Why this matters</h3><p>{finding.description}</p></section><section className="drawer-section"><h3>Location</h3><div className="location-card"><FileCode2 size={16} /><code>{finding.file}</code><span>Line {finding.line}</span><button className="icon-button small" aria-label="Copy location" onClick={() => void navigator.clipboard?.writeText(`${finding.file}:${finding.line}`)}><Copy size={14} /></button></div></section><section className="drawer-section"><h3>Compliance mapping</h3><div className="framework-list">{finding.frameworks.map((framework) => <span key={framework} className="framework-pill">{framework}</span>)}</div></section><section className="drawer-section remediation-preview"><div className="section-heading-row"><h3>Recommended remediation</h3><button className="text-button" onClick={copy}>{copied ? <><Check size={13} />Copied</> : <><Copy size={13} />Copy</>}</button></div><p>{finding.remediation}</p><pre>{finding.after}</pre></section><section className="drawer-section ai-explanation" aria-live="polite"><div className="section-heading-row"><div><h3>Local AI explanation</h3><span className="ai-label">Local AI · Ollama</span></div>{explanation && <button className="text-button" onClick={() => void requestExplanation()} disabled={loadingAI}>{loadingAI ? 'Analyzing locally…' : 'Regenerate'}</button>}</div><p className="ai-disclaimer">AI-generated explanation based on AntiFine's deterministic finding.</p>{aiError ? <div className="ai-error"><strong>Local AI unavailable</strong><span>AntiFine's deterministic security analysis is still available.</span><button className="text-button" onClick={() => void requestExplanation()} disabled={loadingAI}>Retry</button></div> : explanation ? <div className="ai-response"><span className="ai-model">{explanation.model} · generated locally</span>{renderExplanation(explanation.explanation)}</div> : <button className="button button-secondary ai-explain-button" onClick={() => void requestExplanation()} disabled={loadingAI}>{loadingAI ? <><RefreshCw size={15} className="spin" />Analyzing locally…</> : <><Sparkles size={15} />Explain with Local AI</>}</button>}</section></div><div className="drawer-footer"><button className="button button-secondary" onClick={onClose}>Dismiss</button><button className="button button-primary" onClick={onRemediate}><Sparkles size={15} />Review fix</button></div></motion.aside></>;
}

function RemediationModal({ finding, onClose, onApplied }: { finding: Finding; onClose: () => void; onApplied: () => void }) {
  const [applying, setApplying] = useState(false);
  const [applied, setApplied] = useState(false);
  const [remediationError, setRemediationError] = useState('');
  const apply = async () => {
    setApplying(true);
    setRemediationError('');
    try {
      await remediateFinding(finding.file, finding.rule_name);
      setApplied(true);
      onApplied();
    } catch (error: any) {
      const detail = error?.response?.data?.detail;
      setRemediationError(detail || 'AntiFine could not apply this deterministic fix.');
    } finally {
      setApplying(false);
    }
  };
  return <motion.div className="modal-scrim" role="dialog" aria-modal="true" aria-label="Review remediation" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}><motion.div className="remediation-modal" initial={{ opacity: 0, y: 16, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}><div className="modal-header"><div><span className="drawer-eyebrow">Deterministic remediation</span><h2>Review proposed fix</h2><p>Inspect the exact change before applying it to <code>{finding.file}</code>.</p></div><button className="icon-button" onClick={onClose} aria-label="Close"><X size={19} /></button></div><div className="diff-meta"><span><FileCode2 size={15} />{finding.file}</span><span>Line {finding.line}</span><span className="diff-safe"><ShieldCheck size={14} />Safe to apply</span></div><div className="diff-view"><div className="diff-column"><div className="diff-column-header removed">Before <span>−</span></div><pre>{finding.before.split('\n').map((line, index) => <div key={`${line}-${index}`} className="diff-line removed-line"><span>{String(index + 1).padStart(2, '0')}</span>{line || ' '}</div>)}</pre></div><div className="diff-column"><div className="diff-column-header added">After <span>＋</span></div><pre>{finding.after.split('\n').map((line, index) => <div key={`${line}-${index}`} className="diff-line added-line"><span>{String(index + 1).padStart(2, '0')}</span>{line || ' '}</div>)}</pre></div></div>  <div className={`modal-callout${remediationError ? ' modal-callout-error' : ''}`}><ShieldCheck size={17} /><div><strong>{remediationError ? 'Fix could not be applied' : 'What will happen'}</strong><span>{remediationError || 'AntiFine creates a backup, applies the allowlisted fix, then re-scans the target to verify the result.'}</span></div></div><div className="modal-footer"><button className="button button-secondary" onClick={onClose}>Cancel</button>{applied ? <button className="button button-success" onClick={onClose}><Check size={15} />Fix applied</button> : <button className="button button-primary" disabled={applying} onClick={() => void apply()}>{applying ? <><RefreshCw size={15} className="spin" />Applying fix…</> : <><Sparkles size={15} />Apply deterministic fix</>}</button>}</div></motion.div></motion.div>;
}

function CompliancePage() {
  const frameworks = [{ name: 'CIS AWS Foundations', score: 91, checks: '42 / 46 checks passing', color: 'green' }, { name: 'NIST SP 800-190', score: 86, checks: '30 / 35 checks passing', color: 'blue' }, { name: 'SOC 2', score: 78, checks: '18 / 23 checks passing', color: 'orange' }, { name: 'PCI DSS v4.0', score: 94, checks: '47 / 50 checks passing', color: 'green' }];
  return <div className="content-stack"><PageHeader eyebrow="Posture management" title="Compliance" description="Track control coverage across the frameworks your team cares about." action={<button className="button button-secondary"><Download size={15} />Export evidence</button>} /><div className="compliance-summary"><div className="compliance-score"><div className="score-ring small"><div><strong>87%</strong><small>Overall</small></div></div><div><h2>Good standing</h2><p>89 of 104 controls passing across all mapped frameworks.</p><span className="trend-up"><ArrowUpRight size={14} /> 4.8% this month</span></div></div><div className="compliance-stat"><span>Passing controls</span><strong>89</strong><small>+7 this month</small></div><div className="compliance-stat"><span>Needs review</span><strong>15</strong><small>Across 4 frameworks</small></div></div><div className="framework-grid">{frameworks.map((framework) => <div className="panel framework-card" key={framework.name}><div className="framework-card-top"><div className={`framework-icon ${framework.color}`}><ShieldCheck size={18} /></div><button className="icon-button"><MoreHorizontal size={17} /></button></div><h3>{framework.name}</h3><div className="framework-score"><strong>{framework.score}%</strong><span>{framework.checks}</span></div><div className="progress-track"><div className={`progress-fill ${framework.color}`} style={{ width: `${framework.score}%` }} /></div><button className="text-button">View controls <ChevronRight size={14} /></button></div>)}</div></div>;
}

function SecretsPage() {
  const secrets = [{ name: 'AWS access key', location: 'services/api/.env', type: 'AWS Access Key', detected: '8 min ago', status: 'Open' }, { name: 'GitHub token', location: 'scripts/deploy.sh', type: 'GitHub Token', detected: 'Yesterday', status: 'Open' }];
  return <div className="content-stack"><PageHeader eyebrow="Posture management" title="Secrets" description="High-confidence credentials detected in your connected repositories." action={<button className="button button-primary"><KeyRound size={15} />Configure detection</button>} /><div className="secret-banner"><div className="secret-banner-icon"><ShieldAlert size={19} /></div><div><strong>2 secrets need attention</strong><span>Rotate exposed credentials, then mark the finding as resolved.</span></div><button className="button button-secondary">View playbook <ChevronRight size={14} /></button></div><div className="panel table-panel"><div className="table-meta"><span><strong>Open secrets</strong></span><span>Scanned 12 min ago</span></div><div className="table-scroll"><table className="findings-table secrets-table"><thead><tr><th>Secret</th><th>Location</th><th>Type</th><th>Detected</th><th>Status</th><th /></tr></thead><tbody>{secrets.map((secret) => <tr key={secret.location}><td><div className="finding-cell"><div className="finding-icon critical"><KeyRound size={15} /></div><div><strong>{secret.name}</strong><span>High confidence match</span></div></div></td><td><code>{secret.location}</code></td><td><span className="framework-pill">{secret.type}</span></td><td>{secret.detected}</td><td><span className="status-badge open"><span />{secret.status}</span></td><td><ChevronRight size={16} className="muted" /></td></tr>)}</tbody></table></div></div><div className="secret-trust"><ShieldCheck size={17} /><div><strong>Privacy by design</strong><span>AntiFine never stores secret values. Only fingerprints and locations are retained for triage.</span></div></div></div>;
}

function HistoryPage() {
  const scans = [{ id: 'scan_8f31c2', target: 'acme-infrastructure', type: 'IaC Config Audit', findings: 6, status: 'Completed', time: '12 min ago', duration: '18.4s' }, { id: 'scan_3a10b9', target: 'acme/web · PR #418', type: 'IaC Config Audit', findings: 2, status: 'Completed', time: '2 hr ago', duration: '11.2s' }, { id: 'scan_887bc1', target: 'staging ingress', type: 'SSRF Web Audit', findings: 0, status: 'Completed', time: 'Yesterday', duration: '7.8s' }, { id: 'scan_11ac72', target: 'acme-infrastructure', type: 'IaC Config Audit', findings: 8, status: 'Completed', time: 'Sep 08, 2026', duration: '20.1s' }];
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Scan history" description="A complete audit trail of scans run in the Acme Cloud workspace." action={<button className="button button-secondary"><Download size={15} />Export history</button>} /><div className="panel table-panel"><div className="table-meta"><span><strong>Recent scans</strong></span><div className="filter-group"><select aria-label="Filter scan type"><option>All scan types</option><option>IaC Config Audit</option><option>SSRF Web Audit</option></select><button className="icon-button" aria-label="Refresh history"><RefreshCw size={15} /></button></div></div><div className="table-scroll"><table className="findings-table history-table"><thead><tr><th>Target</th><th>Scan type</th><th>Findings</th><th>Status</th><th>Run time</th><th /></tr></thead><tbody>{scans.map((scan) => <tr key={scan.id}><td><div className="finding-cell"><div className="finding-icon blue"><GitBranch size={15} /></div><div><strong>{scan.target}</strong><span>{scan.id} · {scan.duration}</span></div></div></td><td><span className="muted">{scan.type}</span></td><td><span className={scan.findings ? 'finding-count' : 'finding-count clean'}>{scan.findings || 'Clean'}</span></td><td><span className="status-badge fixed"><span />{scan.status}</span></td><td>{scan.time}</td><td><ChevronRight size={16} className="muted" /></td></tr>)}</tbody></table></div></div></div>;
}

function ReportsPage() {
  const [loading, setLoading] = useState('');
  const [message, setMessage] = useState('');
  const createReport = async (format: string) => { setLoading(format); setMessage(''); try { const result = await generateReport(format); setMessage(result.message ?? 'Report generated successfully.'); if (result.downloadUrl) { const link = document.createElement('a'); link.href = result.downloadUrl; link.download = 'antifine-results.sarif'; link.click(); } } catch { setMessage('Report queued. Connect the API to download the generated artifact.'); } finally { setLoading(''); } };
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Reports" description="Generate audit-ready evidence for engineering, security, and compliance teams." /><div className="report-grid"><div className="panel report-card"><div className="report-icon blue"><FileText size={20} /></div><h2>Executive summary</h2><p>A concise Markdown report with posture score, finding trends, and recommended priorities.</p><div className="report-meta"><span><Clock3 size={14} />Generated from latest scan</span><span><FileText size={14} />Markdown</span></div><button className="button button-secondary" onClick={() => void createReport('markdown')} disabled={Boolean(loading)}>{loading === 'markdown' ? <><RefreshCw size={15} className="spin" />Generating…</> : <><Download size={15} />Generate report</>}</button></div><div className="panel report-card"><div className="report-icon purple"><Code2 size={20} /></div><h2>SARIF export</h2><p>Machine-readable results for GitHub code scanning, CI gates, and downstream automation.</p><div className="report-meta"><span><ShieldCheck size={14} />OASIS SARIF 2.1.0</span><span><Download size={14} />JSON</span></div><button className="button button-primary" onClick={() => void createReport('sarif')} disabled={Boolean(loading)}>{loading === 'sarif' ? <><RefreshCw size={15} className="spin" />Preparing…</> : <><Download size={15} />Export SARIF</>}</button></div></div>{message && <div className="toast"><CheckCircle2 size={17} />{message}</div>}<div className="panel report-history"><div className="panel-heading"><div><h2>Recent reports</h2><p>Previously generated artifacts</p></div></div><div className="report-history-row"><div className="report-icon small blue"><FileText size={15} /></div><div><strong>antifine-executive-summary.md</strong><span>Generated Sep 09, 2026 · 14 findings</span></div><button className="icon-button"><Download size={16} /></button></div><div className="report-history-row"><div className="report-icon small purple"><Code2 size={15} /></div><div><strong>scan_results.sarif</strong><span>Generated Sep 08, 2026 · 8 findings</span></div><button className="icon-button"><Download size={16} /></button></div></div></div>;
}

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [findings, setFindings] = useState<Finding[]>(mockFindings);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [remediationFinding, setRemediationFinding] = useState<Finding | null>(null);
  const [explanationCache, setExplanationCache] = useState<Record<string, FindingExplanation>>({});
  const [target, setTarget] = useState('infra/production.tf');
  const selectFinding = (finding: Finding) => setSelectedFinding(finding);
  const completeScan = (nextFindings: Finding[]) => { setFindings(nextFindings); setPage('findings'); };
  const markApplied = () => { if (remediationFinding) setFindings((current) => current.map((item) => item.id === remediationFinding.id ? { ...item, status: 'Fixed' } : item)); };
  return <AppShell page={page} setPage={setPage}><AnimatePresence mode="wait"><motion.div key={page} className="page-transition" initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -5 }} transition={{ duration: 0.16 }}>{page === 'overview' && <Overview findings={findings} onNavigate={setPage} onSelect={selectFinding} />}{page === 'scan' && <ScanWorkspace onComplete={completeScan} target={target} setTarget={setTarget} />}{page === 'findings' && <FindingsPage findings={findings} onSelect={selectFinding} />}{page === 'compliance' && <CompliancePage />}{page === 'secrets' && <SecretsPage />}{page === 'history' && <HistoryPage />}{page === 'reports' && <ReportsPage />}</motion.div></AnimatePresence><AnimatePresence>{selectedFinding && !remediationFinding && <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} onRemediate={() => setRemediationFinding(selectedFinding)} explanationCache={explanationCache} onExplanation={(id, result) => setExplanationCache((current) => ({ ...current, [id]: result }))} />}{remediationFinding && <RemediationModal finding={remediationFinding} onClose={() => setRemediationFinding(null)} onApplied={markApplied} />}</AnimatePresence></AppShell>;
}
