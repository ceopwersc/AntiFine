import {
CheckCircle2,
Clock3,
Code2,
Download,
FileText,
GitBranch,
KeyRound,
RefreshCw,
ShieldAlert,
ShieldCheck,
WifiOff
} from 'lucide-react';
import { useEffect,useState } from 'react';
import { fetchScanHistory,fetchSecretFindings,generateReport } from '../api';
import type { Page } from '../types';
import { PageHeader } from './WorkstationUI';
export function SecretsPage() {
  const [secrets, setSecrets] = useState<Awaited<ReturnType<typeof fetchSecretFindings>>['findings']>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    void fetchSecretFindings().then((result) => setSecrets(result.findings)).catch(() => setError('Secret findings unavailable. Connect the local API and run a scan.'));
  }, []);
  return <div className="content-stack"><PageHeader eyebrow="Posture management" title="Secrets" description="Persisted secret findings with values intentionally withheld." /><div className="secret-banner"><div className="secret-banner-icon"><ShieldAlert size={19} /></div><div><strong>{secrets.length} secret finding{secrets.length === 1 ? '' : 's'} need attention</strong><span>Rotate exposed credentials, then verify the deterministic finding is gone.</span></div></div>{error ? <div className="panel empty-state"><WifiOff size={22} /><strong>{error}</strong></div> : secrets.length === 0 ? <div className="panel empty-state"><ShieldCheck size={22} /><strong>No persisted secret findings</strong><span>Run a deterministic scan to check local infrastructure.</span></div> : <div className="panel table-panel"><div className="table-meta"><span><strong>Open secrets</strong></span><span>Values withheld</span></div><div className="table-scroll"><table className="findings-table secrets-table"><thead><tr><th>Rule</th><th>Location</th><th>Severity</th><th>Detected</th><th>Status</th></tr></thead><tbody>{secrets.map((secret) => <tr key={`${secret.filename}-${secret.rule_name}`}><td><div className="finding-cell"><div className="finding-icon critical"><KeyRound size={15} /></div><div><strong>{secret.rule_name}</strong><span>Safe metadata only</span></div></div></td><td><code>{secret.filename}</code></td><td><span className="severity-badge critical"><span className="severity-dot" />{secret.severity}</span></td><td>{secret.detected}</td><td><span className={`status-badge ${secret.status.toLowerCase()}`}><span />{secret.status}</span></td></tr>)}</tbody></table></div></div>}<div className="secret-trust"><ShieldCheck size={17} /><div><strong>Privacy by design</strong><span>AntiFine never returns secret values. Only rule, location, severity, and lifecycle metadata are shown.</span></div></div></div>;
}

export function HistoryPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [scanTypeFilter, setScanTypeFilter] = useState('All scan types');
  const [exporting, setExporting] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchScanHistory().then((res) => setScans(res.scans)).catch(() => setMessage('Could not load history.'));
  }, []);
  const exportHistory = async () => {
    setExporting(true); setMessage('');
    try { setMessage((await generateReport('markdown')).message); } catch { setMessage('History export failed. Check the local API and try again.'); } finally { setExporting(false); }
  };
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Scan history" description="Recorded scan runs, including clean scans and partial coverage." action={<button className="button button-secondary" onClick={() => void exportHistory()} disabled={exporting}>{exporting ? <><RefreshCw size={15} className="spin" />Exporting…</> : <><Download size={15} />Export history</>}</button>} />{message && <div className="toast" role="status"><CheckCircle2 size={17} />{message}</div>}<div className="panel table-panel"><div className="table-meta"><span><strong>Recent scans</strong></span><div className="filter-group"><select aria-label="Filter scan type" value={scanTypeFilter} onChange={event => setScanTypeFilter(event.target.value)}><option>All scan types</option><option>IaC Config Audit</option><option>SSRF Web Audit</option></select></div></div><div className="table-scroll"><table className="findings-table history-table"><thead><tr><th>Target</th><th>Scan type</th><th>Findings</th><th>Status</th><th>Run time</th></tr></thead><tbody>{scans.filter(scan => scanTypeFilter === 'All scan types' || scan.type === scanTypeFilter).map((scan) => <tr key={scan.id}><td><div className="finding-cell"><div className="finding-icon blue"><GitBranch size={15} /></div><div><strong>{scan.target}</strong><span>{scan.id} · {scan.duration}</span></div></div></td><td><span className="muted">{scan.type}</span></td><td><span className={scan.findings ? 'finding-count' : 'finding-count clean'}>{scan.findings || 'Clean'}</span></td><td><span className="status-badge fixed"><span />{scan.status}</span></td><td>{scan.time}</td></tr>)}</tbody></table></div></div></div>;
}

export function ReportsPage() {
  const [loading, setLoading] = useState('');
  const [message, setMessage] = useState('');
  const createReport = async (format: string) => { setLoading(format); setMessage(''); try { const result = await generateReport(format); setMessage(result.message ?? 'Report generated successfully.'); if (result.downloadUrl) { const link = document.createElement('a'); link.href = result.downloadUrl; link.download = result.downloadName; link.click(); } } catch { setMessage('Report generation failed. Reconnect the local API and retry.'); } finally { setLoading(''); } };
  return <div className="content-stack"><PageHeader eyebrow="Activity" title="Reports" description="Generate audit-ready evidence for engineering, security, and compliance teams." /><div className="report-grid"><div className="panel report-card"><div className="report-icon blue"><FileText size={20} /></div><h2>Executive summary</h2><p>A Markdown evidence report with recorded findings, scan coverage, and source locations.</p><div className="report-meta"><span><Clock3 size={14} />Generated from persisted evidence</span><span><FileText size={14} />Markdown</span></div><button className="button button-secondary" onClick={() => void createReport('markdown')} disabled={Boolean(loading)}>{loading === 'markdown' ? <><RefreshCw size={15} className="spin" />Generating…</> : <><Download size={15} />Generate report</>}</button></div><div className="panel report-card"><div className="report-icon purple"><Code2 size={20} /></div><h2>SARIF export</h2><p>Machine-readable results for GitHub code scanning, CI gates, and downstream automation.</p><div className="report-meta"><span><ShieldCheck size={14} />OASIS SARIF 2.1.0</span><span><Download size={14} />JSON</span></div><button className="button button-primary" onClick={() => void createReport('sarif')} disabled={Boolean(loading)}>{loading === 'sarif' ? <><RefreshCw size={15} className="spin" />Preparing…</> : <><Download size={15} />Export SARIF</>}</button></div></div>{message && <div className="toast"><CheckCircle2 size={17} />{message}</div>}<div className="panel report-history"><div className="panel-heading"><div><h2>Recent reports</h2><p>Generate a fresh artifact above to download current data.</p></div></div></div></div>;
}

export function SettingsPage({ onNavigate }: { onNavigate: (page: Page) => void }) {
  const [density, setDensity] = useState(() => localStorage.getItem('antifine-density') ?? 'dense');
  const saveDensity = (value: string) => {
    setDensity(value);
    localStorage.setItem('antifine-density', value);
  };
  return <div className="content-stack"><PageHeader eyebrow="Workspace configuration" title="Settings" description="Local runtime settings and operator preferences." /><section className="panel settings-panel"><div className="panel-heading"><div><h2>Local services</h2><p>AntiFine does not change backend or Ollama configuration from the browser.</p></div></div><div className="settings-row"><div><strong>FastAPI engine</strong><span>127.0.0.1:8000 · deterministic scanner and remediation</span></div><span className="status-badge fixed"><span />Local</span></div><div className="settings-row"><div><strong>Ollama provider</strong><span>Configured through OLLAMA_* environment variables</span></div><button className="button button-secondary" onClick={() => onNavigate('ai')}>Open Ask AntiFine</button></div></section><section className="panel settings-panel"><div className="panel-heading"><div><h2>Interface</h2><p>Preferences are stored only in this browser.</p></div></div><label className="field-label" htmlFor="density">Table density</label><select id="density" value={density} onChange={(event) => saveDensity(event.target.value)}><option value="dense">Dense</option><option value="comfortable">Comfortable</option></select></section></div>;
}