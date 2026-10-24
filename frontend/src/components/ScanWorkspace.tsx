import {
Activity,
AlertTriangle,
ChevronDown,
ChevronRight,
FileCode2,
FilePlus2,
Play,
Radar,
RefreshCw,
ShieldCheck,
Terminal,
Upload,
X
} from 'lucide-react';
import { useRef,useState } from 'react';
import { runScan,uploadScanWorkspace } from '../api';
import { normalizeFinding,type Finding } from '../types';
import { PageHeader,SeverityBadge } from './WorkstationUI';
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

export function ScanWorkspace({ onComplete, target, setTarget, onViewFindings, onOpenFinding }: { onComplete: (findings: Finding[]) => void; target: string; setTarget: (target: string) => void; onViewFindings: () => void; onOpenFinding: (finding: Finding) => void }) {
  const [mode, setMode] = useState<'import' | 'local'>('import');
  const [scanType, setScanType] = useState('IaC Config Audit');
  const [scanning, setScanning] = useState(false);
  const [scanLog, setScanLog] = useState<string[]>(['Ready. Select files or provide a path to begin.']);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [scanResult, setScanResult] = useState<{ findings: Finding[]; durationMs: number; target: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addFiles = (files: FileList | File[]) => {
    const fileList = Array.from(files).filter(f => queuedFileType(f.name) !== 'Unknown');
    if (fileList.length === 0) {
      setError('No supported files provided.');
      return;
    }
    setImportFiles(current => {
      const newFiles = [...current];
      fileList.forEach(f => {
        if (!newFiles.find(existing => existing.name === f.name && existing.size === f.size)) {
          newFiles.push(f);
        }
      });
      return newFiles;
    });
    setError('');
  };

  const queue: ScanQueueItem[] = importFiles.map(f => ({
    id: `${f.name}-${f.size}-${f.lastModified}`,
    name: f.name,
    size: f.size,
    type: queuedFileType(f.name),
    status: 'Ready' as const
  }));

  const validQueue = queue.filter((item) => item.status === 'Ready');
  const removeFile = (id: string) => setImportFiles((current) => current.filter((f) => `${f.name}-${f.size}-${f.lastModified}` !== id));
  const clearQueue = () => { setImportFiles([]); setScanResult(null); setDone(false); setError(''); };

  const startScan = async () => {
    if (scanning) return;
    if (mode === 'local' && !target.trim()) return;
    if (mode === 'import' && importFiles.length === 0) return;

    setScanning(true); setDone(false); setError(''); setScanResult(null);
    const startedAt = performance.now();
    setScanLog(['Initializing local scan context…', `Protocol: ${scanType}`]);

    let finalTarget = target.trim();

    try {
      if (mode === 'import') {
        setScanLog(current => [...current, `Uploading ${importFiles.length} files to temporary workspace…`]);
        const result = await uploadScanWorkspace(importFiles);
        finalTarget = result.target_path;
        setScanLog(current => [...current, `Files imported successfully to isolated workspace.`, `Target: ${finalTarget}`, 'Parsing configuration…']);
      } else {
        setScanLog(current => [...current, `Target: ${finalTarget}`, 'Parsing configuration…']);
      }

      const result = await runScan(finalTarget, scanType);
      const returned = Array.isArray(result?.findings) ? result.findings : [];
      const durationMs = Math.round(performance.now() - startedAt);
      const mappedFindings = returned.map(normalizeFinding);
      if (result.status !== 'completed') {
        setError('Scan incomplete. Review file coverage and parser errors before making security decisions.');
      }
      onComplete(mappedFindings);
      setScanResult({ findings: mappedFindings, durationMs, target: result?.target ?? finalTarget });
      setScanLog((current) => [...current, `Coverage: ${result.status}.`, 'Rules evaluated.', 'Compliance mappings resolved.', `Scan complete · ${returned.length} findings`]);
      setDone(true);
    } catch (requestError: any) {
      const detail = requestError?.response?.data?.detail;
      setError(detail || 'The scan backend could not complete this request.');
      setScanLog((current) => [...current, 'Scan failed · no findings were loaded.']);
    } finally { setScanning(false); }
  };

  return <div className="content-stack scan-workspace">
    <PageHeader eyebrow="Local security engine" title="New security scan" description="Analyze infrastructure locally before deployment." />

    <div className="scan-mode-tabs">
      <button className={`tab-button ${mode === 'import' ? 'active' : ''}`} onClick={() => setMode('import')}><Upload size={14} />Import files</button>
      <button className={`tab-button ${mode === 'local' ? 'active' : ''}`} onClick={() => setMode('local')}><Terminal size={14} />Server-local path</button>
    </div>

    <div className="scan-layout">
      <section className="panel scan-config">
        {mode === 'import' ? (
          <>
            <div className="panel-heading">
              <div><h2>Files</h2><p>Files are securely transferred to a temporary isolated workspace.</p></div>
              <div className="secure-label"><ShieldCheck size={14} /> Local</div>
            </div>
            <div className={`drop-zone ${dragActive ? 'drop-zone-active' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); setDragActive(false); addFiles(event.dataTransfer.files); }}>
              <Upload size={18} /><strong>Drop files here</strong><span>or</span>
              <button type="button" className="button button-secondary" onClick={() => fileInputRef.current?.click()}><FilePlus2 size={14} />Choose files</button>
              <small>Supported: .tf · .yaml · .yml · Dockerfile</small>
              <input ref={fileInputRef} type="file" multiple accept=".tf,.yaml,.yml,Dockerfile" hidden onChange={(event) => { if (event.target.files) addFiles(event.target.files); event.currentTarget.value = ''; }} />
            </div>
            <div className="queue-heading">
              <span>Scan queue <strong>{queue.length}</strong></span>
              {queue.length > 0 && <button type="button" className="text-button" onClick={clearQueue}>Clear all</button>}
            </div>
            <div className="scan-queue">
              {queue.length === 0 ? <div className="queue-empty">No files queued.</div> : queue.map((file) => (
                <div className={`queue-row ${file.status === 'Error' ? 'queue-error' : ''}`} key={file.id}>
                  <FileCode2 size={15} />
                  <div><strong>{file.name}</strong><span>{file.type} · {formatFileSize(file.size)}</span></div>
                  <span className={`queue-status ${file.status.toLowerCase()}`}>{file.status}</span>
                  {file.error && <span className="queue-error-text">{file.error}</span>}
                  <button type="button" className="icon-button small" aria-label={`Remove ${file.name}`} onClick={() => removeFile(file.id)}><X size={14} /></button>
                </div>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="panel-heading">
              <div><h2>Server-local path</h2><p>Scan a path that already exists on the FastAPI server.</p></div>
              <div className="secure-label"><ShieldCheck size={14} /> Local</div>
            </div>
            <label className="field-label" htmlFor="target">Absolute or project-relative path</label>
            <div className="input-with-icon">
              <FileCode2 size={17} />
              <input id="target" value={target} onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void startScan(); }} placeholder="e.g. infra/production.tf" />
            </div>
          </>
        )}

        <label className="field-label" htmlFor="protocol">Scan protocol</label>
        <div className="select-wrap">
          <Radar size={17} />
          <select id="protocol" value={scanType} onChange={(event) => setScanType(event.target.value)}>
            <option>IaC Config Audit</option>
            <option>SSRF Web Audit</option>
          </select>
          <ChevronDown size={15} />
        </div>

        <div className="scan-summary">
          {mode === 'import' ? (
            <span>Files <strong>{validQueue.length}</strong></span>
          ) : (
            <span>Target <strong>{target.trim() || '—'}</strong></span>
          )}
          <span>Technologies <strong>{mode === 'import' ? Array.from(new Set(validQueue.map((item) => item.type))).join(' · ') || '—' : 'Auto-detected'}</strong></span>
          <span>Rules <strong>Backend reported</strong></span>
        </div>

        <button className="button button-primary scan-button" onClick={() => void startScan()} disabled={scanning || (mode === 'import' ? validQueue.length === 0 : !target.trim())}>
          {scanning ? <><RefreshCw size={16} className="spin" />Scanning…</> : <><Play size={16} fill="currentColor" />Run scan</>}
        </button>
        {error && <div className="inline-error"><AlertTriangle size={15} />{error}</div>}
      </section>

      <section className={`panel terminal-panel ${scanning ? 'terminal-active' : ''}`}>
        <div className="terminal-header">
          <span><span className="terminal-dot red" /><span className="terminal-dot yellow" /><span className="terminal-dot green" /></span>
          <span className="terminal-title"><Terminal size={14} /> scan output</span>
          <span className="terminal-live">{scanning ? 'LIVE' : done ? 'COMPLETE' : 'IDLE'}</span>
        </div>
        <div className="terminal-body">
          {scanLog.map((line, index) => <div key={`${line}-${index}`} className={line.includes('complete') || line.includes('findings') ? 'terminal-success' : index === scanLog.length - 1 && scanning ? 'terminal-current' : ''}><span className="terminal-prefix">{index === scanLog.length - 1 && scanning ? '›' : '✓'}</span>{line}</div>)}
          {scanning && <div className="terminal-cursor">▌</div>}
          {scanResult && <>
            <div className="scan-completion">
              <div>
                <span className="section-kicker">SCAN COMPLETE</span>
                <strong>{scanResult.findings.length} findings</strong>
                <span>{scanResult.target}</span>
                <span>{scanResult.durationMs} ms · rules evaluated by backend</span>
              </div>
              <div className="completion-actions">
                <button type="button" className="button button-primary" onClick={onViewFindings}>View findings</button>
                <button type="button" className="button button-secondary" onClick={() => { setDone(false); setScanResult(null); }}>Run again</button>
              </div>
            </div>
            <div className="scan-output-findings">
              {scanResult.findings.slice(0, 5).map((finding) => (
                <button type="button" key={finding.id} onClick={() => onOpenFinding(finding)}>
                  <SeverityBadge severity={finding.severity} /><code>{finding.id}</code><span>{finding.rule_name}</span><span>{finding.file}:{finding.line}</span><ChevronRight size={13} />
                </button>
              ))}
            </div>
          </>}
        </div>
        <div className="terminal-footer">
          <span><Activity size={14} /> FastAPI · 127.0.0.1:8000</span>
          <span>Read-only scan</span>
        </div>
      </section>
    </div>
    <div className="scan-trust-row">
      <ShieldCheck size={17} />
      <span>Local security engine</span>
      <span className="muted">Deterministic scanner · no file mutation</span>
    </div>
  </div>;
}