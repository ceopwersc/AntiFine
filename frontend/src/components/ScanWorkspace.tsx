import {AlertTriangle, FileCode2, FilePlus2, FolderOpen, Play, RefreshCw, ShieldCheck, Terminal, Upload, X} from 'lucide-react';
import {useRef, useState} from 'react';
import {createDemoWorkspace, runScan, uploadScanWorkspace} from '../api';
import {normalizeFinding, type Finding, type ScanResponse} from '../types';
import {CoveragePanel} from './CoveragePanel';
import {PageHeader, SeverityBadge} from './WorkstationUI';

const filePath = (file: File) => file.webkitRelativePath || file.name;
const excluded = new Set(['.git', '.terraform', 'node_modules', '.venv', 'venv', '__pycache__']);

export function ScanWorkspace({onComplete, target, setTarget, onViewFindings, onOpenFinding}: {
  onComplete: (findings: Finding[]) => void; target: string; setTarget: (target: string) => void;
  onViewFindings: () => void; onOpenFinding: (finding: Finding) => void;
}) {
  const [mode, setMode] = useState<'import' | 'local'>('import');
  const [scanType, setScanType] = useState('IaC Config Audit');
  const [scanning, setScanning] = useState(false);
  const [log, setLog] = useState(['Ready. Import files, choose a project folder, or try the safe demo.']);
  const [files, setFiles] = useState<File[]>([]);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<ScanResponse | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const directoryInput = useRef<HTMLInputElement>(null);

  const addFiles = (incoming: FileList) => {
    const all = Array.from(incoming);
    const selected = all.filter(file => !filePath(file).split('/').some(part => excluded.has(part)));
    setFiles(current => {
      const paths = new Map(current.map(file => [filePath(file), file]));
      selected.forEach(file => paths.set(filePath(file), file));
      return [...paths.values()];
    });
    setNotice(all.length === selected.length ? '' : `${all.length - selected.length} files in tool/cache directories excluded before import.`);
    setError('');
  };
  const start = async (demo = false) => {
    if (scanning) return;
    setScanning(true); setError(''); setResult(null);
    setLog([demo ? 'Creating private copy of synthetic Terraform demo…' : mode === 'import' ? 'Importing project into a private workspace…' : 'Authorizing server-local target…']);
    try {
      const selectedTarget = demo ? (await createDemoWorkspace()).target_path : mode === 'import' ? (await uploadScanWorkspace(files)).target_path : target.trim();
      setLog(current => [...current, 'Running bounded deterministic checks…']);
      const response = await runScan(selectedTarget, demo ? 'IaC Config Audit' : scanType);
      setResult(response);
      setLog(current => [...current, `Run ${response.scan_id}`, `Coverage: ${response.status}. ${response.coverage.filter(file => file.status === 'evaluated').length}/${response.coverage.length} files evaluated.`, `${response.findings_count} findings recorded.`]);
      if (response.status !== 'completed') setError('Scan incomplete. Review coverage and parser errors before making security decisions.');
      onComplete(response.findings.map(normalizeFinding));
    } catch (requestError: unknown) {
      const detail = (requestError as {response?: {data?: {detail?: unknown}}})?.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'Scan unavailable. Check the local API and selected input, then retry.');
      setLog(current => [...current, 'Scan request failed. No security pass established.']);
    } finally {setScanning(false);}
  };

  return <div className="content-stack scan-workspace">
    <PageHeader eyebrow="Local security engine" title="New security scan" description="Import infrastructure, inspect exact findings, then review a deterministic fix." action={<button className="button button-secondary" disabled={scanning} onClick={() => void start(true)}>Try safe Terraform demo</button>}/>
    <div className="scan-mode-tabs"><button className={`tab-button ${mode === 'import' ? 'active' : ''}`} onClick={() => setMode('import')}><Upload size={14}/>Import files</button><button className={`tab-button ${mode === 'local' ? 'active' : ''}`} onClick={() => setMode('local')}><Terminal size={14}/>Server-local path</button></div>
    <div className="scan-layout"><section className="panel scan-config">
      {mode === 'import' ? <>
        <div className="panel-heading"><div><h2>Project files</h2><p>Private local import. Relative directories are preserved; source stays on this computer.</p></div></div>
        <div className="drop-zone" onDragOver={event => event.preventDefault()} onDrop={event => {event.preventDefault(); addFiles(event.dataTransfer.files);}}>
          <Upload size={18}/><strong>Drop files here</strong><span>Use Choose project to preserve folder structure.</span>
          <button className="button button-secondary" disabled={scanning} onClick={() => fileInput.current?.click()}><FilePlus2 size={14}/>Choose files</button>
          <button className="button button-secondary" disabled={scanning} onClick={() => {if (directoryInput.current) {directoryInput.current.webkitdirectory = true; directoryInput.current.click();}}}><FolderOpen size={14}/>Choose project</button>
          <small>Terraform, Kubernetes, Docker and supported secret/config formats. Other files remain visible as unsupported coverage.</small>
          <input ref={fileInput} aria-label="Import files" type="file" multiple hidden onChange={event => {if (event.target.files) addFiles(event.target.files); event.currentTarget.value = '';}}/>
          <input ref={directoryInput} aria-label="Import project directory" type="file" multiple hidden onChange={event => {if (event.target.files) addFiles(event.target.files); event.currentTarget.value = '';}}/>
        </div>
        <div className="queue-heading"><span>Scan queue <strong>{files.length}</strong></span><button className="text-button" disabled={scanning} onClick={() => {setFiles([]); setNotice('');}}>Clear all</button></div>
        <div className="scan-queue">{files.length === 0 ? <div className="queue-empty">Choose a project or try the synthetic demo. No cloud account or AI setup required.</div> : files.map(file => <div className="queue-row" key={filePath(file)}><FileCode2 size={15}/><div><strong>{filePath(file)}</strong><span>{file.size} bytes · coverage determined by backend</span></div><button className="icon-button small" disabled={scanning} aria-label={`Remove ${filePath(file)}`} onClick={() => setFiles(current => current.filter(item => filePath(item) !== filePath(file)))}><X size={14}/></button></div>)}</div>
        {notice && <p role="status">{notice}</p>}
      </> : <>
        <div className="panel-heading"><div><h2>Server-local path</h2><p>A file or directory relative to the configured workspace root.</p></div></div>
        <label className="field-label" htmlFor="target">{scanType === 'IaC Config Audit' ? 'Workspace-relative path' : 'Authorized target URL'}</label><div className="input-with-icon"><FileCode2 size={17}/><input id="target" value={target} onChange={event => setTarget(event.target.value)} placeholder="examples/terraform-workflow"/></div>
      </>}
      <label className="field-label" htmlFor="protocol">Scan protocol</label><div className="select-wrap"><select id="protocol" value={scanType} onChange={event => setScanType(event.target.value)}><option>IaC Config Audit</option><option>SSRF Web Audit</option></select></div>
      <button className="button button-primary scan-button" disabled={scanning || (mode === 'import' ? files.length === 0 : !target.trim())} onClick={() => void start()}>{scanning ? <><RefreshCw size={16} className="spin"/>Scanning…</> : <><Play size={16}/>Run scan</>}</button>
      {error && <div className="inline-error" role="alert"><AlertTriangle size={15}/>{error}</div>}
    </section><section className="panel terminal-panel" aria-live="polite"><div className="terminal-header"><span>Deterministic scan activity</span><span>{scanning ? 'RUNNING' : result?.status.toUpperCase() ?? 'READY'}</span></div><div className="terminal-body">{log.map((line, index) => <p key={index}>{line}</p>)}{result && <div className="completion-actions"><button className="button button-primary" onClick={onViewFindings}>View findings</button><button className="button button-secondary" onClick={() => void start()}>Run again</button></div>}{result?.findings.slice(0, 5).map(item => <button className="scan-finding-result" key={item.id} onClick={() => onOpenFinding(normalizeFinding(item))}><SeverityBadge severity={normalizeFinding(item).severity}/>{item.rule_name} · {item.file}</button>)}</div></section></div>
    {result && <CoveragePanel coverage={result.coverage} scanId={result.scan_id} status={result.status}/>}
    <div className="scan-trust-row"><ShieldCheck size={17}/><span>Deterministic checks · scans never modify source · AI is optional and advisory</span></div>
  </div>;
}
