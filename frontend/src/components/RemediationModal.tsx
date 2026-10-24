import {useEffect, useState} from 'react';
import {Check, RefreshCw, ShieldCheck, X} from 'lucide-react';
import {explainRemediation, previewRemediation, remediateFinding, rescanFinding, type RemediationExplanation} from '../api';
import type {Finding} from '../types';
import {useDialog} from '../hooks/useDialog';

export function RemediationModal({finding, onClose, onApplied}: {finding: Finding; onClose: () => void; onApplied: () => void}) {
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof previewRemediation>> | null>(null);
  const [approved, setApproved] = useState(false);
  const [applying, setApplying] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Awaited<ReturnType<typeof remediateFinding>> | null>(null);
  const [explanation, setExplanation] = useState<RemediationExplanation | null>(null);
  const [aiError, setAIError] = useState('');
  const [explaining, setExplaining] = useState(false);
  const dialogRef = useDialog(() => {if (!applying && !rescanning) onClose();});
  useEffect(() => {
    let active = true;
    previewRemediation(finding.id).then(value => {if (active) setPreview(value);})
      .catch(() => {if (active) setError('Preview unavailable: source may be stale or require manual action. Rescan the source before reviewing again.');});
    return () => {active = false;};
  }, [finding.id]);
  const apply = async () => {
    if (!preview || preview.finding_id !== finding.id || !approved || error || applying || result) return;
    setApplying(true);
    try {const value = await remediateFinding(finding.id, preview.preview_id); setResult(value); onApplied();}
    catch {setApproved(false); setError('Apply rejected or verification failed. Source may be stale; inspect the backup and recorded status, then rescan.'); onApplied();}
    finally {setApplying(false);}
  };
  const rescan = async () => {
    setRescanning(true); setApproved(false);
    try {await rescanFinding(finding.id); onApplied(); onClose();}
    catch {setError('Source could not be rescanned. Re-import the project or choose an authorized local path.');}
    finally {setRescanning(false);}
  };
  const explain = async () => {
    if (!preview) return;
    setExplaining(true); setAIError('');
    try {setExplanation(await explainRemediation({preview_id:preview.preview_id, finding:{id:finding.id,rule_name:finding.rule_name,severity:finding.severity.toUpperCase(),filename:finding.file,frameworks:finding.frameworks,remediation:finding.remediation,description:finding.description},before:preview.before,after:preview.after,diff:preview.diff,remediation:finding.remediation,frameworks:finding.frameworks}));}
    catch {setAIError('Local AI unavailable. Deterministic preview and verification remain available.');}
    finally {setExplaining(false);}
  };
  return <div ref={dialogRef} className="modal-scrim" role="dialog" aria-modal="true" aria-label="Review remediation" tabIndex={-1}><div className="remediation-modal">
    <div className="modal-header"><div><span className="drawer-eyebrow">Deterministic remediation</span><h2>Review proposed fix</h2><p><code>{finding.file}:{preview?.changed_line ?? finding.line}</code> · {preview?.resource_label ?? finding.resource_label}</p><code>{finding.rule_id}</code></div><button className="icon-button" aria-label="Close" disabled={applying || rescanning} onClick={onClose}><X size={18}/></button></div>
    {error ? <div className="modal-callout modal-callout-error" role="alert"><strong>Preview or apply unavailable</strong><p>{error}</p><button className="button button-secondary" disabled={rescanning} onClick={() => void rescan()}>{rescanning ? 'Rescanning…' : 'Rescan source and return to findings'}</button></div> : preview ? <>
      <div className="diff-view unified-diff"><pre aria-label="Proposed diff">{preview.diff.split('\n').map((line,index) => <span key={index} className={line.startsWith('+') && !line.startsWith('+++') ? 'diff-added' : line.startsWith('-') && !line.startsWith('---') ? 'diff-removed' : 'diff-context'}>{line}{'\n'}</span>)}</pre></div>
      <p className="preview-version">Source version <code>{preview.source_digest}</code> · lines {preview.start_line}–{preview.end_line}</p>
      <ul className="preview-conditions">{preview.conditions.map(condition => <li key={condition}>{condition}</li>)}</ul>
      {!result && <label className="approval-control"><input type="checkbox" checked={approved} disabled={applying} onChange={event => setApproved(event.target.checked)}/>I approve this exact change to the displayed file and resource.</label>}
    </> : <p role="status">Loading deterministic preview…</p>}
    <section className="remediation-ai-review" aria-live="polite"><h3>Local AI · advisory</h3><p>AI cannot approve, apply or verify a fix.</p>{aiError && <p role="alert">{aiError}</p>}{explanation && <p className="ai-response">{explanation.explanation}</p>}<button className="button button-secondary" disabled={!preview || Boolean(error) || explaining || applying} onClick={() => void explain()}>{explaining ? 'Analyzing locally…' : 'Explain this Fix'}</button></section>
    {result && <div className="modal-callout" role="status"><ShieldCheck size={17}/><div><strong>{result.verified ? 'Verification completed' : 'Original finding resolved; findings remain'}</strong><p>{result.verified ? 'Deterministic rescan detected no remaining findings in this file.' : `${result.findings_count} finding(s) remain. This file is not verified.`} No new finding introduced.</p><p>Backup <code>{result.backup_id}</code></p><p>Verification scan <code>{result.scan_id}</code></p></div></div>}
    <div className="modal-footer"><button className="button button-secondary" disabled={applying || rescanning} onClick={onClose}>Cancel</button>{result ? <button className="button button-success" onClick={onClose}><Check size={15}/>{result.verified ? 'Fix applied' : 'Close applied change'}</button> : <button className="button button-primary" disabled={applying || rescanning || !preview || !approved || Boolean(error)} onClick={() => void apply()}>{applying ? <><RefreshCw size={15} className="spin"/>Applying and verifying…</> : 'Apply deterministic fix'}</button>}</div>
  </div></div>;
}
