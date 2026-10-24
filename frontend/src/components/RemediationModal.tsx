import { Check,RefreshCw,ShieldCheck,X } from 'lucide-react';
import { useEffect,useState } from 'react';
import { explainRemediation,previewRemediation,remediateFinding,type RemediationExplanation } from '../api';
import { useDialog } from '../hooks/useDialog';
import type { Finding } from '../types';

export function RemediationModal({ finding, onClose, onApplied }: { finding: Finding; onClose: () => void; onApplied: () => void }) {
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof previewRemediation>> | null>(null);
  const [error, setError] = useState('');
  const [applying, setApplying] = useState(false);
  const [result, setResult] = useState<Awaited<ReturnType<typeof remediateFinding>> | null>(null);
  const [explanation, setExplanation] = useState<RemediationExplanation | null>(null);
  const [aiError, setAIError] = useState('');
  const [explaining, setExplaining] = useState(false);
  useDialog(() => { if (!applying) onClose(); });
  useEffect(() => {
    let active = true;
    previewRemediation(finding.id).then(value => { if (active) setPreview(value); })
      .catch((e: unknown) => { if (active) setError(e instanceof Error ? e.message : 'Deterministic preview unavailable. Rescan and review again.'); });
    return () => { active = false; };
  }, [finding.id]);
  const apply = async () => {
    if (!preview || error || applying || result) return;
    setApplying(true);
    try {
      const value = await remediateFinding(finding.id, preview.preview_id);
      setResult(value); onApplied();
    } catch { setError('Apply rejected. The source or preview may be stale. Rescan and review again.'); }
    finally { setApplying(false); }
  };
  const explain = async () => {
    if (!preview) return;
    setExplaining(true); setAIError('');
    try { setExplanation(await explainRemediation({preview_id:preview.preview_id,finding: {id:finding.id,rule_name:finding.rule_name,severity:finding.severity.toUpperCase(),filename:finding.file,frameworks:finding.frameworks,remediation:finding.remediation,description:finding.description},before:preview.before,after:preview.after,diff:`BEFORE\n${preview.before}\nAFTER\n${preview.after}`,remediation:finding.remediation,frameworks:finding.frameworks})); }
    catch { setAIError('Local AI unavailable. Deterministic preview and verification remain available.'); }
    finally { setExplaining(false); }
  };
  return <div className="modal-scrim" role="dialog" aria-modal="true" aria-label="Review remediation" tabIndex={-1}>
    <div className="remediation-modal">
      <div className="modal-header"><div><span className="drawer-eyebrow">Deterministic remediation</span><h2>Review proposed fix</h2><p>Source: <code>{finding.file}</code> · line {finding.line}</p></div><button className="icon-button" aria-label="Close" disabled={applying} onClick={onClose}><X size={18}/></button></div>
      {error ? <div className="modal-callout modal-callout-error" role="alert"><strong>Preview or apply unavailable</strong><p>{error}</p></div> : preview ? <div className="diff-view">
        <div className="diff-column"><div className="diff-column-header removed">Before</div><pre>{preview.before}</pre></div>
        <div className="diff-column"><div className="diff-column-header added">After</div><pre>{preview.after}</pre></div>
      </div> : <p role="status">Loading deterministic preview…</p>}
      <section className="remediation-ai-review" aria-live="polite"><h3>Local AI · advisory explanation</h3><p>AI cannot approve, apply or verify a fix.</p>{aiError && <p role="alert">{aiError}</p>}{explanation && <p className="ai-response">{explanation.explanation}</p>}<button className="button button-secondary" disabled={!preview || Boolean(error) || explaining} onClick={() => void explain()}>{explaining ? 'Analyzing locally…' : explanation ? 'Regenerate' : 'Explain this Fix'}</button></section>
      {result && <div className="modal-callout" role="status"><ShieldCheck size={17}/><div><strong>{result.verified ? 'Verification completed' : 'Change applied; findings remain'}</strong><p>{result.verified ? 'Deterministic rescan detected no remaining findings.' : `${result.findings_count} finding(s) remain. This file is not marked verified.`} Backup: {result.backup_id}.</p></div></div>}
      <div className="modal-footer"><button className="button button-secondary" disabled={applying} onClick={onClose}>Cancel</button>{result ? <button className="button button-success" onClick={onClose}><Check size={15}/>{result.verified ? 'Fix applied' : 'Close applied change'}</button> : <button className="button button-primary" disabled={applying || !preview || Boolean(error)} onClick={() => void apply()}>{applying ? <><RefreshCw size={15} className="spin"/>Applying fix…</> : 'Apply deterministic fix'}</button>}</div>
    </div>
  </div>;
}
