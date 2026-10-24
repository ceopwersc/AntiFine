import {useState} from 'react';
import {motion} from 'framer-motion';
import {Copy, RefreshCw, X} from 'lucide-react';
import {explainFinding, type FindingExplanation} from '../api';
import {findingState, type Finding} from '../types';
import {useDialog} from '../hooks/useDialog';
import {SeverityBadge} from './WorkstationUI';
import {renderExplanation} from '../utils/findingPresentation';

interface Props {
  finding: Finding; onClose: () => void; onRemediate: () => void; onAsk: () => void;
  explanationCache: Record<string, FindingExplanation>; onExplanation: (id: string, value: FindingExplanation) => void;
}

export function FindingDrawer({finding, onClose, onRemediate, onAsk, explanationCache, onExplanation}: Props) {
  const dialogRef = useDialog<HTMLElement>(onClose);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const explanation = explanationCache[finding.id];
  const explain = async () => {
    setLoading(true); setError('');
    try { onExplanation(finding.id, await explainFinding({id:finding.id, rule_name:finding.rule_name,
      severity:finding.severity.toUpperCase(), filename:finding.file, frameworks:finding.frameworks,
      remediation:finding.remediation, description:finding.description})); }
    catch { setError('Local AI unavailable. Deterministic evidence and fixes remain available.'); }
    finally { setLoading(false); }
  };
  const copyLocation = async () => {try {await navigator.clipboard.writeText(`${finding.file}:${finding.line}`); setCopied(true);} catch {setError('Copy unavailable; select the displayed location.');}};
  return <><motion.button className="drawer-scrim" aria-label="Close finding details" onClick={onClose}/>
    <motion.aside ref={dialogRef} className="detail-drawer" role="dialog" aria-modal="true" aria-label="Finding details" tabIndex={-1} initial={{x:'100%'}} animate={{x:0}} exit={{x:'100%'}}>
      <div className="drawer-header"><div><code className="rule-id">{finding.rule_id}</code><h2>{finding.rule_name}</h2><p><code>{finding.file}:{finding.line}</code></p></div><button className="icon-button" aria-label="Close" onClick={onClose}><X size={18}/></button></div>
      <div className="drawer-content">
        <div className="drawer-badges"><SeverityBadge severity={finding.severity}/><span className={`status-badge ${finding.status.toLowerCase()}`}>{finding.status}</span></div>
        <section className="drawer-section"><h3>Source and rule</h3><p>{finding.resource_label}</p><p>Family: {finding.family}</p><p>Workspace: <code>{finding.workspace_id}</code></p><p>File ID: <code>{finding.file_id}</code></p><code className="finding-reference">{finding.id}</code><button className="text-button" onClick={() => void copyLocation()}><Copy size={13}/>{copied ? 'Location copied' : 'Copy source location'}</button></section>
        <section className="drawer-section"><h3>Why this matters</h3><p>{finding.description}</p></section>
        <section className="drawer-section"><h3>Deterministic evidence</h3><pre className="drawer-code">{finding.evidence}</pre><p>Sensitive values are withheld. Review fix shows a sanitized source excerpt for an eligible edit.</p></section>
        <section className="drawer-section"><h3>Remediation and verification</h3><strong>{findingState(finding)}</strong><p>{finding.remediation}</p>{finding.verification.scan_id && <p>Recorded verification scan: <code>{finding.verification.scan_id}</code></p>}{finding.verification.recorded_at && <p>Recorded at {finding.verification.recorded_at} UTC</p>}{finding.verification.state === 'verification_failed' && <p>Review the private backup and rescan before another approval.</p>}</section>
        <section className="drawer-section"><h3>Supported mappings</h3><p>{finding.frameworks.join(', ') || 'No mapping supplied'}</p><p>Mappings are metadata, not evaluated control passes.</p></section>
        <section className="drawer-section ai-explanation-section"><h3>Local AI · advisory</h3><p>AI cannot approve, apply or verify a fix.</p>{error && <p role="alert">{error}</p>}{explanation && <div className="ai-response">{renderExplanation(explanation.explanation)}</div>}<button className="button button-secondary" disabled={loading} onClick={() => void explain()}>{loading ? <RefreshCw className="spin" size={14}/> : null}{explanation ? 'Regenerate explanation' : 'Explain with Local AI'}</button><button className="button button-secondary" onClick={onAsk}>Ask AntiFine about this</button></section>
      </div>
      <div className="drawer-footer"><button className="button button-secondary" onClick={onClose}>Close</button>{finding.remediation_eligible && finding.status === 'Open' && <button className="button button-primary" onClick={onRemediate}>Review fix</button>}</div>
    </motion.aside></>;
}
