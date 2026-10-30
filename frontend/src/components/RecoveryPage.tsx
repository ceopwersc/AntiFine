import {useCallback, useEffect, useState} from 'react';
import {AlertTriangle, RefreshCw, RotateCcw, X} from 'lucide-react';
import {fetchBackups, fetchRestorations, inspectBackup, previewRestore, restoreBackup} from '../api';
import type {BackupInspection, RestorationEvent, RestorePreview, RestoreResult} from '../types';
import {useDialog} from '../hooks/useDialog';
import {PageHeader} from './WorkstationUI';

const stateLabel = (state: BackupInspection['state']) => state === 'needs_review' ? 'Needs review' : state === 'restored' ? 'Source restored' : 'Ready for review';
const eventLabel = (event: RestorationEvent, latest?: RestorationEvent) => event.status === 'restore_pending' && latest && ['restored', 'restore_failed'].includes(latest.status) ? 'Restoration started' : event.status === 'restore_pending' || event.status === 'restore_needs_review' ? 'Needs review' : event.status === 'restored' ? 'Source restored' : 'Restore failed';

export function RecoveryPage({onRestored}: {onRestored: () => void}) {
  const [backups, setBackups] = useState<BackupInspection[]>([]);
  const [history, setHistory] = useState<RestorationEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const latestEvents = new Map<string, RestorationEvent>();
  for (const event of history) if (!latestEvents.has(event.restoration_id)) latestEvents.set(event.restoration_id, event);
  const load = useCallback(() => Promise.all([fetchBackups(), fetchRestorations()]).then(([response, events]) => {
    setBackups(response.backups); setHistory(events.restorations); setError('');
  }).catch(() => setError('Recovery evidence unavailable. Reconnect the local API and retry.')).finally(() => setLoading(false)), []);
  useEffect(() => {void load();}, [load]);
  const refresh = () => {setLoading(true); void load();};
  return <div className="content-stack recovery-page">
    <PageHeader eyebrow="Source recovery" title="Recovery" description="Inspect immutable backups and restore only a proven source version." action={<button className="button button-secondary" disabled={loading} onClick={refresh}><RefreshCw size={14}/>Refresh recovery</button>}/>
    <div className="recovery-warning"><AlertTriangle size={16}/><p>Restoring original source may reintroduce security findings. Restoration is not a successful security remediation.</p></div>
    {loading && <p role="status">Loading backup evidence…</p>}{error && <p role="alert">{error}</p>}
    {!loading && !error && backups.length === 0 && <div className="panel empty-state"><strong>No recorded remediation backups</strong><span>Apply an explicitly approved deterministic fix to create an immutable backup. Unassociated files cannot authorize recovery.</span></div>}
    {backups.length > 0 && <div className="panel table-panel"><div className="table-meta"><strong>Recent remediation backups</strong><span>Up to 100 · inspect before confirming</span></div><div className="table-scroll"><table className="findings-table recovery-table"><thead><tr><th>Source / resource</th><th>Remediation / backup</th><th>Recorded at</th><th>Availability / state</th><th>Action</th></tr></thead><tbody>{backups.map(backup => <tr key={backup.backup_id}>
      <td><code>{backup.file}</code><p>{backup.resource_label}</p><small>{backup.rule_id}</small></td>
      <td><code className="finding-reference">{backup.remediation_id}</code><code className="finding-reference">{backup.backup_id}</code></td>
      <td>{backup.remediated_at} UTC</td><td>{backup.backup_status}<p>{stateLabel(backup.state)}</p></td>
      <td><button className="button button-secondary" aria-label={`Inspect backup ${backup.backup_id}`} onClick={() => setSelected(backup.backup_id)}>Inspect backup</button></td>
    </tr>)}</tbody></table></div></div>}
    <section className="panel table-panel"><div className="table-meta"><strong>Restoration history</strong><span>Immutable events · security verification is not inferred</span></div>{history.length === 0 ? <p className="coverage-notice">No recorded restoration events.</p> : <div className="table-scroll"><table className="findings-table"><thead><tr><th>Recorded at</th><th>Source / restoration</th><th>Outcome</th><th>Rescan evidence</th></tr></thead><tbody>{history.map(event => <tr key={event.id}><td>{event.recorded_at} UTC</td><td><code>{event.file}</code><code className="finding-reference">{event.restoration_id}</code></td><td>{eventLabel(event, latestEvents.get(event.restoration_id))}{event.rollback_completed !== undefined && <p>Rollback {event.rollback_completed ? 'completed' : 'needs review'}</p>}</td><td><code className="finding-reference">{event.scan_id || 'No completed rescan recorded'}</code><p>{event.findings_count === null ? 'Coverage unconfirmed' : `${event.findings_count} finding(s)`}</p></td></tr>)}</tbody></table></div>}</section>
    {selected && <BackupDialog key={selected} backupId={selected} onClose={() => setSelected(null)} onRestored={() => {void load(); onRestored();}}/>}
  </div>;
}

function BackupDialog({backupId, onClose, onRestored}: {backupId: string; onClose: () => void; onRestored: () => void}) {
  const [inspection, setInspection] = useState<BackupInspection | null>(null);
  const [preview, setPreview] = useState<RestorePreview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<RestoreResult | null>(null);
  const dialog = useDialog(() => {if (!busy) onClose();});
  useEffect(() => {
    let active = true;
    inspectBackup(backupId).then(value => {if (active) setInspection(value);}).catch(() => {if (active) setError('Backup inspection unavailable. Refresh recovery and review again.');});
    return () => {active = false;};
  }, [backupId]);
  const refresh = async () => {
    setBusy(true); setPreview(null); setConfirmed(false); setError('');
    try {setInspection(await inspectBackup(backupId));} catch {setError('Backup inspection unavailable. Retry after reconnecting the API.');}
    finally {setBusy(false);}
  };
  const review = async () => {
    setBusy(true); setPreview(null); setConfirmed(false); setError('');
    try {const value = await previewRestore(backupId); setInspection(value); setPreview(value);}
    catch {setError('Restore preview rejected. Refresh inspection; source, backup or ownership may have changed.');}
    finally {setBusy(false);}
  };
  const apply = async () => {
    if (!preview || !confirmed || busy || result) return;
    setBusy(true); setError('');
    try {
      setResult(await restoreBackup(backupId, preview.preview_id));
      setInspection(current => current ? {...current, state: 'restored', can_restore: false,
        current_digest: current.original_digest, reason: 'Original bytes were restored and rescanned; review the resulting findings.'} : null);
      onRestored();
    }
    catch {
      setPreview(null); setConfirmed(false); setError('Restore rejected or interrupted. Inspect the recorded outcome before another confirmation.');
      try {setInspection(await inspectBackup(backupId));} catch {setInspection(current => current ? {...current, state: 'needs_review', can_restore: false, reason: 'Recovery evidence unavailable; inspect again.'} : null);}
      onRestored();
    }
    finally {setBusy(false);}
  };
  return <div ref={dialog} className="modal-scrim" role="dialog" aria-modal="true" aria-label="Inspect remediation backup" tabIndex={-1}><div className="remediation-modal recovery-modal">
    <div className="modal-header"><div><span className="drawer-eyebrow">Source recovery · operator controlled</span><h2>Inspect remediation backup</h2><p><code>{inspection?.file || 'Loading source identity…'}</code></p></div><button className="icon-button" aria-label="Close backup inspection" disabled={busy} onClick={onClose}><X size={18}/></button></div>
    {!inspection && !error && <p className="coverage-notice" role="status">Checking backup and current source…</p>}
    {inspection && <>
      <dl className="recovery-metadata">
        <div><dt>Finding</dt><dd><code>{inspection.finding_id}</code></dd></div><div><dt>Remediation</dt><dd><code>{inspection.remediation_id}</code></dd></div>
        <div><dt>File identity</dt><dd><code>{inspection.file_id}</code></dd></div><div><dt>Workspace identity</dt><dd><code>{inspection.workspace_id || 'Unavailable'}</code></dd></div>
        <div><dt>Resource / rule</dt><dd>{inspection.resource_label}<p>{inspection.rule_id}</p></dd></div><div><dt>Remediated at</dt><dd>{inspection.remediated_at} UTC</dd></div>
        <div><dt>Backup</dt><dd><code>{inspection.backup_id}</code><p>{inspection.backup_status}</p></dd></div><div><dt>Restoration state</dt><dd>{result ? 'Source restored' : stateLabel(inspection.state)}<p>{inspection.reason}</p></dd></div>
        <div><dt>Original version</dt><dd><code>{inspection.original_digest}</code></dd></div><div><dt>Remediated version</dt><dd><code>{inspection.remediated_digest}</code></dd></div>
        <div><dt>Current source version</dt><dd><code>{inspection.current_digest || 'Unavailable or ownership unconfirmed'}</code></dd></div>
      </dl>
      <div className="recovery-warning"><AlertTriangle size={16}/><p>{inspection.warning}</p></div>
      {inspection.changes && <div className="diff-view unified-diff"><pre aria-label="Restoration diff">{inspection.changes.diff.split('\n').map((line, index) => <span key={index} className={line.startsWith('+') && !line.startsWith('+++') ? 'diff-added' : line.startsWith('-') && !line.startsWith('---') ? 'diff-removed' : 'diff-context'}>{line}{'\n'}</span>)}</pre></div>}
      {!result && inspection.can_restore && !preview && <button className="button button-secondary recovery-review" disabled={busy} onClick={() => void review()}>Review restore</button>}
      {preview && !result && !error && <label className="approval-control"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)}/>I confirm restoring this original source and understand that security findings may return.</label>}
    </>}
    {error && <div className="modal-callout modal-callout-error" role="alert"><p>{error}</p></div>}
    {result && <div className="recovery-result" role="status"><strong>Source restored and rescanned</strong><p>{result.findings_count} finding(s) recorded. {result.finding_reopened ? 'The original finding reopened.' : 'Review the actual rescan findings.'} This is not a verified security remediation.</p><p>Rescan <code>{result.scan_id}</code></p><p>Safety backup <code>{result.pre_restore_backup_id}</code></p></div>}
    <div className="modal-footer"><button className="button button-secondary" disabled={busy} onClick={onClose}>{result ? 'Close recovery result' : 'Cancel'}</button>{!result && <><button className="button button-secondary" disabled={busy} onClick={() => void refresh()}>Refresh inspection</button><button className="button button-primary" disabled={busy || !preview || !confirmed || Boolean(error) || !inspection?.can_restore} onClick={() => void apply()}>{busy ? <><RefreshCw size={14} className="spin"/>Working…</> : <><RotateCcw size={14}/>Restore original and rescan</>}</button></>}</div>
  </div></div>;
}
