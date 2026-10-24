import type {FileCoverage, ScanRun} from '../types';

export function CoveragePanel({coverage, scanId, status}: {coverage: FileCoverage[]; scanId: string; status: ScanRun['status']}) {
  return <details className="panel coverage-panel" open={status !== 'completed'}>
    <summary>Scan coverage · {status} · {coverage.filter(file => file.status === 'evaluated').length}/{coverage.length} files evaluated</summary>
    <p><code>{scanId}</code> · Only the listed checks were evaluated. Mappings are not certification.</p>
    <div className="table-scroll"><table className="findings-table"><thead><tr><th>File</th><th>Coverage</th><th>Rule families</th></tr></thead><tbody>
      {coverage.map(file => <tr key={file.file_id}><td><code>{file.file}</code>{file.error && <p>{file.error}</p>}</td><td>{file.status}</td><td>{file.status === 'evaluated' ? file.rule_families?.join(', ') || 'Legacy coverage; rescan for families' : 'Not evaluated'}</td></tr>)}
    </tbody></table></div>
    {coverage.length === 0 && <p>No files evaluated. This is not a security pass.</p>}
  </details>;
}
