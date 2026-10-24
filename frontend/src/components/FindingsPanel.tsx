import {useMemo, useState} from 'react';
import {ChevronRight, Search} from 'lucide-react';
import {findingState, type Finding, type Severity} from '../types';
import {PageHeader, SeverityBadge} from './WorkstationUI';

export function FindingsPanel({findings, onSelect}: {findings: Finding[]; onSelect: (finding: Finding) => void}) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('All');
  const [status, setStatus] = useState('All');
  const [file, setFile] = useState('All');
  const [family, setFamily] = useState('All');
  const [sort, setSort] = useState('severity');
  const files = useMemo(() => Array.from(new Map(findings.map(finding => [finding.file_id, finding.file])).entries()).sort((a,b) => a[1].localeCompare(b[1])), [findings]);
  const families = Array.from(new Set(findings.map(finding => finding.family))).sort();
  const ranks: Record<Severity, number> = {Critical:0, High:1, Medium:2, Low:3, Informational:4, Unknown:5};
  const filtered = findings.filter(finding => (severity === 'All' || finding.severity === severity) &&
    (status === 'All' || finding.status === status) && (file === 'All' || finding.file_id === file) &&
    (family === 'All' || finding.family === family) &&
    `${finding.rule_id} ${finding.id} ${finding.rule_name} ${finding.file} ${finding.resource_label} ${finding.frameworks.join(' ')}`.toLowerCase().includes(query.toLowerCase()))
    .sort((a,b) => sort === 'severity' ? ranks[a.severity]-ranks[b.severity] : sort === 'file' ? a.file.localeCompare(b.file) : a.status.localeCompare(b.status));
  return <div className="content-stack workstation-findings">
    <PageHeader eyebrow="Finding queue" title="Findings" description="Recorded security evidence, exact source identity, and verification state."/>
    <div className="finding-toolbar"><div className="search-input"><Search size={15}/><input placeholder="Search rule IDs, files, paths, frameworks" value={query} onChange={event => setQuery(event.target.value)}/></div>
      <div className="filter-group">
        <select aria-label="Filter by severity" value={severity} onChange={event => setSeverity(event.target.value)}><option value="All">All severities</option>{Object.keys(ranks).map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter by status" value={status} onChange={event => setStatus(event.target.value)}><option value="All">All statuses</option>{['Open','Resolved','Accepted','Unknown'].map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter by file" value={file} onChange={event => setFile(event.target.value)}><option value="All">All files</option>{files.map(([id,name]) => <option key={id} value={id}>{name} · {id.slice(0,8)}</option>)}</select>
        <select aria-label="Filter by rule family" value={family} onChange={event => setFamily(event.target.value)}><option value="All">All rule families</option>{families.map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Sort findings" value={sort} onChange={event => setSort(event.target.value)}><option value="severity">Sort: severity</option><option value="file">Sort: file</option><option value="status">Sort: status</option></select>
      </div>
    </div>
    <div className="panel table-panel"><div className="table-meta"><span>{filtered.length} of {findings.length} persisted findings</span><span>Deterministic evidence</span></div>
      <div className="table-scroll"><table className="findings-table workstation-table"><thead><tr><th>Severity</th><th>Rule / finding</th><th>Source / resource</th><th>Mappings</th><th>State</th><th aria-label="Actions"/></tr></thead><tbody>
        {filtered.map(finding => <tr key={finding.id} role="button" tabIndex={0} aria-label={`${finding.rule_name} ${finding.id}`} onClick={() => onSelect(finding)} onKeyDown={event => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); onSelect(finding);}}}>
          <td><SeverityBadge severity={finding.severity}/></td><td><code className="rule-id">{finding.rule_id}</code><strong>{finding.rule_name}</strong><small className="finding-reference">{finding.id}</small></td>
          <td><code>{finding.file}:{finding.line}</code><p>{finding.resource_label}</p></td><td>{finding.frameworks.join(', ') || 'No mapping supplied'}</td>
          <td><span className={`status-badge ${finding.status.toLowerCase()}`}>{finding.status}</span><p>{findingState(finding)}</p></td><td><ChevronRight size={15}/></td>
        </tr>)}
      </tbody></table></div>
      {filtered.length === 0 && <div className="empty-state"><Search size={22}/><strong>{findings.length ? 'No findings match these filters' : 'No persisted findings yet'}</strong><span>{findings.length ? 'Adjust the rule, file, status, or severity filters.' : 'Import a project or run the safe Terraform demo. A lack of records is not a completed scan.'}</span></div>}
    </div>
  </div>;
}
