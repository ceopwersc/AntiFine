import { type ReactNode } from 'react';
import { type Severity } from '../types';
const severityStyles: Record<Severity, string> = {
  Critical: 'severity-critical',
  High: 'severity-high',
  Medium: 'severity-medium',
  Low: 'severity-low',
  Informational: 'severity-info',
  Unknown: 'severity-info',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge ${severityStyles[severity]}`}><span className="severity-dot" />{severity}</span>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow ?? 'Security posture'}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}