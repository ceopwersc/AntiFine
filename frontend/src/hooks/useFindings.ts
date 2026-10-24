import { useCallback,useEffect,useState } from 'react';
import { fetchFindings,fetchScanHistory } from '../api';
import { normalizeFinding,type Finding } from '../types';

export function useFindings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState('Scan coverage unavailable. Run a scan to evaluate supported rules.');
  const [findingError, setFindingError] = useState('');
  const reloadFindings = useCallback(async () => {
    try {
      const [response, history] = await Promise.all([fetchFindings(), fetchScanHistory()]);
      setCoverage(describeCoverage(history.scans));
      setFindings(response.findings.map(normalizeFinding));
      setFindingError('');
    } catch { setFindingError('Persisted findings unavailable. Reconnect the local API.'); }
  }, []);
  useEffect(() => {
    void Promise.all([fetchFindings(), fetchScanHistory()]).then(([response, history]) => { setFindings(response.findings.map(normalizeFinding)); setCoverage(describeCoverage(history.scans)); })
      .catch(() => setFindingError('Persisted findings unavailable. Reconnect the local API.'));
  }, []);
  return { findings, setFindings, reloadFindings, findingError, coverage };
}

function describeCoverage(scans: Array<{status:string;coverage:Array<{status:string}>}>) {
  const latest = scans[0];
  if (!latest) return 'No evaluated scans yet. Compliance certification is not provided.';
  return `Latest scan: ${latest.status}. ${latest.coverage.filter(f=>f.status==='evaluated').length} evaluated file(s); ${latest.coverage.filter(f=>f.status!=='evaluated').length} unsupported/error file(s). Coverage details are in Scan history. No compliance certification is inferred.`;
}
