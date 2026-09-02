import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { runScan } from '../api';

interface Finding {
  rule_name: string;
  severity: string;
  compliance_framework: string;
  description: string;
}

interface ScanResult {
  status: string;
  target?: string;
  findings_count?: number;
  findings?: Finding[];
  summary?: string;
  // SSRF endpoint still returns message-only
  message?: string;
}

// Severity → terminal colour class
const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-500',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-blue-400',
};

function SeverityBadge({ severity }: { severity: string }) {
  const upper = severity.toUpperCase();
  const cls = SEVERITY_COLOR[upper] ?? 'text-gray-400';
  return <span className={`font-bold ${cls}`}>[{upper}]</span>;
}

export default function Scanner() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('SSRF Web Audit');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [showRaw, setShowRaw] = useState(false);

  const handleScan = async () => {
    if (!target.trim()) return;

    // Strip leading/trailing quotation marks before firing
    const cleanTarget = target.replace(/^["']|["']$/g, '').trim();

    setIsScanning(true);
    setHasError(false);
    setErrorMsg('');
    setResult(null);
    setShowRaw(false);

    try {
      const data = await runScan(cleanTarget, scanType) as ScanResult;
      setResult(data);
    } catch (err: any) {
      setHasError(true);
      const detail =
        err?.response?.data?.detail ?? err?.message ?? 'Unknown error.';
      setErrorMsg(detail);
    } finally {
      setIsScanning(false);
    }
  };

  // ── Terminal lines builder ────────────────────────────────────────────────
  const renderTerminal = () => {
    if (isScanning) {
      return (
        <motion.div className="flex flex-col gap-1" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <span className="text-green-400">[INFO] Initializing connection parameters...</span>
          <span className="text-green-400">[INFO] Routing request to backend engine...</span>
          <motion.span
            animate={{ opacity: [1, 0.2, 1] }}
            transition={{ duration: 1, repeat: Infinity }}
            className="text-neon"
          >
            ▌ Awaiting engine response...
          </motion.span>
        </motion.div>
      );
    }

    if (hasError) {
      return (
        <div className="flex flex-col gap-1 text-red-400">
          <span>[ERROR] Request failed.</span>
          <span>[DETAIL] {errorMsg}</span>
          <span className="text-red-600">[HINT] Ensure the backend is running on http://localhost:8000</span>
        </div>
      );
    }

    if (!result) {
      return <span className="text-gray-600">&gt; System ready. Awaiting coordinates.</span>;
    }

    // SSRF or simple message response
    if (!result.findings) {
      const status = (result.status ?? 'INFO').toUpperCase();
      const color = status === 'SUCCESS' || status === 'COMPLETED' ? 'text-green-400' : 'text-yellow-400';
      return <span className={color}>[{status}] {result.message ?? result.summary ?? 'Scan completed.'}</span>;
    }

    // Full IaC structured response
    const findings = result.findings;
    const count = result.findings_count ?? findings.length;
    const summaryColor = count === 0 ? 'text-green-400' : count >= 5 ? 'text-red-400' : 'text-yellow-400';

    return (
      <div className="flex flex-col gap-2">
        {/* Header */}
        <span className="text-green-400">[INFO] Target: {result.target}</span>
        <span className={summaryColor}>[INFO] Total Violations: {count}</span>
        <span className="text-gray-500">{'─'.repeat(60)}</span>

        {/* Per-finding lines */}
        {count === 0 ? (
          <span className="text-green-400">[OK] No compliance violations detected. Target appears clean.</span>
        ) : (
          findings.map((f, i) => (
            <div key={i} className="flex flex-col gap-0.5">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="text-gray-500">[{String(i + 1).padStart(2, '0')}]</span>
                <SeverityBadge severity={f.severity} />
                <span className="text-white font-semibold">{f.rule_name}</span>
              </div>
              <span className="text-gray-400 ml-8">
                Control: <span className="text-neon">{f.compliance_framework}</span>
              </span>
              <span className="text-gray-500 ml-8">Description: {f.description}</span>
            </div>
          ))
        )}

        <span className="text-gray-500 mt-2">{'─'.repeat(60)}</span>
        <span className="text-green-400">[DONE] {result.summary}</span>

        {/* Raw JSON toggle */}
        <div className="mt-3 border border-white/10 rounded-lg overflow-hidden">
          <button
            onClick={() => setShowRaw(v => !v)}
            className="w-full text-left px-4 py-2 text-xs text-gray-500 uppercase tracking-widest bg-white/5 hover:bg-white/10 transition-colors flex items-center gap-2"
          >
            <span className={`transition-transform duration-200 ${showRaw ? 'rotate-90' : ''}`}>▶</span>
            {showRaw ? 'Collapse' : 'Expand'} raw JSON payload
          </button>
          <AnimatePresence>
            {showRaw && (
              <motion.pre
                key="raw"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.25 }}
                className="text-xs text-gray-400 bg-black/40 p-4 overflow-x-auto"
              >
                {JSON.stringify(result, null, 2)}
              </motion.pre>
            )}
          </AnimatePresence>
        </div>
      </div>
    );
  };

  return (
    <div className="w-full h-full p-8 flex flex-col">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">
        WAR <span className="text-neon">ROOM</span>
      </h1>

      <div className="bg-surface border border-white/10 p-6 rounded-xl max-w-4xl mb-6 flex flex-col gap-4">
        <div>
          <label className="block text-gray-400 text-sm uppercase tracking-widest mb-2">
            Target Interface
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleScan()}
            placeholder='e.g. http://10.0.0.5/api or ./k8s/deployment.yaml'
            className="w-full bg-oled border border-white/20 rounded p-3 text-white focus:outline-none focus:border-neon transition-colors font-mono"
          />
        </div>

        <div>
          <label className="block text-gray-400 text-sm uppercase tracking-widest mb-2">
            Audit Protocol
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="w-full bg-oled border border-white/20 rounded p-3 text-white focus:outline-none focus:border-neon transition-colors"
          >
            <option>SSRF Web Audit</option>
            <option>IaC Config Audit</option>
          </select>
        </div>

        <motion.button
          onClick={handleScan}
          disabled={!target.trim() || isScanning}
          whileHover={{
            scale: target.trim() && !isScanning ? 1.02 : 1,
            boxShadow: target.trim() && !isScanning ? '0px 0px 15px #00E5FF' : 'none',
          }}
          whileTap={{ scale: target.trim() && !isScanning ? 0.98 : 1 }}
          className={`mt-4 w-full py-4 rounded font-bold text-xl tracking-widest transition-colors flex items-center justify-center gap-3 ${
            !target.trim() || isScanning
              ? 'bg-surface-hover text-gray-500 cursor-not-allowed'
              : 'bg-neon text-oled hover:bg-[#00cce6]'
          }`}
        >
          <AnimatePresence mode="wait">
            {isScanning ? (
              <motion.span
                key="scanning"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex items-center gap-3"
              >
                <motion.span
                  className="inline-block w-5 h-5 border-2 border-current border-t-transparent rounded-full"
                  animate={{ rotate: 360 }}
                  transition={{ duration: 0.8, repeat: Infinity, ease: 'linear' }}
                />
                SCANNING...
              </motion.span>
            ) : (
              <motion.span
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                INITIALIZE SCAN
              </motion.span>
            )}
          </AnimatePresence>
        </motion.button>
      </div>

      {/* Terminal output block */}
      <div
        className={`flex-1 bg-oled border rounded-xl p-5 font-mono text-sm overflow-y-auto max-w-4xl min-h-[280px] transition-colors ${
          hasError ? 'border-red-500/40' : 'border-white/10'
        }`}
      >
        {renderTerminal()}
      </div>
    </div>
  );
}
