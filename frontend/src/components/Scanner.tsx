import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { runScan } from '../api';

export default function Scanner() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('SSRF Web Audit');
  const [logs, setLogs] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [hasError, setHasError] = useState(false);

  const handleScan = async () => {
    if (!target.trim()) return;

    // Strip leading/trailing quotation marks from the target before firing
    const cleanTarget = target.replace(/^["']|["']$/g, '').trim();

    setIsScanning(true);
    setHasError(false);
    setLogs('[INFO] Initializing connection parameters...\n[INFO] Routing request to backend engine...\n');

    try {
      const result: any = await runScan(cleanTarget, scanType);

      // Backend returns { status, message } — render that in the terminal
      const statusLine = `[${result.status?.toUpperCase() ?? 'INFO'}] ${result.message ?? 'Scan completed.'}`;
      setLogs(prev => prev + statusLine);
    } catch (err: any) {
      setHasError(true);
      // Surface structured backend error detail if available, otherwise raw message
      const detail =
        err?.response?.data?.detail ?? err?.message ?? 'Unknown error.';
      setLogs(
        prev =>
          prev +
          `[ERROR] Request failed.\n[DETAIL] ${detail}\n[HINT] Ensure the backend is running on http://localhost:8000`
      );
    } finally {
      setIsScanning(false);
    }
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
                {/* Pulsing spinner */}
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
        className={`flex-1 bg-oled border rounded-xl p-4 font-mono text-sm overflow-y-auto max-w-4xl min-h-[200px] transition-colors ${
          hasError ? 'border-red-500/40 text-red-400' : 'border-white/10 text-green-400'
        }`}
      >
        {isScanning ? (
          <motion.div
            className="flex flex-col gap-1"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <span className="whitespace-pre-wrap">{logs}</span>
            <motion.span
              animate={{ opacity: [1, 0.2, 1] }}
              transition={{ duration: 1, repeat: Infinity }}
              className="text-neon"
            >
              ▌ Awaiting engine response...
            </motion.span>
          </motion.div>
        ) : logs ? (
          <span className="whitespace-pre-wrap">{logs}</span>
        ) : (
          <span className="text-gray-600">&gt; System ready. Awaiting coordinates.</span>
        )}
      </div>
    </div>
  );
}
