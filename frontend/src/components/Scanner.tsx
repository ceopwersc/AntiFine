import { useState } from 'react';
import { motion } from 'framer-motion';
import { runScan } from '../api';

export default function Scanner() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('SSRF Web Audit');
  const [logs, setLogs] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = async () => {
    if (!target) return;
    setIsScanning(true);
    setLogs('[INFO] Initializing connection parameters...\n');
    
    try {
      const result: any = await runScan(target, scanType);
      setLogs(prev => prev + result.logs);
    } catch (e) {
      setLogs(prev => prev + '\n[ERROR] Failed to execute scan.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="w-full h-full p-8 flex flex-col">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">WAR <span className="text-neon">ROOM</span></h1>
      
      <div className="bg-surface border border-white/10 p-6 rounded-xl max-w-4xl mb-6 flex flex-col gap-4">
        <div>
          <label className="block text-gray-400 text-sm uppercase tracking-widest mb-2">Target Interface</label>
          <input 
            type="text" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. http://10.0.0.5/api or ./k8s/deployment.yaml"
            className="w-full bg-oled border border-white/20 rounded p-3 text-white focus:outline-none focus:border-neon transition-colors font-mono"
          />
        </div>

        <div>
          <label className="block text-gray-400 text-sm uppercase tracking-widest mb-2">Audit Protocol</label>
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
          disabled={!target || isScanning}
          whileHover={{ scale: target && !isScanning ? 1.02 : 1, boxShadow: target && !isScanning ? "0px 0px 15px #00E5FF" : "none" }}
          whileTap={{ scale: target && !isScanning ? 0.98 : 1 }}
          className={`mt-4 w-full py-4 rounded font-bold text-xl tracking-widest transition-colors ${
            !target || isScanning ? 'bg-surface-hover text-gray-500 cursor-not-allowed' : 'bg-neon text-oled hover:bg-[#00cce6]'
          }`}
        >
          {isScanning ? 'EXECUTING...' : 'INITIALIZE SCAN'}
        </motion.button>
      </div>

      <div className="flex-1 bg-oled border border-white/10 rounded-xl p-4 font-mono text-sm text-green-400 overflow-y-auto max-w-4xl min-h-[200px]">
        {logs || '> System ready. Awaiting coordinates.'}
      </div>
    </div>
  );
}
