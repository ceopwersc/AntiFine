import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Download, Play, Copy, Terminal, X, Check, Search, Shield, ShieldQuestion, ChevronRight, Activity } from 'lucide-react';
import { runScan, generateReport } from '../api';

interface Finding {
  rule_name: string;
  severity: string;
  compliance_framework: string;
  frameworks: string[];
  description: string;
  remediation: string;
}

export default function Dashboard() {
  const [target, setTarget] = useState<string>('k8s_test.yaml');
  const [isScanning, setIsScanning] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!target.trim()) return;
    setIsScanning(true);
    setError(null);
    try {
      const res = await runScan(target, 'IaC Config Audit');
      if (res.findings) {
        setFindings(res.findings);
      } else {
        setFindings([]);
      }
      setFilterSeverity(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? 'Scan failed.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleExportSarif = async () => {
    setIsExporting(true);
    try {
      const res = await generateReport('sarif');
      if (res.downloadUrl) {
        const a = document.createElement('a');
        a.href = res.downloadUrl;
        a.download = 'scan_results.sarif';
        a.click();
      }
    } catch (err: any) {
      setError(err?.message ?? 'Export failed.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityColors = (sev: string) => {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL') return 'text-rose-400 bg-rose-950/50 border-rose-800';
    if (s === 'HIGH') return 'text-amber-400 bg-amber-950/50 border-amber-800';
    if (s === 'MEDIUM') return 'text-yellow-400 bg-yellow-950/50 border-yellow-800';
    return 'text-sky-400 bg-sky-950/50 border-sky-800';
  };

  // Compute KPIs
  const kpis = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => {
      const s = f.severity.toUpperCase();
      if (s in counts) counts[s as keyof typeof counts]++;
      else counts.INFO++;
    });
    
    // Weighting: C=4, H=3, M=2, L=1
    const totalViolations = counts.CRITICAL * 4 + counts.HIGH * 3 + counts.MEDIUM * 2 + (counts.LOW + counts.INFO) * 1;
    const maxViolations = 100; // Arbitrary scale for demo
    const score = Math.max(0, 100 - (totalViolations / maxViolations) * 100);

    return { counts, score: Math.round(score) };
  }, [findings]);

  const filteredFindings = useMemo(() => {
    if (!filterSeverity) return findings;
    return findings.filter(f => f.severity.toUpperCase() === filterSeverity.toUpperCase());
  }, [findings, filterSeverity]);

  const toggleFilter = (sev: string) => {
    if (filterSeverity === sev) setFilterSeverity(null);
    else setFilterSeverity(sev);
  };

  return (
    <div className="w-full h-full p-8 overflow-y-auto bg-[#0b0f19] text-slate-200">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide flex items-center gap-3">
        <ShieldAlert className="w-8 h-8 text-rose-500" />
        REMEDIATION <span className="text-indigo-400">WORKSPACE</span>
      </h1>

      {/* Target Scan Bar */}
      <div className="sticky top-0 z-10 bg-slate-950/80 backdrop-blur-md border border-slate-800 rounded-xl p-4 mb-8 flex flex-wrap items-center gap-4 shadow-lg shadow-black/50">
        <div className="flex-1 min-w-[200px] flex items-center bg-slate-900 border border-slate-800 rounded-lg px-3 py-2">
          <Search className="w-5 h-5 text-slate-500 mr-2" />
          <input 
            type="text" 
            className="bg-transparent border-none outline-none text-slate-200 w-full font-mono placeholder:text-slate-600"
            placeholder="Target Path / Filename (e.g. infra_test.tf, k8s_test.yaml)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>
        <button 
          onClick={handleScan}
          disabled={isScanning || !target}
          className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-lg transition-colors disabled:opacity-50"
        >
          {isScanning ? (
            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <Play className="w-5 h-5 fill-current" />
          )}
          Scan Target
        </button>
        <button 
          onClick={handleExportSarif}
          disabled={isExporting}
          className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold rounded-lg transition-colors disabled:opacity-50"
        >
          {isExporting ? (
            <div className="w-5 h-5 border-2 border-slate-400 border-t-white rounded-full animate-spin" />
          ) : (
            <Download className="w-5 h-5" />
          )}
          Export SARIF
        </button>
      </div>

      {error && (
        <div className="mb-8 p-4 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-400 font-mono text-sm flex items-center gap-3">
          <ShieldAlert className="w-5 h-5" />
          {error}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <div className="lg:col-span-1 p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center items-center">
          <div className="text-slate-400 text-sm font-semibold mb-2 uppercase tracking-wider">Compliance Score</div>
          <div className={`text-5xl font-black ${kpis.score > 80 ? 'text-emerald-400' : kpis.score > 50 ? 'text-amber-400' : 'text-rose-500'}`}>
            {kpis.score}%
          </div>
        </div>

        <div className="lg:col-span-4 grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'CRITICAL', count: kpis.counts.CRITICAL, colors: 'text-rose-400 bg-rose-950/30 border-rose-800/50 hover:bg-rose-950/60 hover:border-rose-700' },
            { label: 'HIGH', count: kpis.counts.HIGH, colors: 'text-amber-400 bg-amber-950/30 border-amber-800/50 hover:bg-amber-950/60 hover:border-amber-700' },
            { label: 'MEDIUM', count: kpis.counts.MEDIUM, colors: 'text-yellow-400 bg-yellow-950/30 border-yellow-800/50 hover:bg-yellow-950/60 hover:border-yellow-700' },
            { label: 'LOW/INFO', count: kpis.counts.LOW + kpis.counts.INFO, colors: 'text-sky-400 bg-sky-950/30 border-sky-800/50 hover:bg-sky-950/60 hover:border-sky-700' },
          ].map((sev) => (
            <div 
              key={sev.label} 
              onClick={() => toggleFilter(sev.label.split('/')[0])}
              className={`p-6 rounded-xl border flex flex-col items-center justify-center cursor-pointer transition-all ${sev.colors} ${filterSeverity === sev.label.split('/')[0] ? 'ring-2 ring-current ring-offset-2 ring-offset-slate-950' : ''}`}
            >
              <div className="text-sm font-bold mb-2 uppercase tracking-wider opacity-80">{sev.label}</div>
              <div className="text-4xl font-black">{sev.count}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-400" />
            Active Findings
            {filterSeverity && <span className="text-xs px-2 py-1 bg-slate-800 rounded-full ml-2 text-slate-300">Filtered: {filterSeverity}</span>}
          </h2>
          <div className="text-sm text-slate-400 font-mono">{filteredFindings.length} Violations</div>
        </div>
        
        {filteredFindings.length === 0 ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center">
            <ShieldCheck className="w-16 h-16 text-emerald-500/50 mb-4" />
            <p className="text-lg">No findings to display.</p>
            <p className="text-sm mt-2">Run a scan or adjust filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/50 text-xs uppercase tracking-wider text-slate-400">
                  <th className="px-6 py-4 font-medium">Severity</th>
                  <th className="px-6 py-4 font-medium">Rule Name</th>
                  <th className="px-6 py-4 font-medium">Frameworks</th>
                  <th className="px-6 py-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredFindings.map((finding, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/50 transition-colors group cursor-pointer" onClick={() => setSelectedFinding(finding)}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded-md text-xs font-bold border ${getSeverityColors(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-medium text-slate-200">
                      {finding.rule_name}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-2">
                        {finding.frameworks.slice(0, 2).map((fw, fIdx) => (
                          <span key={fIdx} className="px-2 py-1 rounded bg-slate-800 text-slate-400 text-xs whitespace-nowrap">
                            {fw}
                          </span>
                        ))}
                        {finding.frameworks.length > 2 && (
                          <span className="px-2 py-1 rounded bg-slate-800 text-slate-500 text-xs">
                            +{finding.frameworks.length - 2} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="text-indigo-400 hover:text-indigo-300 font-medium text-sm flex items-center justify-end gap-1 ml-auto opacity-0 group-hover:opacity-100 transition-opacity">
                        Remediate <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Slide-over Drawer */}
      <AnimatePresence>
        {selectedFinding && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
              onClick={() => setSelectedFinding(null)}
            />
            <motion.div 
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: "spring", damping: 25, stiffness: 200 }}
              className="fixed top-0 right-0 h-full w-full max-w-2xl bg-slate-900 border-l border-slate-800 shadow-2xl z-50 overflow-y-auto flex flex-col"
            >
              {/* Header */}
              <div className="p-6 border-b border-slate-800 flex justify-between items-start bg-slate-950">
                <div className="flex flex-col gap-3">
                  <span className={`inline-block px-3 py-1 rounded-md text-xs font-bold border w-max ${getSeverityColors(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                  <h3 className="text-xl font-bold text-white leading-tight">
                    {selectedFinding.rule_name}
                  </h3>
                </div>
                <button 
                  onClick={() => setSelectedFinding(null)}
                  className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>

              {/* Content */}
              <div className="p-6 flex-1 flex flex-col gap-8">
                <div>
                  <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <ShieldQuestion className="w-4 h-4" /> Violation Context
                  </h4>
                  <p className="text-slate-300 leading-relaxed text-sm">
                    {selectedFinding.description}
                  </p>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <Shield className="w-4 h-4" /> Framework Mapping
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedFinding.frameworks.map((fw, idx) => (
                      <span key={idx} className="px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 text-slate-300 text-xs">
                        {fw}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-auto">
                  <div className="flex justify-between items-end mb-3">
                    <h4 className="text-sm font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      <Terminal className="w-4 h-4" /> Drop-In Remediation
                    </h4>
                    <button 
                      onClick={() => handleCopy(selectedFinding.remediation)}
                      className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                    >
                      {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                      {copied ? 'Copied!' : 'Copy Code'}
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#030712] border border-slate-800 text-slate-300 font-mono text-sm overflow-x-auto">
                    <code>{selectedFinding.remediation}</code>
                  </pre>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
