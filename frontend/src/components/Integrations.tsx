import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Webhook, CheckCircle2, AlertTriangle, Radio } from 'lucide-react';
import { getWebhooks, saveWebhook, testWebhook } from '../api';

export default function Integrations() {
  const [url, setUrl] = useState('');
  const [minSeverity, setMinSeverity] = useState('HIGH');
  const [status, setStatus] = useState<{ type: 'idle' | 'loading' | 'success' | 'error'; message: string }>({ type: 'idle', message: '' });

  useEffect(() => {
    getWebhooks().then((data) => {
      if (data.webhooks && data.webhooks.length > 0) {
        setUrl(data.webhooks[0].url);
        setMinSeverity(data.webhooks[0].min_severity);
      }
    }).catch(err => console.error(err));
  }, []);

  const handleSave = async () => {
    if (!url) return;
    setStatus({ type: 'loading', message: 'Saving configuration...' });
    try {
      await saveWebhook(url, minSeverity);
      setStatus({ type: 'success', message: 'Webhook configuration saved successfully.' });
    } catch (err: any) {
      setStatus({ type: 'error', message: err.message || 'Failed to save configuration.' });
    }
  };

  const handleTest = async () => {
    if (!url) return;
    setStatus({ type: 'loading', message: 'Pinging webhook endpoint...' });
    try {
      await testWebhook(url);
      setStatus({ type: 'success', message: 'Test alert dispatched to webhook!' });
    } catch (err: any) {
      setStatus({ type: 'error', message: err.message || 'Failed to dispatch test alert.' });
    }
  };

  return (
    <div className="w-full h-full p-8 overflow-y-auto">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">SOC <span className="text-neon">INTEGRATIONS</span></h1>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-3xl bg-surface border border-white/10 p-8 rounded-xl shadow-2xl"
      >
        <div className="flex items-center gap-3 mb-6">
          <Webhook className="text-neon" size={28} />
          <h2 className="text-xl font-bold text-white tracking-widest">WEBHOOK PIPELINE</h2>
        </div>

        <p className="text-gray-400 mb-8 leading-relaxed">
          Configure external targets (SIEM/SOAR, Slack, Discord) to receive automated JSON security alerts when a scan detects high-severity vulnerabilities or compliance failures.
        </p>

        <div className="space-y-6">
          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-500 mb-2">Endpoint URL</label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://webhook.site/..."
              className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-white focus:outline-none focus:border-neon transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-widest text-gray-500 mb-2">Minimum Severity Threshold</label>
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
              className="w-full bg-black/50 border border-white/10 rounded-lg p-3 text-white focus:outline-none focus:border-neon transition-colors appearance-none"
            >
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High & Critical</option>
              <option value="ALL">All Severities</option>
            </select>
          </div>

          <div className="flex gap-4 pt-4 border-t border-white/5">
            <button
              onClick={handleSave}
              className="px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-white font-medium transition-colors"
            >
              Save Configuration
            </button>
            <button
              onClick={handleTest}
              className="px-6 py-3 bg-neon/20 hover:bg-neon/30 border border-neon/50 text-neon rounded-lg font-bold tracking-wide transition-colors flex items-center gap-2 group"
            >
              <Radio size={18} className="group-hover:animate-ping" />
              Test Webhook Ping
            </button>
          </div>
        </div>

        {status.type !== 'idle' && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className={`mt-6 p-4 rounded-lg flex items-center gap-3 border ${
              status.type === 'error' ? 'bg-danger/10 border-danger/20 text-danger' : 
              status.type === 'success' ? 'bg-success/10 border-success/20 text-success' : 
              'bg-white/5 border-white/10 text-gray-300'
            }`}
          >
            {status.type === 'error' && <AlertTriangle size={18} />}
            {status.type === 'success' && <CheckCircle2 size={18} />}
            {status.type === 'loading' && <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />}
            <span className="text-sm font-medium">{status.message}</span>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}
