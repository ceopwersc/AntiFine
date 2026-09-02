import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { fetchAnalyticsDashboard } from '../api';
import ComplianceGauge from './charts/ComplianceGauge';
import SeverityPieChart from './charts/SeverityPieChart';
import TrendLineChart from './charts/TrendLineChart';

interface AnalyticsData {
  status: string;
  overall_compliance_score: number;
  severity_breakdown: { name: string; value: number }[];
  historical_trends: { date: string; count: number }[];
}

// Fallback empty-state so charts never receive undefined props
const DEFAULT_ANALYTICS: AnalyticsData = {
  status: 'ok',
  overall_compliance_score: 100,
  severity_breakdown: [
    { name: 'Critical', value: 0 },
    { name: 'High', value: 0 },
    { name: 'Medium', value: 0 },
    { name: 'Low', value: 0 },
  ],
  historical_trends: [],
};

export default function Dashboard() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchAnalyticsDashboard()
      .then((data: any) => setAnalytics(data))
      .catch((err: any) => {
        console.error(err);
        // Surface a readable error and fall back to default so charts render
        const detail =
          err?.response?.data?.detail ?? err?.message ?? 'Unknown error.';
        setError(`Backend unreachable — ${detail}`);
        setAnalytics(DEFAULT_ANALYTICS);
      });
  }, []);

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 300, damping: 24 } }
  };

  return (
    <div className="w-full h-full p-8 overflow-y-auto">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">EXECUTIVE <span className="text-neon">ANALYTICS</span></h1>

      {/* Error banner — shown when backend is down but charts still render with defaults */}
      {error && (
        <div className="max-w-5xl mb-6 px-4 py-3 rounded-lg bg-red-950/40 border border-red-500/30 text-red-400 text-sm font-mono flex items-center gap-3">
          <span className="text-red-500">⚠</span>
          {error}
          <span className="text-red-600 ml-auto text-xs">Displaying default state</span>
        </div>
      )}

      {analytics ? (
        <motion.div
          className="flex flex-col gap-8 max-w-5xl"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          {/* Top row: Compliance Gauge */}
          <motion.div variants={itemVariants} className="w-full">
            <ComplianceGauge score={analytics.overall_compliance_score} />
          </motion.div>

          {/* Bottom row: Pie Chart and Trend Line */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <motion.div variants={itemVariants} className="w-full h-96">
              <SeverityPieChart data={analytics.severity_breakdown} />
            </motion.div>

            <motion.div variants={itemVariants} className="w-full h-96">
              <TrendLineChart data={analytics.historical_trends} />
            </motion.div>
          </div>
        </motion.div>
      ) : (
        <div className="text-neon animate-pulse flex items-center gap-3">
          <div className="w-4 h-4 border-2 border-neon border-t-transparent rounded-full animate-spin" />
          Initializing telemetry...
        </div>
      )}
    </div>
  );
}
