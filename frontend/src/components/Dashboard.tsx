import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { fetchDashboardStats } from '../api';

interface DashboardData {
  counts: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  compliance: Record<string, string>;
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardData | null>(null);

  useEffect(() => {
    fetchDashboardStats().then((data: any) => setStats(data));
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
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <div className="w-full h-full p-8 overflow-y-auto">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">SYSTEM <span className="text-neon">OVERVIEW</span></h1>
      
      {stats ? (
        <motion.div 
          className="flex flex-col gap-8 max-w-4xl"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          <div className="grid grid-cols-2 gap-6">
            <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
              <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Critical Threats</h2>
              <div className="text-6xl font-bold text-danger">{stats.counts.CRITICAL || 0}</div>
            </motion.div>
            
            <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
              <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">High Severity</h2>
              <div className="text-6xl font-bold text-warning">{stats.counts.HIGH || 0}</div>
            </motion.div>
            
            <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
              <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Medium Issues</h2>
              <div className="text-6xl font-bold text-white">{stats.counts.MEDIUM || 0}</div>
            </motion.div>
            
            <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
              <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Low Priority</h2>
              <div className="text-6xl font-bold text-success">{stats.counts.LOW || 0}</div>
            </motion.div>
          </div>

          {stats.compliance && Object.keys(stats.compliance).length > 0 && (
            <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl">
              <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-4">Compliance Status</h2>
              <div className="flex flex-col gap-3">
                {Object.entries(stats.compliance).map(([framework, status]) => (
                  <div key={framework} className="flex justify-between items-center p-3 bg-black/40 rounded border border-white/5">
                    <span className="text-white font-medium">{framework}</span>
                    <span className={`px-3 py-1 rounded text-xs font-bold uppercase ${status === 'Passing' ? 'bg-success/20 text-success' : 'bg-danger/20 text-danger'}`}>
                      {status}
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </motion.div>
      ) : (
        <div className="text-neon animate-pulse">Initializing telemetry...</div>
      )}
    </div>
  );
}
