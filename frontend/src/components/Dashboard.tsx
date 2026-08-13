import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { fetchDashboardStats } from '../api';

export default function Dashboard() {
  const [stats, setStats] = useState<{ critical: number; high: number; medium: number; low: number } | null>(null);

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
    <div className="w-full h-full p-8">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">SYSTEM <span className="text-neon">OVERVIEW</span></h1>
      
      {stats ? (
        <motion.div 
          className="grid grid-cols-2 gap-6 max-w-4xl"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
            <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Critical Threats</h2>
            <div className="text-6xl font-bold text-danger">{stats.critical}</div>
          </motion.div>
          
          <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
            <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">High Severity</h2>
            <div className="text-6xl font-bold text-warning">{stats.high}</div>
          </motion.div>
          
          <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
            <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Medium Issues</h2>
            <div className="text-6xl font-bold text-white">{stats.medium}</div>
          </motion.div>
          
          <motion.div variants={itemVariants} className="bg-surface border border-white/10 p-6 rounded-xl flex flex-col items-center justify-center">
            <h2 className="text-gray-400 text-sm uppercase tracking-widest mb-2">Low Priority</h2>
            <div className="text-6xl font-bold text-success">{stats.low}</div>
          </motion.div>
        </motion.div>
      ) : (
        <div className="text-neon animate-pulse">Initializing telemetry...</div>
      )}
    </div>
  );
}
