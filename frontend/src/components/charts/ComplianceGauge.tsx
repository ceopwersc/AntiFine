import { motion } from 'framer-motion';

export default function ComplianceGauge({ score }: { score: number }) {
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  let color = '#ff3333'; // Danger (bg-danger)
  if (score >= 80) color = '#00cc66'; // Success (bg-success)
  else if (score >= 50) color = '#ffaa00'; // Warning (bg-warning)

  return (
    <div className="flex flex-col items-center justify-center p-6 bg-surface border border-white/10 rounded-xl relative overflow-hidden group shadow-2xl h-full">
      <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
      
      <h3 className="text-sm font-semibold tracking-widest text-gray-400 mb-6 uppercase">Enterprise Compliance Score</h3>
      
      <div className="relative flex items-center justify-center">
        {/* Background track */}
        <svg className="w-40 h-40 transform -rotate-90">
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="12"
            fill="transparent"
          />
          {/* Animated score ring */}
          <motion.circle
            cx="80"
            cy="80"
            r={radius}
            stroke={color}
            strokeWidth="12"
            fill="transparent"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.5, ease: "easeOut" }}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 8px ${color})` }}
          />
        </svg>
        
        <div className="absolute flex flex-col items-center justify-center">
          <motion.span 
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            className="text-4xl font-black tracking-tighter"
            style={{ color }}
          >
            {score}
          </motion.span>
          <span className="text-xs text-gray-500 font-medium mt-1">/ 100</span>
        </div>
      </div>
      
      <div className="mt-6 flex gap-6 text-xs font-bold tracking-wider text-gray-500 uppercase">
        <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full" style={{ backgroundColor: '#00cc66' }}></div> Passing</div>
        <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full" style={{ backgroundColor: '#ffaa00' }}></div> Warning</div>
        <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full" style={{ backgroundColor: '#ff3333' }}></div> Critical</div>
      </div>
    </div>
  );
}
