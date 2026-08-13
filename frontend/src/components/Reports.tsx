import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { generateReport } from '../api';

export default function Reports() {
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const handleGenerate = async (format: string) => {
    try {
      const result: any = await generateReport(format);
      setToastMessage(result.message);
      setTimeout(() => setToastMessage(null), 3000);
    } catch (e) {
      setToastMessage('Error generating report');
      setTimeout(() => setToastMessage(null), 3000);
    }
  };

  return (
    <div className="w-full h-full p-8 relative">
      <h1 className="text-3xl font-bold mb-8 text-white tracking-wide">COMPLIANCE <span className="text-neon">REPORTS</span></h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl">
        <div className="bg-surface border border-white/10 p-8 rounded-xl flex flex-col items-center text-center gap-4">
          <h2 className="text-xl font-bold text-white">Markdown Report</h2>
          <p className="text-gray-400 text-sm">Human-readable summary of all findings for executive review.</p>
          <motion.button 
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => handleGenerate('markdown')}
            className="mt-4 px-6 py-2 bg-white/10 hover:bg-white/20 border border-white/30 rounded text-white transition-colors"
          >
            Generate Markdown
          </motion.button>
        </div>

        <div className="bg-surface border border-white/10 p-8 rounded-xl flex flex-col items-center text-center gap-4">
          <h2 className="text-xl font-bold text-white">SARIF Export</h2>
          <p className="text-gray-400 text-sm">Machine-readable format for CI/CD integration and automated parsing.</p>
          <motion.button 
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => handleGenerate('sarif')}
            className="mt-4 px-6 py-2 bg-neon/20 hover:bg-neon/30 border border-neon/50 rounded text-neon transition-colors"
          >
            Export SARIF
          </motion.button>
        </div>
      </div>

      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: 50, x: '-50%' }}
            animate={{ opacity: 1, y: 0, x: '-50%' }}
            exit={{ opacity: 0, y: 50, x: '-50%' }}
            className="absolute bottom-8 left-1/2 bg-success text-oled px-6 py-3 rounded shadow-[0_0_15px_#00FF66] font-bold tracking-wide"
          >
            {toastMessage}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
