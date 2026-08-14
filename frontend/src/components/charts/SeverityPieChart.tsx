import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';

const COLORS = {
  Critical: '#ff3333',
  High: '#ffaa00',
  Medium: '#ffffff',
  Low: '#00cc66'
};

export default function SeverityPieChart({ data }: { data: { name: string, value: number }[] }) {
  // Filter out empty data for cleaner pie chart
  const activeData = data.filter(item => item.value > 0);

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="bg-surface border border-white/10 rounded-xl p-6 shadow-2xl h-full flex flex-col"
    >
      <h3 className="text-sm font-semibold tracking-widest text-gray-400 mb-6 uppercase">Severity Breakdown</h3>
      
      <div className="flex-1 w-full min-h-[250px]">
        {activeData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={activeData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
                stroke="none"
              >
                {activeData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={COLORS[entry.name as keyof typeof COLORS] || COLORS.Low} 
                    style={{ filter: `drop-shadow(0 0 4px ${COLORS[entry.name as keyof typeof COLORS]})` }}
                  />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#0a0a0a', 
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
                }}
                itemStyle={{ color: '#fff' }}
              />
              <Legend 
                verticalAlign="bottom" 
                height={36}
                formatter={(value) => <span className="text-gray-400 text-xs tracking-wider uppercase ml-1">{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500 text-sm tracking-widest uppercase">
            No active vulnerabilities
          </div>
        )}
      </div>
    </motion.div>
  );
}
