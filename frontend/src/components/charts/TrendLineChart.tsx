import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { motion } from 'framer-motion';

export default function TrendLineChart({ data }: { data: { date: string, count: number }[] }) {
  // Format date for better readability
  const formattedData = data.map(item => ({
    ...item,
    displayDate: new Date(item.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  }));

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 }}
      className="bg-surface border border-white/10 rounded-xl p-6 shadow-2xl h-full flex flex-col"
    >
      <h3 className="text-sm font-semibold tracking-widest text-gray-400 mb-6 uppercase">Historical Trends</h3>
      
      <div className="flex-1 w-full min-h-[250px]">
        {formattedData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={formattedData} margin={{ top: 5, right: 20, bottom: 5, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis 
                dataKey="displayDate" 
                stroke="#666" 
                tick={{ fill: '#666', fontSize: 12 }} 
                tickLine={false}
                axisLine={false}
                dy={10}
              />
              <YAxis 
                stroke="#666" 
                tick={{ fill: '#666', fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{ 
                  backgroundColor: '#0a0a0a', 
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
                }}
                itemStyle={{ color: '#00E5FF' }}
                labelStyle={{ color: '#9ca3af', marginBottom: '4px' }}
              />
              <Line 
                type="monotone" 
                dataKey="count" 
                name="Vulnerabilities"
                stroke="#00E5FF" 
                strokeWidth={3}
                dot={{ r: 4, fill: '#0a0a0a', stroke: '#00E5FF', strokeWidth: 2 }}
                activeDot={{ r: 6, fill: '#00E5FF', stroke: '#fff', strokeWidth: 2 }}
                style={{ filter: 'drop-shadow(0 0 8px rgba(0, 229, 255, 0.5))' }}
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500 text-sm tracking-widest uppercase">
            No historical data
          </div>
        )}
      </div>
    </motion.div>
  );
}
