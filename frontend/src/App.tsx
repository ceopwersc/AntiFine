import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { LayoutDashboard, Shield, FileText, Webhook } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import Reports from './components/Reports';
import Integrations from './components/Integrations';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'War Room', icon: Shield },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'integrations', label: 'Integrations', icon: Webhook },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard': return <Dashboard key="dashboard" />;
      case 'scanner': return <Scanner key="scanner" />;
      case 'reports': return <Reports key="reports" />;
      case 'integrations': return <Integrations key="integrations" />;
      default: return null;
    }
  };

  return (
    <div className="flex h-screen w-full bg-oled text-white overflow-hidden font-sans">
      {/* Sidebar */}
      <div className="w-20 md:w-64 bg-surface border-r border-white/10 flex flex-col pt-8 z-10 shadow-2xl">
        <div className="px-4 md:px-8 mb-12 hidden md:block">
          <h1 className="text-xl font-bold tracking-widest text-white">
            ANTI<span className="text-neon">FINE</span>
          </h1>
          <div className="h-[1px] w-full bg-gradient-to-r from-neon to-transparent mt-2 opacity-50"></div>
        </div>
        
        <div className="flex flex-col gap-2 relative">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative flex items-center gap-4 py-4 px-6 md:px-8 w-full transition-colors ${
                  isActive ? 'text-neon' : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeTabIndicator"
                    className="absolute left-0 top-0 bottom-0 w-1 bg-neon shadow-[0_0_10px_#00E5FF]"
                    initial={false}
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                  />
                )}
                <Icon size={24} className={isActive ? 'drop-shadow-[0_0_8px_#00E5FF]' : ''} />
                <span className="hidden md:inline font-semibold tracking-wider">{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-auto relative">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,_var(--color-surface),_transparent_40%)] pointer-events-none" />
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
            className="w-full h-full relative z-10"
          >
            {renderContent()}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
