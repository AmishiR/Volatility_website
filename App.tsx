import React, { useState, useMemo } from 'react';
import { Terminal, ShieldAlert, Cpu, Network, FileCode, Activity, HardDrive, Database, Key, Layers, GitMerge } from 'lucide-react'; // Added GitMerge icon
import ReactMarkdown from 'react-markdown';
import { motion, AnimatePresence } from 'framer-motion';

import { PLUGINS, INITIAL_CONTENT, PREDEFINED_PLUGIN_CONTENT, PluginDef } from './constants';
import { explainPlugin } from './services/geminiService';
import RetroButton from './components/RetroButton';
import ScanlineOverlay from './components/ScanlineOverlay';
import HexViewer from './components/HexViewer';
import VolatilityLoader from './components/VolatilityLoader';

const App: React.FC = () => {
  const [loadingApp, setLoadingApp] = useState<boolean>(true);
  const [selectedPlugin, setSelectedPlugin] = useState<PluginDef | null>(null);
  const [content, setContent] = useState<string>(INITIAL_CONTENT);
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [loadingContent, setLoadingContent] = useState<boolean>(false);
  const [activeCategory, setActiveCategory] = useState<string | null>('Networking');

  // Group plugins by category
  const categories = useMemo(() => {
    return Array.from(new Set(PLUGINS.map(p => p.category)));
  }, []);

  const groupedPlugins = useMemo(() => {
    return categories.reduce((acc, cat) => {
      acc[cat] = PLUGINS.filter(p => p.category === cat);
      return acc;
    }, {} as Record<string, PluginDef[]>);
  }, [categories]);

  // Handle typing effect for content
  const loadContentWithEffect = (text: string) => {
    let i = 0;
    setIsTyping(true);
    const speed = 1; 
    const typeWriter = () => {
      if (i < text.length) {
        setContent(text.substring(0, i + 1));
        i++;
        setTimeout(typeWriter, speed);
      } else {
        setIsTyping(false);
      }
    };
    typeWriter();
  };

  const handlePluginClick = async (plugin: PluginDef) => {
    if (selectedPlugin?.name === plugin.name && !loadingContent) return;
    
    setSelectedPlugin(plugin);
    setLoadingContent(true);
    setContent(''); 
    
    let explanation = '';
    if (PREDEFINED_PLUGIN_CONTENT[plugin.name]) {
      explanation = PREDEFINED_PLUGIN_CONTENT[plugin.name];
      await new Promise(resolve => setTimeout(resolve, 300)); 
    } else {
      explanation = await explainPlugin(plugin.name);
    }

    setLoadingContent(false);
    loadContentWithEffect(explanation);
  };

  // NEW: Handler for the Methodology Button
  const handleMethodologyClick = () => {
    setLoadingContent(true);
    setContent('');
    setTimeout(() => {
        setLoadingContent(false);
        loadContentWithEffect(PREDEFINED_PLUGIN_CONTENT["Methodology"]);
    }, 400);
  };

  const resetHome = () => {
    setSelectedPlugin(null);
    setContent(INITIAL_CONTENT);
  };

  const getCategoryIcon = (category: string) => {
     if (category.includes('Malware')) return <ShieldAlert className="w-4 h-4" />;
     if (category.includes('Network')) return <Network className="w-4 h-4" />;
     if (category.includes('Process')) return <Activity className="w-4 h-4" />;
     if (category.includes('Registry')) return <Database className="w-4 h-4" />;
     if (category.includes('Memory')) return <Layers className="w-4 h-4" />;
     if (category.includes('Users')) return <Key className="w-4 h-4" />;
     return <Cpu className="w-4 h-4" />;
  };

  return (
    <>
      <AnimatePresence mode="wait">
        {loadingApp ? (
          <VolatilityLoader key="loader" onComplete={() => setLoadingApp(false)} />
        ) : (
          <motion.div 
            key="main-app"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
            className="min-h-screen text-[#33ff33] selection:bg-[#33ff33] selection:text-black overflow-hidden relative flex flex-col font-mono"
          >
            <ScanlineOverlay />
            
            <nav className="h-14 border-b-2 border-[#33ff33] bg-[#020402] flex items-center justify-between px-6 z-20 shrink-0">
              <div className="flex items-center gap-4">
                <div className="w-8 h-8 bg-[#33ff33] flex items-center justify-center text-black font-bold text-xl">V</div>
                <h1 className="text-2xl font-bold tracking-wider uppercase">Volatility 3</h1>
              </div>
              <div className="flex gap-6 text-sm opacity-80">
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div> ONLINE</div>
                <div className="hidden sm:block">MEM: 4096MB</div>
                <div className="hidden sm:block">SESSION: 0x89AF</div>
              </div>
            </nav>

            <div className="flex-1 flex overflow-hidden relative z-10 p-4 gap-4">
              
              <aside className="w-72 flex flex-col gap-4 shrink-0 hidden md:flex">
                <div className="bg-[#001100] border border-[#33ff33] flex-1 flex flex-col overflow-hidden box-glow">
                  <div className="p-2 border-b border-[#33ff33] bg-[#002200] font-bold flex items-center gap-2">
                    <HardDrive className="w-4 h-4" /> PLUGINS_DIR
                  </div>
                  
                  <div className="overflow-y-auto p-2 flex-1 scrollbar-hide">
                    {categories.map(cat => (
                      <div key={cat} className="mb-4">
                        <button 
                          onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                          className="w-full text-left uppercase font-bold text-[#ccffcc] mb-1 flex items-center justify-between hover:bg-[#113311] p-1 border-b border-[#33ff33] border-opacity-30 pb-1"
                        >
                          <div className="flex items-center gap-2 text-xs tracking-wider">
                            {getCategoryIcon(cat)} {cat.toUpperCase()}
                          </div>
                          <span className="text-xs">{activeCategory === cat ? '[-]' : '[+]'}</span>
                        </button>
                        
                        {activeCategory === cat && (
                          <div className="pl-4 border-l border-[#33ff33] ml-2 space-y-1 mt-1">
                            {groupedPlugins[cat].map(plugin => (
                              <button
                                key={plugin.name}
                                onClick={() => handlePluginClick(plugin)}
                                className={`
                                  block w-full text-left text-sm truncate px-2 py-1
                                  ${selectedPlugin?.name === plugin.name 
                                    ? 'bg-[#33ff33] text-black font-bold' 
                                    : 'hover:text-[#fff] hover:translate-x-1 transition-transform opacity-70 hover:opacity-100'}
                                `}
                              >
                                {plugin.name}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </aside>

              <main className="flex-1 flex flex-col gap-4 overflow-hidden">
                <div className="flex-1 border-2 border-[#33ff33] bg-[#000900] relative flex flex-col shadow-[0_0_15px_rgba(51,255,51,0.15)]">
                  
                  <div className="h-8 bg-[#33ff33] flex items-center justify-between px-2 shrink-0">
                     <span className="text-black font-bold uppercase flex items-center gap-2 text-sm">
                       <Terminal className="w-4 h-4" /> 
                       {selectedPlugin ? `ROOT@VOL3:~/${selectedPlugin.name.toUpperCase()}` : 'ROOT@VOL3:~/HOME'}
                     </span>
                     <div className="flex gap-1">
                       <button onClick={resetHome} className="w-3 h-3 bg-red-900 border border-black hover:bg-red-600"></button>
                     </div>
                  </div>

                  <div className="flex-1 overflow-y-auto p-6 font-mono relative">
                     {loadingContent ? (
                      <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#000900] z-20 opacity-90">
                         <div className="text-xl animate-pulse mb-2 tracking-widest">EXECUTING PLUGIN...</div>
                         <div className="w-64 h-2 border border-[#33ff33] p-0.5">
                           <div className="h-full bg-[#33ff33] animate-[width_1s_ease-in-out_infinite]" style={{width: '0%'}}></div>
                         </div>
                      </div>
                    ) : (
                      <div className="prose prose-invert prose-p:text-[#33ff33] prose-headings:text-[#ccffcc] prose-code:text-[#ffff00] prose-pre:bg-[#111] max-w-none text-sm md:text-base">
                        <ReactMarkdown
                          components={{
                            h1: ({node, ...props}) => <h1 className="text-2xl font-bold border-b border-[#33ff33] pb-2 mb-4 uppercase text-white" {...props} />,
                            h2: ({node, ...props}) => <h2 className="text-lg font-bold mt-6 mb-2 text-[#ffff00] flex items-center gap-2" {...props}><span className="text-[#33ff33]">{'>'}</span> {props.children}</h2>,
                            strong: ({node, ...props}) => <strong className="text-[#fff] bg-[#003300] px-1" {...props} />,
                            code: ({node, ...props}) => <code className="font-mono text-xs md:text-sm bg-[#111] border border-[#333] px-1 py-0.5 rounded text-[#fa0]" {...props} />
                          }}
                        >
                          {content}
                        </ReactMarkdown>
                        {isTyping && <span className="inline-block w-2 h-4 bg-[#33ff33] animate-pulse ml-1 align-middle"></span>}
                      </div>
                    )}
                  </div>

                  <div className="p-3 border-t border-[#33ff33] bg-[#001100] flex items-center gap-2 text-sm md:text-base shrink-0">
                     <span className="text-[#ffff00] whitespace-nowrap">root@volatility:~$</span>
                     <span className="flex-1 opacity-90 truncate font-mono text-[#33ff33]">
                       {loadingContent ? 'analyzing_memory_dump...' : (
                         selectedPlugin 
                           ? `vol -f mem.raw ${selectedPlugin.command} --help` 
                           : 'waiting_for_input...'
                       )}
                       <span className="animate-pulse ml-1">_</span>
                     </span>
                  </div>
                </div>

                {/* --- BOTTOM PANELS --- */}
                <div className="h-40 shrink-0 grid grid-cols-12 gap-4 hidden sm:grid">
                  <div className="col-span-8 border border-[#33ff33] bg-[#020202] p-2 relative overflow-hidden group">
                     <div className="absolute top-0 right-0 bg-[#33ff33] text-black text-xs px-2 font-bold">HEX_VIEW</div>
                     <HexViewer />
                  </div>
                  
                  {/* --- ACTION PANEL --- */}
                  <div className="col-span-4 flex flex-col gap-2">
                     <div className="flex-1 bg-[#001100] border border-[#33ff33] p-2 flex flex-col justify-center gap-2">
                        
                        {/* CONDITIONAL METHODOLOGY BUTTON */}
                        {selectedPlugin && (selectedPlugin.name === 'NetScan' || selectedPlugin.name === 'NetStat') ? (
                          <RetroButton 
                            label="METHODOLOGY" 
                            subLabel="CONFIRMATION CHAIN" 
                            onClick={handleMethodologyClick}
                            className="flex-1 animate-pulse border-[#ffff00]" // Highlighted Button
                          />
                        ) : (
                          <RetroButton label="CHEAT SHEET" subLabel="Export PDF" onClick={() => {}} />
                        )}

                        <RetroButton label="COMMANDS" subLabel="Copy All" variant="success" onClick={() => {}} />
                     </div>
                  </div>
                </div>
              </main>
            </div>
            
            <footer className="bg-[#020402] border-t border-[#33ff33] py-1 text-center text-xs opacity-50 tracking-[0.2em] z-20">
              VOLATILITY FOUNDATION // MEMORY FORENSICS // v3.0
            </footer>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default App;