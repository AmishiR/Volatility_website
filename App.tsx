import React, { useState, useMemo } from 'react';
import { Terminal, ShieldAlert, Cpu, Network, FileCode, Activity, HardDrive, Lock, Search } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { PLUGINS, INITIAL_CONTENT, PREDEFINED_PLUGIN_CONTENT } from './constants';
import { explainPlugin } from './services/geminiService';
import RetroButton from './components/RetroButton';
import ScanlineOverlay from './components/ScanlineOverlay';
import HexViewer from './components/HexViewer';

const App: React.FC = () => {
  const [selectedPlugin, setSelectedPlugin] = useState<string | null>(null);
  const [content, setContent] = useState<string>(INITIAL_CONTENT);
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [activeCategory, setActiveCategory] = useState<string | null>('malware');

  // Group plugins by category
  const categories = ['process', 'network', 'malware', 'system', 'misc'];
  const groupedPlugins = useMemo(() => {
    return categories.reduce((acc, cat) => {
      acc[cat] = PLUGINS.filter(p => p.category === cat);
      return acc;
    }, {} as Record<string, typeof PLUGINS>);
  }, []);

  const handlePluginClick = async (pluginName: string) => {
    if (pluginName === selectedPlugin && !loading) return;
    
    setSelectedPlugin(pluginName);
    setLoading(true);
    setContent(''); 
    
    let explanation = '';

    // HYBRID CONTENT STRATEGY:
    // 1. Check if we have hardcoded content in constants.ts
    // 2. If not, fetch from Gemini API
    if (PREDEFINED_PLUGIN_CONTENT[pluginName]) {
      explanation = PREDEFINED_PLUGIN_CONTENT[pluginName];
      // Simulate a small "decryption" delay for UI consistency (optional, but feels nicer)
      await new Promise(resolve => setTimeout(resolve, 600)); 
    } else {
      explanation = await explainPlugin(pluginName);
    }

    setLoading(false);
    
    // Typewriter effect
    let i = 0;
    setIsTyping(true);
    const speed = 2; 
    
    const typeWriter = () => {
      if (i < explanation.length) {
        setContent(explanation.substring(0, i + 1));
        i++;
        setTimeout(typeWriter, speed);
      } else {
        setIsTyping(false);
      }
    };
    typeWriter();
  };

  const resetHome = () => {
    setSelectedPlugin(null);
    setContent(INITIAL_CONTENT);
  };

  const getCategoryIcon = (category: string) => {
     switch (category) {
       case 'malware': return <ShieldAlert className="w-4 h-4" />;
       case 'network': return <Network className="w-4 h-4" />;
       case 'system': return <Cpu className="w-4 h-4" />;
       case 'process': return <Activity className="w-4 h-4" />;
       default: return <FileCode className="w-4 h-4" />;
     }
  };

  return (
    <div className="min-h-screen text-[#33ff33] selection:bg-[#33ff33] selection:text-black overflow-hidden relative flex flex-col">
      <ScanlineOverlay />
      
      {/* Top Navigation Bar */}
      <nav className="h-14 border-b-2 border-[#33ff33] bg-[#020402] flex items-center justify-between px-6 z-20 shrink-0">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 bg-[#33ff33] flex items-center justify-center text-black font-bold text-xl">V</div>
          <h1 className="text-2xl font-bold tracking-wider text-glow uppercase">Volatility Framework <span className="text-xs align-top opacity-70">v2.6</span></h1>
        </div>
        <div className="flex gap-6 text-sm opacity-80">
          <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div> ONLINE</div>
          <div>MEM_USAGE: 4096MB</div>
          <div>SESSION_ID: 0x89AF</div>
        </div>
      </nav>

      <div className="flex-1 flex overflow-hidden relative z-10 p-4 gap-4">
        
        {/* LEFT SIDEBAR - NAVIGATION */}
        <aside className="w-64 flex flex-col gap-4 shrink-0">
          <div className="bg-[#001100] border border-[#33ff33] flex-1 flex flex-col overflow-hidden box-glow">
            <div className="p-2 border-b border-[#33ff33] bg-[#002200] font-bold flex items-center gap-2">
              <HardDrive className="w-4 h-4" /> PLUGINS_DIR
            </div>
            
            <div className="overflow-y-auto p-2 flex-1 scrollbar-hide">
              {categories.map(cat => (
                <div key={cat} className="mb-4">
                  <button 
                    onClick={() => setActiveCategory(activeCategory === cat ? null : cat)}
                    className="w-full text-left uppercase font-bold text-[#ccffcc] mb-1 flex items-center justify-between hover:bg-[#113311] p-1"
                  >
                    <div className="flex items-center gap-2">
                      {getCategoryIcon(cat)} {cat}
                    </div>
                    <span>{activeCategory === cat ? '[-]' : '[+]'}</span>
                  </button>
                  
                  {activeCategory === cat && (
                    <div className="pl-4 border-l border-[#33ff33] ml-2 space-y-1">
                      {groupedPlugins[cat].map(plugin => (
                        <button
                          key={plugin.name}
                          onClick={() => handlePluginClick(plugin.name)}
                          className={`
                            block w-full text-left text-lg truncate px-2 py-0.5
                            ${selectedPlugin === plugin.name 
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

          {/* System Status Small Box */}
          <div className="border border-[#33ff33] p-3 bg-[#050505] text-xs space-y-2">
             <div className="flex justify-between"><span>CPU_CORES</span><span>8/8 ACTIVE</span></div>
             <div className="w-full bg-[#112211] h-1.5"><div className="bg-[#33ff33] w-3/4 h-full animate-pulse"></div></div>
             <div className="flex justify-between"><span>RAM_DUMP</span><span>PARSING...</span></div>
             <div className="w-full bg-[#112211] h-1.5"><div className="bg-[#33ff33] w-1/2 h-full"></div></div>
          </div>
        </aside>


        {/* RIGHT MAIN CONTENT */}
        <main className="flex-1 flex flex-col gap-4 overflow-hidden">
          
          {/* TERMINAL WINDOW */}
          <div className="flex-1 border-2 border-[#33ff33] bg-[#000900] relative flex flex-col shadow-[0_0_15px_rgba(51,255,51,0.15)]">
            {/* Terminal Header */}
            <div className="h-8 bg-[#33ff33] flex items-center justify-between px-2 shrink-0">
               <span className="text-black font-bold uppercase flex items-center gap-2">
                 <Terminal className="w-4 h-4" /> 
                 {selectedPlugin ? `ROOT@VOLATILITY:~/${selectedPlugin.toUpperCase()}` : 'ROOT@VOLATILITY:~/HOME'}
               </span>
               <div className="flex gap-1">
                 <div className="w-3 h-3 bg-black border border-white"></div>
                 <div className="w-3 h-3 bg-black border border-white"></div>
                 <button onClick={resetHome} className="w-3 h-3 bg-red-900 border border-black hover:bg-red-600"></button>
               </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-y-auto p-6 font-mono relative">
               {loading ? (
                <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#000900] z-20 opacity-90">
                   <div className="text-2xl animate-pulse mb-2">ACCESSING MAINFRAME...</div>
                   <div className="w-64 h-4 border-2 border-[#33ff33] p-1">
                     <div className="h-full bg-[#33ff33] animate-[width_1.5s_ease-in-out_infinite]" style={{width: '0%'}}></div>
                   </div>
                </div>
              ) : (
                <div className="prose prose-invert prose-p:text-[#33ff33] prose-headings:text-[#ccffcc] prose-code:text-[#ffff00] max-w-none text-lg">
                  <ReactMarkdown
                    components={{
                      h1: ({node, ...props}) => <h1 className="text-3xl font-bold border-b-2 border-[#33ff33] pb-2 mb-4 uppercase" {...props} />,
                      h2: ({node, ...props}) => <h2 className="text-xl font-bold mt-6 mb-2 text-[#ffff00] flex items-center gap-2" {...props}><span className="text-[#33ff33]">{'>'}</span> {props.children}</h2>,
                      strong: ({node, ...props}) => <strong className="text-[#fff] bg-[#003300] px-1" {...props} />,
                      code: ({node, ...props}) => <code className="font-mono text-sm bg-[#111] border border-[#333] px-1 py-0.5 rounded text-[#fa0]" {...props} />
                    }}
                  >
                    {content}
                  </ReactMarkdown>
                  {isTyping && <span className="inline-block w-2 h-5 bg-[#33ff33] animate-pulse ml-1 align-middle"></span>}
                </div>
              )}
            </div>

            {/* Fake Command Input */}
            <div className="p-2 border-t border-[#33ff33] bg-[#001100] flex items-center gap-2 text-lg shrink-0">
               <span className="text-[#ffff00]">root@kali:~$</span>
               <span className="flex-1 opacity-80">
                 {loading ? 'executing_script.py...' : `vol.py -f suspicious.mem ${selectedPlugin || ''}`}
                 <span className="animate-pulse">_</span>
               </span>
            </div>
          </div>


          {/* BOTTOM UTILITY PANEL */}
          <div className="h-48 shrink-0 grid grid-cols-12 gap-4">
            
            {/* Hex Dump Viewer */}
            <div className="col-span-12 lg:col-span-8 border border-[#33ff33] bg-[#020202] p-2 relative overflow-hidden group">
               <div className="absolute top-0 right-0 bg-[#33ff33] text-black text-xs px-2 font-bold">LIVE_HEX_VIEW</div>
               <HexViewer />
               {/* Decorative grid lines */}
               <div className="absolute inset-0 border border-[#33ff33] opacity-20 pointer-events-none"></div>
            </div>

            {/* Quick Actions / Downloads */}
            <div className="col-span-12 lg:col-span-4 flex flex-col gap-2">
               <div className="flex-1 bg-[#001100] border border-[#33ff33] p-2 flex flex-col justify-center">
                 <h3 className="text-[#ffff00] text-sm mb-2 border-b border-[#33ff33] inline-block w-full">SYSTEM_TOOLS</h3>
                 <div className="flex flex-col gap-2">
                    <RetroButton 
                      label="BINARY" 
                      subLabel="Download Standalone" 
                      onClick={() => window.open('https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_win64_standalone.exe')}
                      className="flex-1"
                    />
                    <RetroButton 
                      label="SOURCE" 
                      subLabel="Linux Install Guide" 
                      onClick={() => window.open('https://github.com/volatilityfoundation/volatility/wiki/Installation')}
                      variant="success"
                      className="flex-1"
                    />
                 </div>
               </div>
            </div>

          </div>
        </main>
      </div>

      <footer className="bg-[#020402] border-t border-[#33ff33] py-1 text-center text-xs opacity-50 tracking-[0.2em] z-20">
        ENCRYPTED CONNECTION // SECURE SHELL v2.0 // ACCESS GRANTED
      </footer>
    </div>
  );
};

export default App;