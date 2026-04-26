import { Globe2 } from "lucide-react";

export default function LiveMonitoring() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
         <h1 className="text-2xl font-bold text-white">Live Monitoring</h1>
         <div className="flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-accent"></span>
            </span>
            <span className="text-xs text-accent font-bold tracking-widest neon-text">LISTENING</span>
         </div>
      </div>
      
      <div className="h-[400px] glass-panel border border-white/5 bg-bg2/40 flex items-center justify-center relative overflow-hidden">
         <Globe2 className="text-gray-800 opacity-20 absolute" size={800} />
         <div className="text-gray-400 relative z-10 font-mono text-sm">Awaiting connection to deployment edge...</div>
      </div>
    </div>
  );
}
