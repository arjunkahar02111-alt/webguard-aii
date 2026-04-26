import { Target, Plus } from "lucide-react";
import { Link } from "react-router-dom";

export default function Overview() {
  return (
    <div className="h-full flex flex-col items-center justify-center space-y-6 text-center animate-fade-in-up">
      <div className="w-24 h-24 rounded-full bg-accent/10 border border-accent/20 flex flex-col items-center justify-center">
        <Target className="text-accent" size={40} />
      </div>
      <div>
        <h1 className="text-2xl font-bold text-white mb-2">No Active Protections</h1>
        <p className="text-gray-400 max-w-md mx-auto">Deploy your first WebGuard instance to start scanning, monitoring, and automatically blocking live threats.</p>
      </div>
      <Link to="/dashboard/deploy" className="px-6 py-3 bg-white text-bg2 font-bold rounded-lg flex items-center gap-2 hover:bg-gray-200 transition-all shadow-[0_0_15px_rgba(255,255,255,0.2)]">
        <Plus size={20} /> Deploy Protection
      </Link>
    </div>
  );
}
