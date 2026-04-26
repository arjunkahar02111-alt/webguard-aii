import { Outlet, NavLink, Link, useNavigate } from "react-router-dom";
import { ShieldAlert, LayoutDashboard, Activity, List, Settings, Shield, LogOut } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";

export default function DashboardLayout() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut();
    navigate("/");
  };
  return (
    <div className="min-h-screen flex bg-transparent text-white font-sans h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 glass-panel border-y-0 border-l-0 rounded-none bg-bg2/90 border-r-white/5 flex flex-col z-10">
        <div className="p-6 border-b border-white/5 flex items-center gap-3">
          <Link to="/" className="flex items-center gap-2">
            <ShieldAlert className="text-accent" size={24} />
            <span className="font-mono font-bold text-lg tracking-tight">WebGuard<span className="text-accent">OS</span></span>
          </Link>
        </div>
        <nav className="flex-1 p-4 flex flex-col gap-2">
          <NavLink to="/dashboard" end className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${isActive ? 'bg-accent/10 text-accent border border-accent/20' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
            <LayoutDashboard size={18} /> Overview
          </NavLink>
          <NavLink to="/dashboard/live" className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${isActive ? 'bg-accent/10 text-accent border border-accent/20' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
            <Activity size={18} /> Live Monitoring
          </NavLink>
          <NavLink to="/dashboard/logs" className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${isActive ? 'bg-accent/10 text-accent border border-accent/20' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}>
            <List size={18} /> Threat Logs
          </NavLink>
          <div className="mt-8 mb-2 text-xs font-bold text-gray-500 uppercase tracking-widest px-4">Actions</div>
          <NavLink to="/dashboard/deploy" className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${isActive ? 'bg-accent/10 text-accent border border-accent/20 shadow-[0_0_15px_rgba(0,212,170,0.15)]' : 'text-accent border border-accent/30 hover:bg-accent/10'}`}>
            <Shield size={18} /> Deploy Protection
          </NavLink>
        </nav>
        <div className="p-4 border-t border-white/5 space-y-2">
          <button className="flex w-full items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all">
            <Settings size={18} /> Settings
          </button>
          <button onClick={handleLogout} className="flex w-full items-center gap-3 px-4 py-3 rounded-lg text-danger/80 hover:text-danger hover:bg-danger/10 transition-all font-bold">
            <LogOut size={18} /> Disconnect
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden bg-bg/40 backdrop-blur-sm relative border-l border-white/5">
        {/* Top Header */}
        <header className="h-16 border-b border-white/5 flex items-center justify-between px-8 bg-bg2/40 backdrop-blur-md">
          <div className="font-semibold text-gray-300">Command Center</div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 mr-2">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-accent"></span>
              </span>
              <span className="text-xs text-accent font-bold tracking-widest neon-text">SYSTEM ONLINE</span>
            </div>
            <div className="group relative">
              <div className="w-8 h-8 rounded-full bg-accent/10 border border-accent/40 flex items-center justify-center text-xs font-bold text-accent cursor-pointer uppercase shadow-[0_0_10px_rgba(0,212,170,0.2)]">
                {user?.email?.[0] || 'O'}
              </div>
              <div className="absolute top-10 right-0 hidden group-hover:block w-56 bg-bg2/90 backdrop-blur-md border border-white/10 rounded-lg p-4 shadow-[0_0_20px_rgba(0,0,0,0.5)] z-50">
                <div className="text-gray-400 mb-1 text-[10px] uppercase font-mono tracking-widest">Active Identity</div>
                <div className="text-accent truncate font-mono text-sm font-bold">{user?.email}</div>
              </div>
            </div>
          </div>
        </header>

        {/* Dashboard View */}
        <div className="flex-1 overflow-y-auto p-4 md:p-8 relative">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
