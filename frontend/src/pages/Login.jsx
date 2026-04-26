import { useState } from 'react';
import { supabase } from '../lib/supabase';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { ShieldAlert, ArrowRight, Lock } from 'lucide-react';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || "/dashboard";

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      navigate(from, { replace: true });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative font-sans">
      <div className="w-full max-w-md glass-panel p-8 relative overflow-hidden animate-fade-in-up">
        {/* Background glow flair */}
        <div className="absolute -top-10 -right-10 w-40 h-40 bg-accent/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-accent2/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex justify-center mb-8 relative z-10">
          <Link to="/" className="flex items-center gap-2">
            <ShieldAlert className="text-accent" size={36} />
            <span className="text-2xl font-bold font-mono tracking-tight text-white">WebGuard<span className="text-accent">AI</span></span>
          </Link>
        </div>

        <form onSubmit={handleLogin} className="space-y-5 relative z-10">
          <div className="text-center space-y-2 mb-6">
            <h1 className="text-xl font-bold text-white">Secure Access Panel</h1>
            <p className="text-xs text-gray-400 font-mono">Authenticate to command center.</p>
          </div>

          {error && <div className="p-3 text-[13px] font-mono text-danger bg-danger/10 border border-danger/20 rounded-md">⚠ {error}</div>}

          <div className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono text-gray-400 uppercase tracking-widest mb-1.5 ml-1">Email Directive</label>
              <input 
                type="email" 
                required 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-bg3/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-600 outline-none focus:border-accent/50 transition-colors focus:shadow-[0_0_15px_rgba(0,212,170,0.1)]"
                placeholder="operator@domain.com"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-gray-400 uppercase tracking-widest mb-1.5 ml-1">Access Key</label>
              <input 
                type="password" 
                required 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-bg3/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-600 outline-none focus:border-accent/50 transition-colors focus:shadow-[0_0_15px_rgba(0,212,170,0.1)]"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full mt-2 py-3.5 bg-accent/10 border border-accent/40 text-accent font-bold rounded-lg hover:bg-accent/20 hover:shadow-[0_0_20px_rgba(0,212,170,0.3)] transition-all flex justify-center items-center gap-2 group disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? <span className="animate-pulse">Authenticating...</span> : <><Lock size={16} /> Enter Command Center <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" /></>}
          </button>
        </form>

        <div className="mt-6 text-center text-xs text-gray-500 font-mono relative z-10">
          Unregistered operator? <Link to="/signup" className="text-accent2 hover:text-white transition-colors">Establish new identity.</Link>
        </div>
      </div>
    </div>
  );
}
