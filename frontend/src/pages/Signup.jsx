import { useState } from 'react';
import { supabase } from '../lib/supabase';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldAlert, ArrowRight, UserPlus } from 'lucide-react';

export default function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMsg(null);
    
    if (password !== confirmPassword) {
      setError("Security keys do not match.");
      setLoading(false);
      return;
    }

    const { error } = await supabase.auth.signUp({ 
      email, 
      password,
      options: {
        emailRedirectTo: window.location.origin
      }
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      setMsg("Identity established. Check your secure comms (email) for verification.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative font-sans">
      <div className="w-full max-w-md glass-panel p-8 relative overflow-hidden animate-fade-in-up">
        {/* Background glow flair */}
        <div className="absolute -top-10 -right-10 w-40 h-40 bg-accent2/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex justify-center mb-8 relative z-10">
          <Link to="/" className="flex items-center gap-2">
            <ShieldAlert className="text-accent" size={36} />
            <span className="text-2xl font-bold font-mono tracking-tight text-white">WebGuard<span className="text-accent">AI</span></span>
          </Link>
        </div>

        <form onSubmit={handleSignup} className="space-y-5 relative z-10">
          <div className="text-center space-y-2 mb-6">
            <h1 className="text-xl font-bold text-white">Identity Provisioning</h1>
            <p className="text-xs text-gray-400 font-mono">Create an operator clearance account.</p>
          </div>

          {error && <div className="p-3 text-[13px] font-mono text-danger bg-danger/10 border border-danger/20 rounded-md">⚠ {error}</div>}
          {msg && <div className="p-3 text-[13px] font-mono text-accent bg-accent/10 border border-accent/20 rounded-md">✓ {msg}</div>}

          <div className="space-y-4">
            <div>
              <label className="block text-[11px] font-mono text-gray-400 uppercase tracking-widest mb-1.5 ml-1">Email Directive</label>
              <input 
                type="email" 
                required 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-bg3/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-600 outline-none focus:border-accent2/50 transition-colors focus:shadow-[0_0_15px_rgba(0,122,255,0.1)]"
                placeholder="operator@domain.com"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-gray-400 uppercase tracking-widest mb-1.5 ml-1">Access Key</label>
              <input 
                type="password" 
                required 
                minLength={6}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-bg3/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-600 outline-none focus:border-accent2/50 transition-colors"
                placeholder="••••••••••••"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-gray-400 uppercase tracking-widest mb-1.5 ml-1">Confirm Access Key</label>
              <input 
                type="password" 
                required 
                minLength={6}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full bg-bg3/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-600 outline-none focus:border-accent2/50 transition-colors"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full mt-2 py-3.5 bg-accent2/10 border border-accent2/40 text-accent2 font-bold rounded-lg hover:bg-accent2/20 hover:shadow-[0_0_20px_rgba(0,122,255,0.3)] transition-all flex justify-center items-center gap-2 group disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? <span className="animate-pulse">Provisioning...</span> : <><UserPlus size={16} /> Mint Identity <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" /></>}
          </button>
        </form>

        <div className="mt-6 text-center text-xs text-gray-500 font-mono relative z-10">
          Already cleared? <Link to="/login" className="text-accent hover:text-white transition-colors">Authenticate here.</Link>
        </div>
      </div>
    </div>
  );
}
