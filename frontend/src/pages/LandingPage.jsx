import { Shield, Zap, Activity, Globe, Lock, ShieldCheck, ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";

export default function LandingPage() {
  return (
    <div className="min-h-screen text-white font-sans relative">
      {/* Sticky Navbar */}
      <nav className="fixed top-0 w-full z-50 glass-panel border-b-0 border-x-0 rounded-none bg-bg/80 border-white/5 py-4 px-8 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Shield className="text-accent" size={28} />
          <span className="text-xl font-bold font-mono tracking-tight">WebGuard<span className="text-accent">AI</span></span>
        </div>
        <div className="hidden md:flex gap-8 text-sm font-medium text-gray-300">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#stats" className="hover:text-white transition-colors">Live Stats</a>
          <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
        </div>
        <div className="flex gap-4">
          <Link to="/dashboard" className="px-5 py-2 bg-accent/10 border border-accent/50 text-accent rounded-lg text-sm font-semibold hover:bg-accent/20 hover:shadow-[0_0_15px_rgba(0,212,170,0.3)] transition-all">Get Protected</Link>
        </div>
      </nav>

      <main className="pt-32 pb-20 px-4 max-w-7xl mx-auto space-y-32">
        {/* Hero Section */}
        <section className="text-center space-y-8 animate-fade-in-up mt-10 relative">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-accent/5 rounded-full blur-[100px] -z-10 pointer-events-none" />
          <h1 className="text-5xl md:text-7xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-br from-white to-gray-500">
            AI-Powered Protection <br /> for Your Digital Infrastructure
          </h1>
          <p className="text-lg md:text-xl text-gray-400 max-w-3xl mx-auto">
            Monitor, detect, and neutralize threats in real-time. Unmatched AI cybersecurity designed for modern web applications and APIs.
          </p>
          <div className="flex justify-center flex-wrap gap-6 pt-4">
            <Link to="/dashboard" className="px-8 py-4 bg-accent text-bg2 font-bold rounded-xl flex items-center gap-2 hover:bg-accent/90 shadow-[0_0_20px_rgba(0,212,170,0.4)] hover:shadow-[0_0_30px_rgba(0,212,170,0.6)] transition-all">
              Launch Dashboard <ChevronRight size={20} />
            </Link>
          </div>
        </section>

        {/* Features */}
        <section id="features" className="space-y-12">
          <div className="text-center space-y-4">
            <h2 className="text-3xl font-bold">Advanced Neural Defenses</h2>
            <p className="text-gray-400">Powered by behavioral mechanics and global threat intelligence.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="glass-card glass-card-hover p-8 space-y-4 relative overflow-hidden group">
              <div className="absolute -right-4 -top-4 w-24 h-24 bg-accent/10 rounded-full blur-2xl group-hover:bg-accent/20 transition-all pointer-events-none" />
              <Activity className="text-accent" size={32} />
              <h3 className="text-xl font-bold text-white">AI Threat Detection</h3>
              <p className="text-sm text-gray-400">Our machine learning models adapt to zero-day architectures before they breach your edge layer.</p>
            </div>
            <div className="glass-card glass-card-hover p-8 space-y-4 relative overflow-hidden group">
               <div className="absolute -right-4 -top-4 w-24 h-24 bg-accent2/10 rounded-full blur-2xl group-hover:bg-accent2/20 transition-all pointer-events-none" />
               <Zap className="text-accent2" size={32} />
               <h3 className="text-xl font-bold text-white">Real-Time Mitigations</h3>
               <p className="text-sm text-gray-400">Microsecond-fast decisions at the edge. Automatic IP bans and request rate throttling.</p>
            </div>
            <div className="glass-card glass-card-hover p-8 space-y-4 relative overflow-hidden group">
               <div className="absolute -right-4 -top-4 w-24 h-24 bg-purple-500/10 rounded-full blur-2xl group-hover:bg-purple-500/20 transition-all pointer-events-none" />
               <Globe className="text-purple-400" size={32} />
               <h3 className="text-xl font-bold text-white">Bot & API Protection</h3>
               <p className="text-sm text-gray-400">Seamlessly block malicious scrapers and identify authenticated API exploitation patterns.</p>
            </div>
          </div>
        </section>

        {/* Live Stats */}
        <section id="stats" className="glass-panel p-12 relative overflow-hidden border-x-0 md:border-x">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-accent/5 to-transparent pointer-events-none" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center md:divide-x border-white/5 divide-gray-800">
             <div className="space-y-2">
               <div className="text-3xl md:text-4xl font-mono font-bold text-white">12.4M+</div>
               <div className="text-xs text-gray-400 uppercase tracking-widest font-semibold">Threats Blocked</div>
             </div>
             <div className="space-y-2">
               <div className="text-3xl md:text-4xl font-mono font-bold text-accent">99.9%</div>
               <div className="text-xs text-accent/60 uppercase tracking-widest font-semibold">Detection Accuracy</div>
             </div>
             <div className="space-y-2">
               <div className="text-3xl md:text-4xl font-mono font-bold text-white">14ms</div>
               <div className="text-xs text-gray-400 uppercase tracking-widest font-semibold">Avg Response Time</div>
             </div>
             <div className="space-y-2">
               <div className="text-3xl md:text-4xl font-mono font-bold text-white">2.1K</div>
               <div className="text-xs text-gray-400 uppercase tracking-widest font-semibold">Active Defenses</div>
             </div>
          </div>
        </section>

        {/* Pricing */}
        <section id="pricing" className="space-y-12 pb-20">
           <div className="text-center space-y-4">
             <h2 className="text-3xl font-bold">Secure Your Infrastructure</h2>
             <p className="text-gray-400">Transparent pricing for scaling enterprises.</p>
           </div>
           <div className="grid md:grid-cols-3 gap-8 items-center">
             <div className="glass-card p-8 space-y-6 opacity-70 hover:opacity-100 transition-opacity">
               <h3 className="text-xl font-bold">Starter</h3>
               <div className="text-4xl font-mono font-bold">$49<span className="text-sm text-gray-500 font-sans">/mo</span></div>
               <ul className="space-y-3 text-sm text-gray-400">
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> Basic DDoS Mitigation</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> Rate Limiting</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> 7-Day Log Retention</li>
               </ul>
               <button className="w-full py-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition">Start Free Trial</button>
             </div>
             <div className="glass-card p-8 space-y-6 border-accent/40 shadow-[0_0_20px_rgba(0,212,170,0.15)] relative transform md:scale-105">
               <div className="absolute top-0 left-1/2 -translate-x-1/2 bg-accent text-bg2 text-xs font-bold px-4 py-1 rounded-b-lg">MOST SECURE</div>
               <h3 className="text-xl font-bold text-accent">Pro</h3>
               <div className="text-4xl font-mono font-bold">$199<span className="text-sm text-gray-500 font-sans">/mo</span></div>
               <ul className="space-y-3 text-sm text-gray-300">
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> AI Behavioral Analysis</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> API Security Layer</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> 30-Day Retention</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-accent"/> Slack/Webhook Alerts</li>
               </ul>
               <Link to="/dashboard" className="block text-center w-full py-3 bg-accent text-bg2 font-bold rounded-lg hover:bg-accent/90 transition shadow-[0_0_15px_rgba(0,212,170,0.3)]">Get Pro</Link>
             </div>
             <div className="glass-card p-8 space-y-6 opacity-70 hover:opacity-100 transition-opacity">
               <h3 className="text-xl font-bold">Enterprise</h3>
               <div className="text-4xl font-mono font-bold">Custom</div>
               <ul className="space-y-3 text-sm text-gray-400">
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-gray-500"/> Dedicated AI Model</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-gray-500"/> Unlimited Log Retention</li>
                 <li className="flex gap-2"><ShieldCheck size={16} className="text-gray-500"/> 24/7 SOC Support</li>
               </ul>
               <button className="w-full py-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition">Contact Sales</button>
             </div>
           </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 bg-bg2/80 backdrop-blur-md py-8 mt-10">
        <div className="max-w-7xl mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-gray-500 font-mono">
          <div className="flex items-center gap-2">
            <Shield className="text-accent" size={16} />
            <span>WebGuard<span className="text-accent">AI</span></span>
          </div>
          <div className="text-center md:text-left tracking-wide">
            Developed By <span className="text-gray-300 font-semibold uppercase">Arjun Kahar</span> &copy; 2026
          </div>
          <div className="flex gap-4">
            <a href="#" className="hover:text-accent transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-accent transition-colors">Terms of Service</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
