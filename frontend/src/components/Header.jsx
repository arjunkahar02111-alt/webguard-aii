// WebGuard AI — UI Components Part 1
// src/components/Header.jsx

export default function Header({ onReset }) {
  return (
    <header className="sticky top-0 z-50 border-b border-white/5 bg-[#0a0c10]/90 backdrop-blur">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <button onClick={onReset} className="flex items-center gap-2.5 group">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-[#00d4aa] to-[#0091ff] flex items-center justify-center text-sm">
            🛡
          </div>
          <span className="font-mono text-[15px] font-bold tracking-tight">
            WebGuard<span className="text-[#00d4aa]">AI</span>
          </span>
        </button>
        <div className="flex gap-2">
          <span className="text-[10px] font-mono px-2.5 py-1 rounded-full border border-[#00d4aa]/30 text-[#00d4aa]">
            20+ vuln checks
          </span>
          <span className="text-[10px] font-mono px-2.5 py-1 rounded-full border border-[#0091ff]/30 text-[#0091ff]">
            AI-powered
          </span>
        </div>
      </div>
    </header>
  );
}
