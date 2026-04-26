// WebGuard AI — ScanProgress Component
// src/components/ScanProgress.jsx

const MODULES = [
  "sql-injection","xss-detection","csrf-check","auth-issues","idor-detection",
  "security-headers","ssl-tls-check","cors-config","cookie-analysis","session-mgmt",
  "open-redirect","ssrf-detect","dir-traversal","clickjacking","file-upload",
  "api-security","dep-vulns","subdomain-check","dns-config","perf-audit","seo-scan"
];

export default function ScanProgress({ progress }) {
  const { pct, module } = progress;
  const runningIdx = MODULES.findIndex(m => m === module);
  const doneCount = Math.floor((pct / 100) * MODULES.length);

  return (
    <div className="pt-12 max-w-2xl mx-auto">
      <div className="bg-[#0f1318] border border-white/8 rounded-2xl p-6">
        <div className="flex justify-between items-center mb-3">
          <span className="font-mono text-[12px] text-[#00d4aa]">{module}</span>
          <span className="font-mono text-[12px] text-gray-500">{pct}%</span>
        </div>
        <div className="h-[3px] bg-[#151a22] rounded-full overflow-hidden mb-6">
          <div
            className="h-full rounded-full bg-gradient-to-r from-[#00d4aa] to-[#0091ff] transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="grid grid-cols-3 gap-2">
          {MODULES.map((m, i) => (
            <div
              key={m}
              className={`flex items-center gap-2 rounded-lg px-3 py-2 text-[11px] font-mono transition-all duration-300 ${
                i < doneCount
                  ? "bg-[#00d4aa]/8 border border-[#00d4aa]/15 text-[#00d4aa]"
                  : i === doneCount
                  ? "bg-[#ffaa00]/8 border border-[#ffaa00]/20 text-[#ffaa00]"
                  : "bg-[#151a22] border border-transparent text-gray-600"
              }`}
            >
              <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                i < doneCount ? "bg-[#00d4aa]"
                : i === doneCount ? "bg-[#ffaa00] animate-pulse"
                : "bg-gray-700"
              }`} />
              {m}
            </div>
          ))}
        </div>
      </div>
      <p className="text-center text-[12px] text-gray-600 font-mono mt-4">
        Scanning with safe, non-destructive probes only
      </p>
    </div>
  );
}
