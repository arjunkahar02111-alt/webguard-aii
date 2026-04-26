// WebGuard AI — FindingCard Component
// src/components/FindingCard.jsx

import { useState } from "react";

export default function FindingCard({ finding, colors }) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className={`border rounded-xl overflow-hidden cursor-pointer transition-colors ${
        open ? "border-white/12" : "border-white/6 hover:border-white/10"
      } bg-[#0f1318]`}
      onClick={() => setOpen(o => !o)}
    >
      <div className="flex items-center gap-3 px-4 py-3">
        <span className={`text-[9px] font-mono font-bold tracking-[1px] px-2 py-0.5 rounded border uppercase flex-shrink-0 ${colors.text} ${colors.bg} ${colors.border}`}>
          {finding.severity}
        </span>
        <span className="text-[13px] font-medium flex-1 leading-snug">{finding.title}</span>
        <span className="text-[10px] font-mono text-gray-600 ml-auto">{finding.category}</span>
        <svg className={`w-3.5 h-3.5 text-gray-600 transition-transform flex-shrink-0 ${open ? "rotate-180" : ""}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
      {open && (
        <div className="px-4 pb-4 border-t border-white/5">
          <p className="text-[13px] text-gray-400 leading-relaxed mt-3 mb-3">{finding.description}</p>
          {finding.evidence && (
            <div className="bg-[#151a22] border border-white/8 rounded-lg px-3 py-2 font-mono text-[11px] text-gray-500 mb-3">
              &gt; {finding.evidence}
            </div>
          )}
          <div className="bg-[#151a22] border-l-2 border-[#00d4aa] rounded-r-lg px-3 py-2.5">
            <div className="text-[9px] font-mono text-[#00d4aa] uppercase tracking-[1px] mb-1.5">// recommended fix</div>
            <p className="text-[12px] leading-relaxed text-gray-300">{finding.fix}</p>
          </div>
          {finding.cve_ids?.length > 0 && (
            <div className="mt-2 flex gap-2">
              {finding.cve_ids.map(cve => (
                <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener"
                  className="text-[10px] font-mono text-[#0091ff] hover:underline"
                  onClick={e => e.stopPropagation()}>
                  {cve} ↗
                </a>
              ))}
            </div>
          )}
          {finding.cvss_score && (
            <div className="mt-2 text-[10px] font-mono text-gray-600">
              CVSS: {finding.cvss_score.toFixed(1)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
