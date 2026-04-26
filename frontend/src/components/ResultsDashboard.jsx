// WebGuard AI — ResultsDashboard Component
// src/components/ResultsDashboard.jsx

import { useState } from "react";
import FindingCard from "./FindingCard";
import ScoreRing from "./ScoreRing";
import MetricsGrid from "./MetricsGrid";

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_COLORS = {
  CRITICAL: { text: "text-[#ff2d55]", bg: "bg-[#ff2d55]/10", border: "border-[#ff2d55]/25" },
  HIGH:     { text: "text-[#ff4444]", bg: "bg-[#ff4444]/10", border: "border-[#ff4444]/25" },
  MEDIUM:   { text: "text-[#ffaa00]", bg: "bg-[#ffaa00]/10", border: "border-[#ffaa00]/25" },
  LOW:      { text: "text-[#00d4aa]", bg: "bg-[#00d4aa]/8",  border: "border-[#00d4aa]/20" },
  INFO:     { text: "text-[#0091ff]", bg: "bg-[#0091ff]/8",  border: "border-[#0091ff]/20" },
};

export default function ResultsDashboard({ data, onRescan, apiBase, scanId }) {
  const [filter, setFilter] = useState("all");
  const findings = data.findings || [];
  const stats = data.stats || {};
  const ssl = data.ssl || {};
  const perf = data.performance || {};
  const seo = data.seo || {};
  const headers = data.headers || {};
  const techs = data.technologies || [];

  const filtered = (filter === "all" ? findings : findings.filter(f => f.severity === filter))
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const riskColor = {
    CRITICAL: "text-[#ff2d55]", HIGH: "text-[#ff4444]",
    MEDIUM: "text-[#ffaa00]", LOW: "text-[#00d4aa]",
  }[data.risk_level] || "text-gray-400";

  return (
    <div className="pt-8">
      {/* ── Score + Summary ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-[200px_1fr] gap-4 mb-4">
        {/* Score ring */}
        <div className="bg-[#0f1318] border border-white/8 rounded-2xl p-5 flex flex-col items-center justify-center text-center">
          <ScoreRing score={data.overall_score || 0} risk={data.risk_level} />
          <div className={`font-mono text-[11px] tracking-[2px] mt-3 font-bold ${riskColor}`}>
            {data.risk_level} RISK
          </div>
          <div className="font-mono text-[10px] text-gray-600 mt-1">{data.hostname}</div>
        </div>

        {/* Stats meta grid */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Critical", value: stats.critical || 0, color: "text-[#ff2d55]" },
            { label: "High",     value: stats.high || 0,     color: "text-[#ff4444]" },
            { label: "Medium",   value: stats.medium || 0,   color: "text-[#ffaa00]" },
            { label: "Checks Run", value: stats.total_checks || 0, color: "text-[#0091ff]" },
            { label: "SSL Grade",  value: ssl.grade || "N/A",
              color: ["A+","A"].includes(ssl.grade) ? "text-[#00d4aa]" : ssl.grade === "B" ? "text-[#ffaa00]" : "text-[#ff4444]" },
            { label: "Total Issues",
              value: (stats.critical||0)+(stats.high||0)+(stats.medium||0)+(stats.low||0),
              color: "text-white" },
          ].map(m => (
            <div key={m.label} className="bg-[#0f1318] border border-white/5 rounded-xl p-4">
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-[1px] mb-1">{m.label}</div>
              <div className={`font-mono text-2xl font-bold ${m.color}`}>{m.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Summary + tech row */}
      <div className="bg-[#0f1318] border border-white/8 rounded-2xl p-5 mb-4">
        <div className="text-[10px] font-mono text-gray-500 uppercase tracking-[1.5px] mb-2">AI Summary</div>
        <p className="text-[13px] leading-relaxed text-gray-300">{data.summary}</p>
        {techs.length > 0 && (
          <div className="mt-4">
            <div className="text-[10px] font-mono text-gray-500 uppercase tracking-[1px] mb-2">Detected Technologies</div>
            <div className="flex flex-wrap gap-2">
              {techs.map((t, i) => (
                <span key={i} title={t.vulnerable ? `CVE: ${t.cve}` : "No known CVEs"}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded-full border ${
                    t.vulnerable
                      ? "border-red-500/30 text-red-400 bg-red-500/8"
                      : "border-white/10 text-gray-400"
                  }`}>
                  {t.name} {t.version !== "unknown" ? t.version : ""}{t.vulnerable ? " ⚠" : ""}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Findings ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-3">
        <span className="font-mono text-[10px] text-gray-500 uppercase tracking-[2px]">
          // security findings
        </span>
        <div className="flex gap-1.5">
          {["all", ...Object.keys(SEV_COLORS).filter(s => sevCounts[s])].map(f => {
            const count = f === "all" ? findings.length : sevCounts[f] || 0;
            const col = f === "all" ? { text: "text-[#0091ff]", bg: "bg-[#0091ff]/8", border: "border-[#0091ff]/25" } : SEV_COLORS[f];
            return (
              <button key={f} onClick={() => setFilter(f)}
                className={`text-[10px] font-mono px-2.5 py-1 rounded-full border transition-all ${
                  filter === f ? `${col.text} ${col.bg} ${col.border}` : "border-white/8 text-gray-600 hover:border-white/15"
                }`}>
                {f === "all" ? "All" : f} ({count})
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex flex-col gap-2 mb-6">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-600 font-mono text-[12px]">
            No {filter !== "all" ? filter.toLowerCase() : ""} findings
          </div>
        ) : (
          filtered.map((f, i) => <FindingCard key={f.id || i} finding={f} colors={SEV_COLORS[f.severity] || SEV_COLORS.INFO} />)
        )}
      </div>

      {/* ── Perf + SEO + Headers + SSL grid ──────────────────────────────── */}
      <MetricsGrid perf={perf} seo={seo} headers={headers} ssl={ssl} />

      {/* ── Export bar ────────────────────────────────────────────────────── */}
      <div className="flex gap-3 pt-6 border-t border-white/5 mt-6">
        <a
          href={`${apiBase}/report/${scanId}/html`}
          target="_blank"
          rel="noopener noreferrer"
          className="bg-[#00d4aa] text-[#0a0c10] font-semibold text-[12px] px-5 py-2.5 rounded-lg hover:opacity-90 transition-all font-mono"
        >
          HTML Report ↗
        </a>
        <a
          href={`${apiBase}/report/${scanId}/pdf`}
          target="_blank"
          rel="noopener noreferrer"
          className="border border-white/10 text-gray-300 font-mono text-[12px] px-5 py-2.5 rounded-lg hover:bg-white/5 transition-all"
        >
          PDF Export ↗
        </a>
        <button
          onClick={onRescan}
          className="border border-white/10 text-gray-300 font-mono text-[12px] px-5 py-2.5 rounded-lg hover:bg-white/5 transition-all"
        >
          New Scan
        </button>
      </div>
    </div>
  );
}
