// WebGuard AI — ScanForm Component
// src/components/ScanForm.jsx

import { useState } from "react";

const SCAN_OPTIONS = [
  { key: "security",     label: "Security" },
  { key: "performance",  label: "Performance" },
  { key: "seo",          label: "SEO" },
  { key: "headers",      label: "Headers" },
  { key: "ssl",          label: "SSL/TLS" },
  { key: "cors",         label: "CORS" },
];

const SCAN_TYPES = [
  { value: "full",             label: "Full Scan" },
  { value: "quick",            label: "Quick Scan" },
  { value: "security_only",    label: "Security Only" },
  { value: "performance_only", label: "Performance Only" },
];

const EXAMPLE_URLS = [
  "https://example.com",
  "https://testphp.vulnweb.com",
  "https://httpbin.org",
];

export default function ScanForm({ onScan, error }) {
  const [url, setUrl]         = useState("");
  const [scanType, setScanType] = useState("full");
  const [activeOpts, setActiveOpts] = useState(new Set(["security","performance","seo","headers","ssl","cors"]));
  const [loading, setLoading] = useState(false);

  function toggleOpt(key) {
    setActiveOpts(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!url.trim()) return;
    let u = url.trim();
    if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
    setLoading(true);
    await onScan(u, scanType, [...activeOpts]);
    setLoading(false);
  }

  return (
    <div className="pt-16 pb-8 text-center">
      {/* Hero text */}
      <p className="font-mono text-[11px] tracking-[3px] text-[#00d4aa] uppercase mb-5">
        // deep security scanning engine
      </p>
      <h1 className="text-4xl font-light tracking-tight mb-3 leading-tight">
        Expose every vulnerability<br />
        <span className="font-semibold bg-gradient-to-r from-[#00d4aa] to-[#0091ff] bg-clip-text text-transparent">
          before attackers do
        </span>
      </h1>
      <p className="text-[15px] text-gray-500 mb-10 leading-relaxed">
        Multi-layer analysis covering security, performance & SEO.<br />
        Powered by AI. Built for professionals.
      </p>

      {/* Scan box */}
      <form onSubmit={handleSubmit} className="bg-[#0f1318] border border-white/8 rounded-2xl p-5 max-w-2xl mx-auto">
        <div className="flex gap-3 mb-4">
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 bg-[#151a22] border border-white/10 rounded-xl px-4 py-3 font-mono text-[13px] text-white placeholder-gray-600 outline-none focus:border-[#00d4aa]/50 transition-colors"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="bg-[#00d4aa] text-[#0a0c10] font-semibold text-[14px] px-7 py-3 rounded-xl hover:opacity-90 active:scale-[0.98] transition-all disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
          >
            {loading ? "Starting..." : "Scan Now"}
          </button>
        </div>

        {/* Scan type select */}
        <div className="flex gap-2 mb-4 flex-wrap">
          {SCAN_TYPES.map(t => (
            <button
              key={t.value}
              type="button"
              onClick={() => setScanType(t.value)}
              className={`text-[11px] font-mono px-3 py-1.5 rounded-full border transition-all ${
                scanType === t.value
                  ? "border-[#0091ff]/60 text-[#0091ff] bg-[#0091ff]/10"
                  : "border-white/8 text-gray-500 hover:border-white/15"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Module options */}
        <div className="flex gap-2 flex-wrap">
          {SCAN_OPTIONS.map(opt => (
            <button
              key={opt.key}
              type="button"
              onClick={() => toggleOpt(opt.key)}
              className={`text-[11px] font-mono px-3 py-1 rounded-full border transition-all ${
                activeOpts.has(opt.key)
                  ? "border-[#00d4aa]/50 text-[#00d4aa] bg-[#00d4aa]/8"
                  : "border-white/8 text-gray-600"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Example URLs */}
        <div className="mt-4 flex gap-2 items-center">
          <span className="text-[10px] font-mono text-gray-600">try:</span>
          {EXAMPLE_URLS.map(u => (
            <button
              key={u}
              type="button"
              onClick={() => setUrl(u)}
              className="text-[10px] font-mono text-gray-500 hover:text-[#00d4aa] transition-colors"
            >
              {u}
            </button>
          ))}
        </div>
      </form>

      {error && (
        <div className="mt-4 max-w-2xl mx-auto bg-red-500/8 border border-red-500/20 rounded-xl px-5 py-3 text-[13px] text-red-400 font-mono text-left">
          ⚠ {error}
        </div>
      )}

      {/* Feature grid */}
      <div className="grid grid-cols-3 gap-3 max-w-2xl mx-auto mt-10">
        {[
          { icon: "🔍", title: "20+ Vulnerability Classes", desc: "SQL, XSS, CSRF, IDOR, SSRF, RCE and more" },
          { icon: "📊", title: "Risk Scoring", desc: "CVSS-based severity with actionable fixes" },
          { icon: "⚡", title: "Safe Mode Only", desc: "Non-destructive probes — zero harm guaranteed" },
        ].map(f => (
          <div key={f.title} className="bg-[#0f1318] border border-white/5 rounded-xl p-4 text-left">
            <div className="text-xl mb-2">{f.icon}</div>
            <div className="text-[12px] font-semibold mb-1">{f.title}</div>
            <div className="text-[11px] text-gray-500 leading-relaxed">{f.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
