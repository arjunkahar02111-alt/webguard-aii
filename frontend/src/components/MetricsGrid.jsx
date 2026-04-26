// WebGuard AI — MetricsGrid Component
// src/components/MetricsGrid.jsx

function cls(v, goodVals = ["present","enabled","found","good","detected"]) {
  if (!v && v !== 0) return "text-gray-600";
  const s = String(v).toLowerCase();
  if (goodVals.includes(s) || s === "a+" || s === "a") return "text-[#00d4aa]";
  if (["weak","poor","missing","disabled","not found","not detected","b"].includes(s)) return "text-[#ffaa00]";
  if (["absent","error","no","f","c"].includes(s)) return "text-[#ff4444]";
  return "text-white";
}

function numCls(v, good, warn) {
  if (v <= good) return "text-[#00d4aa]";
  if (v <= warn) return "text-[#ffaa00]";
  return "text-[#ff4444]";
}

function Row({ label, value, valueClass }) {
  return (
    <div className="flex justify-between items-center py-1.5 border-b border-white/4 last:border-0">
      <span className="text-[11px] text-gray-500">{label}</span>
      <span className={`font-mono text-[11px] font-bold ${valueClass}`}>{value}</span>
    </div>
  );
}

function Panel({ title, rows }) {
  return (
    <div className="bg-[#0f1318] border border-white/6 rounded-xl p-4">
      <div className="font-mono text-[9px] uppercase tracking-[1.5px] text-gray-600 mb-3">{title}</div>
      {rows.map(r => <Row key={r.label} {...r} />)}
    </div>
  );
}

export default function MetricsGrid({ perf, seo, headers, ssl }) {
  const hasPerfData = perf && Object.keys(perf).length > 0;
  const hasSeoData  = seo  && Object.keys(seo).length  > 0;

  return (
    <div className="grid grid-cols-2 gap-3">
      {hasPerfData && (
        <Panel title="// performance" rows={[
          { label: "Load Time",   value: `${perf.load_time_ms}ms`, valueClass: numCls(perf.load_time_ms, 1000, 3000) },
          { label: "TTFB",        value: `${perf.ttfb_ms}ms`,      valueClass: numCls(perf.ttfb_ms, 200, 600) },
          { label: "Page Size",   value: `${perf.page_size_kb}KB`, valueClass: numCls(perf.page_size_kb, 200, 1000) },
          { label: "Requests",    value: perf.requests,            valueClass: numCls(perf.requests, 30, 60) },
          { label: "Compression", value: perf.compression,         valueClass: cls(perf.compression) },
          { label: "Caching",     value: perf.caching,             valueClass: cls(perf.caching) },
          { label: "CDN",         value: perf.cdn,                 valueClass: cls(perf.cdn) },
          { label: "Score",       value: `${perf.score}/100`,      valueClass: numCls(100 - (perf.score||0), 30, 60) },
        ]} />
      )}

      {hasSeoData && (
        <Panel title="// SEO" rows={[
          { label: "Title Tag",       value: seo.title_tag,       valueClass: cls(seo.title_tag) },
          { label: "Meta Description",value: seo.meta_description, valueClass: cls(seo.meta_description) },
          { label: "H1 Tags",         value: seo.h1_tags,          valueClass: seo.h1_tags === 1 ? "text-[#00d4aa]" : seo.h1_tags === 0 ? "text-[#ff4444]" : "text-[#ffaa00]" },
          { label: "Canonical",       value: seo.canonical,        valueClass: cls(seo.canonical) },
          { label: "Sitemap",         value: seo.sitemap,          valueClass: cls(seo.sitemap) },
          { label: "Robots.txt",      value: seo.robots_txt,       valueClass: cls(seo.robots_txt) },
          { label: "Broken Links",    value: seo.broken_links,     valueClass: seo.broken_links === 0 ? "text-[#00d4aa]" : "text-[#ff4444]" },
          { label: "Score",           value: `${seo.score}/100`,   valueClass: numCls(100 - (seo.score||0), 30, 60) },
        ]} />
      )}

      <Panel title="// security headers" rows={[
        { label: "X-Frame-Options",    value: headers.x_frame_options || "absent",  valueClass: cls(headers.x_frame_options) },
        { label: "CSP",                value: headers.csp || "absent",              valueClass: cls(headers.csp) },
        { label: "X-Content-Type",     value: headers.x_content_type || "absent",   valueClass: cls(headers.x_content_type) },
        { label: "Referrer-Policy",    value: headers.referrer_policy || "absent",  valueClass: cls(headers.referrer_policy) },
        { label: "Permissions-Policy", value: headers.permissions_policy || "absent",valueClass: cls(headers.permissions_policy) },
      ]} />

      <Panel title="// SSL / TLS" rows={[
        { label: "Certificate Valid", value: ssl.valid ? "yes" : "no",   valueClass: ssl.valid ? "text-[#00d4aa]" : "text-[#ff4444]" },
        { label: "Grade",             value: ssl.grade || "N/A",          valueClass: cls(ssl.grade) },
        { label: "Expires In",        value: `${ssl.expires_days ?? "?"} days`, valueClass: numCls(ssl.expires_days > 0 ? 0 : 999, 60, 14) },
        { label: "Protocol",          value: ssl.protocol || "unknown",   valueClass: ssl.protocol === "TLS 1.3" ? "text-[#00d4aa]" : ssl.protocol === "TLS 1.2" ? "text-[#ffaa00]" : "text-[#ff4444]" },
        { label: "HSTS",              value: ssl.hsts || "absent",        valueClass: cls(ssl.hsts) },
      ]} />
    </div>
  );
}
