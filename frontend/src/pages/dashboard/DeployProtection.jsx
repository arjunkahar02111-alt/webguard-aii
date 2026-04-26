import { useState, useRef, useEffect } from "react";
import ScanForm from "../../components/ScanForm";
import ScanProgress from "../../components/ScanProgress";
import ResultsDashboard from "../../components/ResultsDashboard";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";

export default function DeployProtection() {
  const [phase, setPhase] = useState("idle"); 
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [progress, setProgress] = useState({ pct: 0, module: "initializing..." });
  const [error, setError] = useState("");
  const pollRef = useRef(null);

  async function startScan(url, scanType, modules) {
    setError("");
    setPhase("scanning");
    setProgress({ pct: 5, module: "queuing scan..." });

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, scan_type: scanType }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start scan");
      setScanId(data.scan_id);
      pollScan(data.scan_id);
    } catch (e) {
      setError(e.message);
      setPhase("error");
    }
  }

  function pollScan(id) {
    let attempts = 0;
    const MODULES = [
      "sql-injection", "xss-detection", "csrf-check", "auth-issues", "idor-detection",
      "security-headers", "ssl-tls-check", "cors-config", "cookie-analysis",
      "session-mgmt", "open-redirect", "ssrf-detect", "dir-traversal", "clickjacking",
      "file-upload", "api-security", "dep-vulns", "subdomain-check", "dns-config",
      "perf-audit", "seo-scan"
    ];

    pollRef.current = setInterval(async () => {
      attempts++;
      const modIdx = Math.min(attempts - 1, MODULES.length - 1);
      const pct = Math.min(90, 5 + attempts * 4);
      setProgress({ pct, module: MODULES[modIdx] || "finalizing..." });

      try {
        const res = await fetch(`${API_BASE}/scan/${id}`);
        const data = await res.json();

        if (data.status === "complete") {
          clearInterval(pollRef.current);
          setProgress({ pct: 100, module: "complete ✓" });
          setTimeout(() => {
            setScanData(data);
            setPhase("results");
          }, 600);
        } else if (data.status === "failed") {
          clearInterval(pollRef.current);
          setError(data.error || "Scan failed");
          setPhase("error");
        }
      } catch (e) {
        if (attempts > 30) {
          clearInterval(pollRef.current);
          setError("Lost connection to scanner");
          setPhase("error");
        }
      }
    }, 2000);
  }

  useEffect(() => () => clearInterval(pollRef.current), []);

  function reset() {
    clearInterval(pollRef.current);
    setPhase("idle");
    setScanId(null);
    setScanData(null);
    setError("");
    setProgress({ pct: 0, module: "initializing..." });
  }

  return (
    <div className="max-w-5xl mx-auto pb-20 animate-fade-in-up">
      {(phase === "idle" || phase === "error") && (
        <ScanForm onScan={startScan} error={error} />
      )}
      {phase === "scanning" && (
        <ScanProgress progress={progress} />
      )}
      {phase === "results" && scanData && (
        <ResultsDashboard data={scanData} onRescan={reset} apiBase={API_BASE} scanId={scanId} />
      )}
    </div>
  );
}
