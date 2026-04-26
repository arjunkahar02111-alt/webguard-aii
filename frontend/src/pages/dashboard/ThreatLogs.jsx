export default function ThreatLogs() {
  return (
    <div className="space-y-6">
      <div>
         <h1 className="text-2xl font-bold text-white">Threat Logs</h1>
         <p className="text-gray-400 text-sm">Real-time analytical ledger of mitigated vulnerabilities.</p>
      </div>
      
      <div className="glass-panel border border-white/5 bg-bg2/40 overflow-hidden">
         <table className="w-full text-left text-sm text-gray-400">
            <thead className="text-xs uppercase bg-white/5 text-gray-300">
               <tr>
                  <th className="px-6 py-4 font-mono">Timestamp</th>
                  <th className="px-6 py-4 font-mono">Client IP</th>
                  <th className="px-6 py-4 font-mono">End Point</th>
                  <th className="px-6 py-4 font-mono">Type</th>
                  <th className="px-6 py-4 font-mono">Severity</th>
                  <th className="px-6 py-4 font-mono text-right">Action</th>
               </tr>
            </thead>
            <tbody>
               <tr>
                  <td colSpan="6" className="px-6 py-12 text-center border-t border-white/5">
                     No event logs recorded in the current timeframe.
                  </td>
               </tr>
            </tbody>
         </table>
      </div>
    </div>
  );
}
