// WebGuard AI — ScoreRing Component
// src/components/ScoreRing.jsx

const RISK_STROKE = {
  CRITICAL: "#ff2d55", HIGH: "#ff4444", MEDIUM: "#ffaa00", LOW: "#00d4aa",
};
const RISK_TEXT = {
  CRITICAL: "text-[#ff2d55]", HIGH: "text-[#ff4444]", MEDIUM: "text-[#ffaa00]", LOW: "text-[#00d4aa]",
};

export default function ScoreRing({ score, risk }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const stroke = RISK_STROKE[risk] || "#00d4aa";
  const textColor = RISK_TEXT[risk] || "text-[#00d4aa]";

  return (
    <div className="relative" style={{ width: 110, height: 110 }}>
      <svg width="110" height="110" viewBox="0 0 100 100" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="50" cy="50" r={r} fill="none" stroke="#151a22" strokeWidth="10" />
        <circle
          cx="50" cy="50" r={r}
          fill="none"
          stroke={stroke}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-mono text-3xl font-bold leading-none ${textColor}`}>{score}</span>
        <span className="font-mono text-[9px] text-gray-600">/100</span>
      </div>
    </div>
  );
}
