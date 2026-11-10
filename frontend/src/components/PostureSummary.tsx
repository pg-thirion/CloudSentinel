import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import type { ScanSummary } from "../types";

interface PostureSummaryProps {
  summary: ScanSummary;
  selectedSeverity: string;
  onSelectSeverity: (sev: string) => void;
}

export const PostureSummary: React.FC<PostureSummaryProps> = ({
  summary,
  selectedSeverity,
  onSelectSeverity,
}) => {
  // Color configuration based on ThreatScore band
  const getScoreColor = (score: number) => {
    if (score >= 90) return { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", stroke: "#10b981" };
    if (score >= 75) return { text: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", stroke: "#3b82f6" };
    if (score >= 60) return { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", stroke: "#eab308" };
    if (score >= 40) return { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", stroke: "#f97316" };
    return { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", stroke: "#ef4444" };
  };

  const scoreTheme = getScoreColor(summary.security_score);

  // SVG circular gauge calculation
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (summary.security_score / 100) * circumference;

  return (
    <div className="space-y-4">
      {/* Scan Incomplete / AccessDenied Warning Banner */}
      {!summary.is_complete && (
        <div className="rounded-xl border border-amber-600/40 bg-amber-950/30 p-4 text-amber-300 flex items-start space-x-3 shadow-md">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs space-y-1">
            <div className="font-semibold text-amber-200">
              Incomplete Security Audit Notice — {summary.access_denied_checks} Check(s) Encountered IAM AccessDenied
            </div>
            <p className="text-amber-300/90 leading-relaxed">
              To guarantee zero false confidence, CloudSentinel excludes unassessed resources from the pass rate.
              Audit completeness is currently <strong>{summary.completeness_percentage}%</strong>.
              Attach the standard AWS <code className="bg-amber-950 px-1 py-0.5 rounded text-amber-200 border border-amber-800">SecurityAudit</code> policy to CloudSentinel's execution role to achieve 100% full posture visibility.
            </p>
          </div>
        </div>
      )}

      {/* Main Posture Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Security Score Card (Prowler ThreatScore) */}
        <div className="lg:col-span-4 rounded-2xl border border-gray-800 bg-gray-900/90 p-5 flex items-center justify-between shadow-lg">
          <div className="space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-gray-400">
              Security Score (ThreatScore)
            </div>
            <div className="flex items-baseline space-x-2">
              <span className={`text-4xl font-extrabold ${scoreTheme.text}`}>
                {summary.security_score}%
              </span>
              <span className="text-xs px-2 py-0.5 rounded font-bold uppercase bg-gray-800 text-gray-300 border border-gray-700">
                {summary.score_band}
              </span>
            </div>
            <p className="text-xs text-gray-400">
              Weighted by vulnerability severity & attack surface impact.
            </p>
            <div className="text-xs text-gray-500 flex items-center space-x-3 pt-1">
              <span>Passed: <strong className="text-gray-300">{summary.passed_checks}</strong></span>
              <span>Failed: <strong className="text-gray-300">{summary.failed_checks}</strong></span>
              <span>Denied: <strong className="text-gray-300">{summary.access_denied_checks}</strong></span>
            </div>
          </div>

          {/* Circular Gauge */}
          <div className="relative flex items-center justify-center shrink-0">
            <svg className="w-28 h-28 transform -rotate-90">
              <circle
                cx="56"
                cy="56"
                r={radius}
                className="stroke-gray-800"
                strokeWidth="10"
                fill="transparent"
              />
              <circle
                cx="56"
                cy="56"
                r={radius}
                stroke={scoreTheme.stroke}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: "stroke-dashoffset 0.8s ease-in-out" }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              {summary.security_score >= 75 ? (
                <ShieldCheck className={`h-7 w-7 ${scoreTheme.text}`} />
              ) : (
                <ShieldAlert className={`h-7 w-7 ${scoreTheme.text}`} />
              )}
            </div>
          </div>
        </div>

        {/* Severity Counters Grid */}
        <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {/* Critical Counter */}
          <button
            onClick={() => onSelectSeverity(selectedSeverity === "CRITICAL" ? "ALL" : "CRITICAL")}
            className={`rounded-2xl border p-4 text-left transition cursor-pointer flex flex-col justify-between ${
              selectedSeverity === "CRITICAL"
                ? "border-red-500 bg-red-950/40 shadow-lg shadow-red-950/50"
                : "border-gray-800 bg-gray-900/90 hover:border-red-900/60"
            }`}
          >
            <div className="flex items-center justify-between text-xs text-red-400 font-semibold uppercase">
              <span>Critical</span>
              <AlertOctagon className="h-4 w-4 text-red-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2">
              {summary.severity_breakdown.CRITICAL || 0}
            </div>
            <span className="text-[11px] text-gray-400 mt-1">Weight: 10x impact</span>
          </button>

          {/* High Counter */}
          <button
            onClick={() => onSelectSeverity(selectedSeverity === "HIGH" ? "ALL" : "HIGH")}
            className={`rounded-2xl border p-4 text-left transition cursor-pointer flex flex-col justify-between ${
              selectedSeverity === "HIGH"
                ? "border-amber-500 bg-amber-950/40 shadow-lg shadow-amber-950/50"
                : "border-gray-800 bg-gray-900/90 hover:border-amber-900/60"
            }`}
          >
            <div className="flex items-center justify-between text-xs text-amber-400 font-semibold uppercase">
              <span>High</span>
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2">
              {summary.severity_breakdown.HIGH || 0}
            </div>
            <span className="text-[11px] text-gray-400 mt-1">Weight: 5x impact</span>
          </button>

          {/* Medium / Low Counter */}
          <button
            onClick={() => onSelectSeverity(selectedSeverity === "MEDIUM" ? "ALL" : "MEDIUM")}
            className={`rounded-2xl border p-4 text-left transition cursor-pointer flex flex-col justify-between ${
              selectedSeverity === "MEDIUM"
                ? "border-yellow-500 bg-yellow-950/40 shadow-lg shadow-yellow-950/50"
                : "border-gray-800 bg-gray-900/90 hover:border-yellow-900/60"
            }`}
          >
            <div className="flex items-center justify-between text-xs text-yellow-400 font-semibold uppercase">
              <span>Medium</span>
              <AlertCircle className="h-4 w-4 text-yellow-400" />
            </div>
            <div className="text-3xl font-extrabold text-white mt-2">
              {summary.severity_breakdown.MEDIUM || 0}
            </div>
            <span className="text-[11px] text-gray-400 mt-1">Weight: 3x impact</span>
          </button>

          {/* Passing Checks Counter */}
          <button
            onClick={() => onSelectSeverity(selectedSeverity === "PASS" ? "ALL" : "PASS")}
            className={`rounded-2xl border p-4 text-left transition cursor-pointer flex flex-col justify-between ${
              selectedSeverity === "PASS"
                ? "border-emerald-500 bg-emerald-950/40 shadow-lg shadow-emerald-950/50"
                : "border-gray-800 bg-gray-900/90 hover:border-emerald-900/60"
            }`}
          >
            <div className="flex items-center justify-between text-xs text-emerald-400 font-semibold uppercase">
              <span>Passing</span>
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="text-3xl font-extrabold text-emerald-400 mt-2">
              {summary.passed_checks || 0}
            </div>
            <span className="text-[11px] text-gray-400 mt-1">Compliant configurations</span>
          </button>
        </div>
      </div>
    </div>
  );
};
