import React from "react";
import { Shield, RefreshCw, Lock, AlertCircle, Database } from "lucide-react";

interface HeaderProps {
  onTriggerScan: () => void;
  isScanning: boolean;
  mode: string;
  readOnlyVerified: boolean;
  onOpenScoreExplanation: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onTriggerScan,
  isScanning,
  mode,
  readOnlyVerified: _readOnlyVerified,
  onOpenScoreExplanation,
}) => {
  return (
    <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-30 px-6 py-4">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Logo & Title */}
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-blue-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold tracking-tight text-white">CloudSentinel</h1>
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-950 text-blue-400 border border-blue-800 font-semibold">
                CSPM
              </span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 border border-gray-700">
                Prowler-Calibrated
              </span>
            </div>
            <p className="text-xs text-gray-400">
              Automated AWS Security & Compliance Posture Management
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center flex-wrap gap-3">
          {/* Read-Only Status Indicator */}
          <div
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 text-xs font-medium"
            title="CloudSentinel uses strictly read-only AWS APIs (Describe/Get/List). Credentials are never stored, logged, or capable of mutations."
          >
            <Lock className="h-3.5 w-3.5 text-emerald-400" />
            <span>Read-Only Enforced</span>
          </div>

          {/* Mode Badge */}
          <div className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 text-xs font-medium">
            <Database className="h-3.5 w-3.5 text-cyan-400" />
            <span>{mode === "LIVE_AWS_SCAN" ? "Live AWS Scan" : "Prowler Standard Demo"}</span>
          </div>

          {/* How Score Works Button */}
          <button
            onClick={onOpenScoreExplanation}
            className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs font-medium transition cursor-pointer"
          >
            <AlertCircle className="h-3.5 w-3.5 text-blue-400" />
            <span>Score Formula</span>
          </button>

          {/* Run Scan Button */}
          <button
            onClick={onTriggerScan}
            disabled={isScanning}
            className="flex items-center space-x-2 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-semibold shadow-md shadow-blue-600/30 transition cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isScanning ? "animate-spin" : ""}`} />
            <span>{isScanning ? "Scanning Fleet..." : "Run Security Scan"}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
