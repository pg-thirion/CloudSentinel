import React, { useState } from "react";
import { X, Play, Lock, Server, Sparkles } from "lucide-react";

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRunScan: (mode: "demo" | "live") => void;
  isScanning: boolean;
}

export const ScanModal: React.FC<ScanModalProps> = ({
  isOpen,
  onClose,
  onRunScan,
  isScanning,
}) => {
  const [selectedMode, setSelectedMode] = useState<"demo" | "live">("demo");

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="relative w-full max-w-lg rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex items-center justify-between bg-gray-950/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <Play className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Initiate CloudSentinel Scan
              </h2>
              <p className="text-xs text-gray-400">Select scan execution target</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-4 text-xs text-gray-300">
          {/* Option 1: Demo Fleet */}
          <div
            onClick={() => setSelectedMode("demo")}
            className={`p-4 rounded-xl border transition cursor-pointer flex items-start space-x-3 ${
              selectedMode === "demo"
                ? "border-blue-500 bg-blue-950/30 shadow-md shadow-blue-950/40"
                : "border-gray-800 bg-gray-950 hover:border-gray-700"
            }`}
          >
            <Sparkles className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-white text-sm flex items-center space-x-2">
                <span>Prowler Reference Sample Fleet</span>
                <span className="text-[10px] px-2 py-0.2 rounded-full bg-blue-900 text-blue-300 font-semibold">
                  Instant
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed text-xs">
                Audits calibrated mock multi-cloud resources across all 4 categories with known vulnerable, safe, and access-denied cases.
              </p>
            </div>
          </div>

          {/* Option 2: Live AWS Environment */}
          <div
            onClick={() => setSelectedMode("live")}
            className={`p-4 rounded-xl border transition cursor-pointer flex items-start space-x-3 ${
              selectedMode === "live"
                ? "border-blue-500 bg-blue-950/30 shadow-md shadow-blue-950/40"
                : "border-gray-800 bg-gray-950 hover:border-gray-700"
            }`}
          >
            <Server className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-white text-sm flex items-center space-x-2">
                <span>Live AWS Account Scan</span>
                <span className="text-[10px] px-2 py-0.2 rounded-full bg-emerald-900 text-emerald-300 font-semibold">
                  Read-Only
                </span>
              </div>
              <p className="text-gray-400 leading-relaxed text-xs">
                Audits live active AWS resources via the backend Lambda engine using the caller's read-only STS session.
              </p>
            </div>
          </div>

          {/* Safety Notice */}
          <div className="p-3.5 rounded-xl bg-gray-950 border border-emerald-900/40 text-emerald-300 flex items-start space-x-2.5">
            <Lock className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-[11px] leading-relaxed text-emerald-300/90">
              <strong>Zero-Leak Guarantee:</strong> CloudSentinel operates strictly via read-only APIs (<code className="font-mono">Describe*</code>, <code className="font-mono">Get*</code>, <code className="font-mono">List*</code>). Credentials are never stored, logged, or mutated.
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 bg-gray-950/60 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium transition"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              onRunScan(selectedMode);
              onClose();
            }}
            disabled={isScanning}
            className="flex items-center space-x-1.5 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition cursor-pointer"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>{isScanning ? "Scanning..." : "Execute Scan"}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
