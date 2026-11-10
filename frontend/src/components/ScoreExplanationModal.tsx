import React from "react";
import { X, Calculator, AlertTriangle, Layers, Award } from "lucide-react";
import type { ScoreExplanation } from "../types";

interface ScoreExplanationModalProps {
  explanation?: ScoreExplanation;
  onClose: () => void;
}

export const ScoreExplanationModal: React.FC<ScoreExplanationModalProps> = ({
  explanation: _explanation,
  onClose,
}) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="relative w-full max-w-2xl rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex items-center justify-between bg-gray-950/60">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30">
              <Calculator className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Security Score Calculation Methodology
              </h2>
              <p className="text-xs text-gray-400">
                Prowler ThreatScore-Calibrated Weighted Compliance Engine
              </p>
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
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-gray-300">
          {/* Formula Card */}
          <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
            <div className="text-[11px] font-semibold uppercase text-blue-400 tracking-wider">
              Mathematical Scoring Formula
            </div>
            <div className="font-mono text-sm text-white font-bold p-3 rounded-lg bg-gray-900 border border-gray-800 text-center">
              Score = ( ∑ (Passed Checks × Severity Weight) / ∑ (Evaluated Checks × Severity Weight) ) × 100%
            </div>
            <p className="text-gray-400 leading-relaxed text-[11px] pt-1">
              Unlike simplistic unweighted check ratios, CloudSentinel aligns with the Prowler ThreatScore standard:
              high-severity exposures (such as public S3 buckets or unrestricted SSH) carry heavy penalties, while low-severity issues do not disproportionately degrade overall posture.
            </p>
          </div>

          {/* Severity Weights Table */}
          <div className="space-y-2">
            <div className="flex items-center space-x-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <span>Severity Point Weights</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="p-3 rounded-xl bg-gray-950 border border-red-900/40 text-center">
                <div className="text-xs font-bold text-red-400">CRITICAL</div>
                <div className="text-2xl font-extrabold text-white mt-1">10 pts</div>
                <div className="text-[10px] text-gray-500 mt-0.5">Highest threat</div>
              </div>
              <div className="p-3 rounded-xl bg-gray-950 border border-amber-900/40 text-center">
                <div className="text-xs font-bold text-amber-400">HIGH</div>
                <div className="text-2xl font-extrabold text-white mt-1">5 pts</div>
                <div className="text-[10px] text-gray-500 mt-0.5">Substantial risk</div>
              </div>
              <div className="p-3 rounded-xl bg-gray-950 border border-yellow-900/40 text-center">
                <div className="text-xs font-bold text-yellow-400">MEDIUM</div>
                <div className="text-2xl font-extrabold text-white mt-1">3 pts</div>
                <div className="text-[10px] text-gray-500 mt-0.5">Moderate risk</div>
              </div>
              <div className="p-3 rounded-xl bg-gray-950 border border-blue-900/40 text-center">
                <div className="text-xs font-bold text-blue-400">LOW</div>
                <div className="text-2xl font-extrabold text-white mt-1">1 pt</div>
                <div className="text-[10px] text-gray-500 mt-0.5">Minor deviation</div>
              </div>
            </div>
          </div>

          {/* Health Tier Bands */}
          <div className="space-y-2">
            <div className="flex items-center space-x-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              <Award className="h-3.5 w-3.5 text-purple-400" />
              <span>Posture Health Bands</span>
            </div>
            <div className="grid grid-cols-5 gap-1.5 text-center font-semibold">
              <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400">
                <div className="text-[10px] uppercase">Excellent</div>
                <div className="text-xs mt-0.5">90 - 100%</div>
              </div>
              <div className="p-2 rounded-lg bg-blue-950/60 border border-blue-800 text-blue-400">
                <div className="text-[10px] uppercase">Good</div>
                <div className="text-xs mt-0.5">75 - 89%</div>
              </div>
              <div className="p-2 rounded-lg bg-yellow-950/60 border border-yellow-800 text-yellow-400">
                <div className="text-[10px] uppercase">Fair</div>
                <div className="text-xs mt-0.5">60 - 74%</div>
              </div>
              <div className="p-2 rounded-lg bg-orange-950/60 border border-orange-800 text-orange-400">
                <div className="text-[10px] uppercase">Poor</div>
                <div className="text-xs mt-0.5">40 - 59%</div>
              </div>
              <div className="p-2 rounded-lg bg-red-950/60 border border-red-800 text-red-400">
                <div className="text-[10px] uppercase">Critical</div>
                <div className="text-xs mt-0.5">&lt; 40%</div>
              </div>
            </div>
          </div>

          {/* Strict Separation of AccessDenied / Incomplete Scans */}
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/60 text-amber-200 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-bold text-amber-300">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <span>Strict Guarantee: Incomplete Scans Are Never Masked as Healthy</span>
            </div>
            <p className="text-[11px] text-amber-200/90 leading-relaxed">
              When AWS APIs return <code className="bg-amber-950 px-1 py-0.5 rounded border border-amber-800">AccessDenied</code> or insufficient IAM privileges, many legacy tools silently pass or ignore the check.
              CloudSentinel strictly classifies these as <strong>ACCESS_DENIED</strong>.
              They are <strong>excluded</strong> from passed points so they cannot falsely inflate the posture score.
              The scan banner prominently displays the scan completeness percentage until full read access is provided.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 bg-gray-950/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition"
          >
            Understood
          </button>
        </div>
      </div>
    </div>
  );
};
