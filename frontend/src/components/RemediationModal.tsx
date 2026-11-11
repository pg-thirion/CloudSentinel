import React, { useState } from "react";
import { X, Copy, Check, Terminal, Code2, ExternalLink } from "lucide-react";
import type { Finding } from "../types";

interface RemediationModalProps {
  finding: Finding | null;
  onClose: () => void;
}

export const RemediationModal: React.FC<RemediationModalProps> = ({ finding, onClose }) => {
  const [activeTab, setActiveTab] = useState<"cli" | "terraform" | "console">("cli");
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="relative w-full max-w-3xl rounded-2xl border border-gray-800 bg-gray-900 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex items-start justify-between bg-gray-950/60">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span
                className={`text-[11px] font-extrabold px-2 py-0.5 rounded border ${
                  finding.status === "PASS"
                    ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                    : finding.severity === "CRITICAL"
                    ? "bg-red-950 text-red-400 border-red-800"
                    : finding.severity === "HIGH"
                    ? "bg-amber-950 text-amber-400 border-amber-800"
                    : "bg-blue-950 text-blue-400 border-blue-800"
                }`}
              >
                {finding.status === "PASS" ? "COMPLIANT" : finding.severity}
              </span>
              <span className="text-xs font-bold uppercase tracking-wider text-gray-400">
                {finding.service.toUpperCase()} POSTURE AUDIT
              </span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-300 font-mono">
                {finding.region}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">{finding.check_title}</h2>
            <p className="text-xs text-gray-400 font-mono">{finding.check_id}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs text-gray-300">
          {/* Resource Details Card */}
          <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2">
            <div className="text-[11px] font-semibold uppercase text-gray-400">Affected Target Resource</div>
            <div className="font-mono text-sm text-white font-semibold break-all">
              {finding.resource_id}
            </div>
            <div className="font-mono text-xs text-gray-500 break-all">
              {finding.resource_arn}
            </div>
          </div>

          {/* Finding Status & Risk Description */}
          <div className="space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              Evaluation & Risk Finding
            </div>
            <div className="p-3.5 rounded-xl bg-gray-950/70 border border-gray-800 leading-relaxed text-gray-200">
              {finding.status_extended}
            </div>
          </div>

          {/* Security Recommendation */}
          <div className="space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-blue-400">
              Remediation Guidance
            </div>
            <p className="text-gray-300 leading-relaxed">
              {finding.remediation.recommendation}
            </p>
          </div>

          {/* Remediation Snippet Tabs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-gray-800 pb-2">
              <div className="flex space-x-2">
                <button
                  onClick={() => setActiveTab("cli")}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === "cli"
                      ? "bg-blue-600 text-white shadow-md shadow-blue-600/30"
                      : "bg-gray-800 text-gray-400 hover:text-white"
                  }`}
                >
                  <Terminal className="h-3.5 w-3.5" />
                  <span>AWS CLI Command</span>
                </button>
                <button
                  onClick={() => setActiveTab("terraform")}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === "terraform"
                      ? "bg-blue-600 text-white shadow-md shadow-blue-600/30"
                      : "bg-gray-800 text-gray-400 hover:text-white"
                  }`}
                >
                  <Code2 className="h-3.5 w-3.5" />
                  <span>Terraform IaC</span>
                </button>
              </div>

              {/* Copy snippet button */}
              <button
                onClick={() =>
                  handleCopy(
                    activeTab === "cli"
                      ? finding.remediation.cli_command
                      : finding.remediation.terraform_fix
                  )
                }
                className="flex items-center space-x-1 px-3 py-1 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition"
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy Fix</span>
                  </>
                )}
              </button>
            </div>

            {/* Code View */}
            <div className="relative rounded-xl bg-gray-950 p-4 border border-gray-800 font-mono text-xs overflow-x-auto text-blue-200">
              <pre className="whitespace-pre-wrap leading-relaxed">
                {activeTab === "cli"
                  ? finding.remediation.cli_command || "# No CLI fix applicable"
                  : finding.remediation.terraform_fix || "# No Terraform fix required"}
              </pre>
            </div>
          </div>

          {/* Compliance Frameworks */}
          {finding.compliance && finding.compliance.length > 0 && (
            <div className="pt-2">
              <div className="text-[11px] font-semibold uppercase text-gray-400 mb-1.5">
                Compliance Mappings
              </div>
              <div className="flex flex-wrap gap-1.5">
                {finding.compliance.map((c) => (
                  <span
                    key={c}
                    className="px-2 py-0.5 rounded text-[11px] bg-gray-800 text-gray-300 border border-gray-700 font-mono"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 bg-gray-950/60 flex items-center justify-between">
          {finding.remediation.documentation_url ? (
            <a
              href={finding.remediation.documentation_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center text-xs text-blue-400 hover:text-blue-300 font-medium"
            >
              <span>AWS Security Best Practices Documentation</span>
              <ExternalLink className="h-3.5 w-3.5 ml-1" />
            </a>
          ) : (
            <div />
          )}
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-white text-xs font-semibold transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
