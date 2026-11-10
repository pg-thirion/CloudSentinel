import React, { useState, useMemo } from "react";
import {
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Copy,
  Check,
  MapPin,
} from "lucide-react";
import type { Finding, FindingStatus, SeverityLevel } from "../types";

interface FindingsTableProps {
  findings: Finding[];
  selectedService: string;
  selectedSeverity: string;
  onSelectService: (svc: string) => void;
  onSelectSeverity: (sev: string) => void;
  onSelectFinding: (finding: Finding) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  selectedService,
  selectedSeverity,
  onSelectService,
  onSelectSeverity,
  onSelectFinding,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Copy command helper
  const handleCopy = (id: string, text: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filtered & searched findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Category filter
      if (selectedService !== "ALL" && f.service !== selectedService) return false;

      // Severity filter
      if (selectedSeverity !== "ALL") {
        if (selectedSeverity === "PASS") {
          if (f.status !== "PASS") return false;
        } else {
          // Severity cards represent failing/vulnerable findings
          if (f.severity !== selectedSeverity || f.status === "PASS") return false;
        }
      }

      // Status filter
      if (statusFilter !== "ALL" && f.status !== statusFilter) return false;

      // Search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesResource = f.resource_id.toLowerCase().includes(query);
        const matchesTitle = f.check_title.toLowerCase().includes(query);
        const matchesId = f.check_id.toLowerCase().includes(query);
        const matchesArn = f.resource_arn.toLowerCase().includes(query);
        const matchesDesc = f.status_extended.toLowerCase().includes(query);
        if (!matchesResource && !matchesTitle && !matchesId && !matchesArn && !matchesDesc) {
          return false;
        }
      }

      return true;
    });
  }, [findings, selectedService, selectedSeverity, statusFilter, searchQuery]);

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-red-950/80 text-red-400 border-red-800";
      case "HIGH":
        return "bg-amber-950/80 text-amber-400 border-amber-800";
      case "MEDIUM":
        return "bg-yellow-950/80 text-yellow-400 border-yellow-800";
      case "LOW":
        return "bg-blue-950/80 text-blue-400 border-blue-800";
      default:
        return "bg-gray-800 text-gray-400 border-gray-700";
    }
  };

  const getStatusBadge = (status: FindingStatus) => {
    switch (status) {
      case "PASS":
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="h-3 w-3 mr-1" /> PASS
          </span>
        );
      case "FAIL":
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-950/80 text-red-400 border border-red-800">
            <XCircle className="h-3 w-3 mr-1" /> FAIL
          </span>
        );
      case "ACCESS_DENIED":
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
            <AlertTriangle className="h-3 w-3 mr-1" /> ACCESS DENIED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-gray-800 text-gray-400 border border-gray-700">
            ERROR
          </span>
        );
    }
  };

  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/90 shadow-xl overflow-hidden">
      {/* Controls Bar */}
      <div className="p-4 border-b border-gray-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search affected resource, ARN, check title or rule..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center flex-wrap gap-2">
          {/* Category Filter */}
          <select
            value={selectedService}
            onChange={(e) => onSelectService(e.target.value)}
            className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Categories</option>
            <option value="s3">S3 Storage</option>
            <option value="iam">IAM Governance</option>
            <option value="encryption">Encryption</option>
            <option value="ec2">Security Groups</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => onSelectSeverity(e.target.value)}
            className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="PASS">Passing Only</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="FAIL">Failed (Vulnerable)</option>
            <option value="PASS">Passed (Safe)</option>
            <option value="ACCESS_DENIED">Access Denied (Incomplete)</option>
          </select>

          {/* Result Count */}
          <span className="text-xs text-gray-400 ml-2">
            Showing <strong className="text-gray-200">{filteredFindings.length}</strong> of{" "}
            {findings.length} findings
          </span>
        </div>
      </div>

      {/* Findings Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-gray-800 bg-gray-950/60 text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Security Check</th>
              <th className="py-3 px-4">Affected Resource</th>
              <th className="py-3 px-4">Region</th>
              <th className="py-3 px-4 text-right">Remediation Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 text-xs">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500">
                  No security findings match your current filters.
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className="hover:bg-gray-800/40 transition cursor-pointer group"
                >
                  {/* Severity */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[11px] font-extrabold border ${
                        finding.status === "PASS"
                          ? "bg-emerald-950/40 text-emerald-400 border-emerald-800/60"
                          : getSeverityBadge(finding.severity)
                      }`}
                    >
                      {finding.status === "PASS" ? "COMPLIANT" : finding.severity}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    {getStatusBadge(finding.status)}
                  </td>

                  {/* Security Check */}
                  <td className="py-3.5 px-4 max-w-xs">
                    <div className="font-semibold text-gray-200 group-hover:text-blue-400 transition">
                      {finding.check_title}
                    </div>
                    <div className="text-[11px] text-gray-400 truncate mt-0.5">
                      {finding.check_id}
                    </div>
                  </td>

                  {/* Affected Resource */}
                  <td className="py-3.5 px-4 max-w-sm">
                    <div className="font-mono text-gray-200 font-medium truncate">
                      {finding.resource_id}
                    </div>
                    <div className="text-[11px] text-gray-500 truncate mt-0.5">
                      {finding.resource_arn}
                    </div>
                  </td>

                  {/* Region */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span className="inline-flex items-center text-gray-400 text-xs font-mono">
                      <MapPin className="h-3 w-3 mr-1 text-gray-500" />
                      {finding.region}
                    </span>
                  </td>

                  {/* Remediation Action */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <div className="inline-flex items-center space-x-2">
                      {finding.remediation.cli_command && (
                        <button
                          onClick={(e) =>
                            handleCopy(finding.id, finding.remediation.cli_command, e)
                          }
                          className="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 transition"
                          title="Copy AWS CLI Remediation Command"
                        >
                          {copiedId === finding.id ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding);
                        }}
                        className="px-3 py-1 rounded-lg bg-blue-950/60 hover:bg-blue-900 border border-blue-800 text-blue-300 text-xs font-medium transition"
                      >
                        Inspect Fix
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
