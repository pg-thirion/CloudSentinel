import React, { useState } from "react";
import { Header } from "./components/Header";
import { PostureSummary } from "./components/PostureSummary";
import { CategoryPillars } from "./components/CategoryPillars";
import { FindingsTable } from "./components/FindingsTable";
import { RemediationModal } from "./components/RemediationModal";
import { ScoreExplanationModal } from "./components/ScoreExplanationModal";
import { ScanModal } from "./components/ScanModal";
import type { Finding, ScanApiResponse } from "./types";
import { initialSampleData } from "./sampleData";

export const App: React.FC = () => {
  const [scanData, setScanData] = useState<ScanApiResponse>(initialSampleData);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedService, setSelectedService] = useState<string>("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isScoreModalOpen, setIsScoreModalOpen] = useState(false);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);

  // Scan handler
  const handleRunScan = async (mode: "demo" | "live") => {
    setIsScanning(true);
    try {
      if (mode === "demo") {
        // Fast mock scan simulation with realistic telemetry
        await new Promise((resolve) => setTimeout(resolve, 600));
        setScanData({
          ...initialSampleData,
          mode: "DEMO_ENVIRONMENT",
          notice: "Scan completed: Prowler standard reference audit dataset refreshed.",
        });
      } else {
        // Attempt live API call to backend Lambda / API Gateway
        try {
          const res = await fetch("/api/scan");
          if (res.ok) {
            const data: ScanApiResponse = await res.json();
            setScanData(data);
          } else {
            throw new Error(`HTTP ${res.status}`);
          }
        } catch (err) {
          // Explicitly report backend connection failure instead of faking a live scan
          const errMsg = err instanceof Error ? err.message : String(err);
          setScanData((prev) => ({
            ...prev,
            notice: `Live scan request failed: ${errMsg}. Backend scanner endpoint unreachable. Displaying cached baseline findings.`,
          }));
        }
      }
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] text-gray-100 flex flex-col font-sans selection:bg-blue-500 selection:text-white">
      {/* Top Navigation */}
      <Header
        onTriggerScan={() => setIsScanModalOpen(true)}
        isScanning={isScanning}
        mode={scanData.mode || "DEMO_ENVIRONMENT"}
        readOnlyVerified={scanData.read_only_verified}
        onOpenScoreExplanation={() => setIsScoreModalOpen(true)}
      />

      {/* Main Content Dashboard */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6 space-y-6">
        {/* Notice Banner (if any) */}
        {scanData.notice && (
          <div className="px-4 py-2.5 rounded-xl bg-blue-950/40 border border-blue-800/60 text-xs text-blue-300 flex items-center justify-between">
            <span>{scanData.notice}</span>
            <span className="text-[10px] text-blue-400 font-mono">Status: Verified</span>
          </div>
        )}

        {/* Posture Score & Severity Row */}
        <PostureSummary
          summary={scanData.summary}
          selectedSeverity={selectedSeverity}
          onSelectSeverity={(sev) => setSelectedSeverity(sev)}
        />

        {/* 4 Security Pillars */}
        <CategoryPillars
          serviceBreakdown={scanData.summary.service_breakdown}
          selectedService={selectedService}
          onSelectService={(svc) => setSelectedService(svc)}
        />

        {/* Interactive Findings Table */}
        <FindingsTable
          findings={scanData.findings}
          selectedService={selectedService}
          selectedSeverity={selectedSeverity}
          onSelectService={(svc) => setSelectedService(svc)}
          onSelectSeverity={(sev) => setSelectedSeverity(sev)}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 bg-gray-950/50 py-4 px-6 text-center text-xs text-gray-500">
        CloudSentinel CSPM — AWS Security Posture Auditing. Calibrated against Prowler security checks and dashboard standards.
      </footer>

      {/* Remediation Modal Drawer */}
      <RemediationModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {/* Score Explanation Modal */}
      {isScoreModalOpen && (
        <ScoreExplanationModal
          explanation={scanData.score_explanation}
          onClose={() => setIsScoreModalOpen(false)}
        />
      )}

      {/* Run Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onRunScan={handleRunScan}
        isScanning={isScanning}
      />
    </div>
  );
};

export default App;
