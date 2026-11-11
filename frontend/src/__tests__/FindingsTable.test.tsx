import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { FindingsTable } from "../components/FindingsTable";
import { initialSampleData } from "../sampleData";

describe("FindingsTable Component", () => {
  it("renders all sample findings by default", () => {
    const handleSelectService = vi.fn();
    const handleSelectSeverity = vi.fn();
    const handleSelectFinding = vi.fn();

    render(
      <FindingsTable
        findings={initialSampleData.findings}
        selectedService="ALL"
        selectedSeverity="ALL"
        onSelectService={handleSelectService}
        onSelectSeverity={handleSelectSeverity}
        onSelectFinding={handleSelectFinding}
      />
    );

    expect(screen.getAllByText(/prod-financial-reports-2026/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/internal-app-audit-logs/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/DeveloperSelfProvisioningPolicy/i).length).toBeGreaterThan(0);
  });

  it("filters findings by search query", () => {
    render(
      <FindingsTable
        findings={initialSampleData.findings}
        selectedService="ALL"
        selectedSeverity="ALL"
        onSelectService={() => {}}
        onSelectSeverity={() => {}}
        onSelectFinding={() => {}}
      />
    );

    const searchInput = screen.getByPlaceholderText(/search affected resource/i);
    fireEvent.change(searchInput, { target: { value: "customer-billing" } });

    expect(screen.getAllByText(/customer-billing-db-01/i).length).toBeGreaterThan(0);
    expect(screen.queryByText("prod-financial-reports-2026")).toBeNull();
  });

  it("does not hide passing critical findings when critical severity is selected", () => {
    render(
      <FindingsTable
        findings={initialSampleData.findings}
        selectedService="ALL"
        selectedSeverity="CRITICAL"
        onSelectService={() => {}}
        onSelectSeverity={() => {}}
        onSelectFinding={() => {}}
      />
    );

    // Both failing critical and passing critical findings should remain visible
    expect(screen.getAllByText(/prod-financial-reports-2026/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/internal-app-audit-logs/i).length).toBeGreaterThan(0);
  });
});
