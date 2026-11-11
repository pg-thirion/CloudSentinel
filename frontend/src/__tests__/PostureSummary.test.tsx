import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { PostureSummary } from "../components/PostureSummary";
import { initialSampleData } from "../sampleData";

describe("PostureSummary Component", () => {
  it("renders ThreatScore percentage and score band", () => {
    render(
      <PostureSummary
        summary={initialSampleData.summary}
        selectedSeverity="ALL"
        onSelectSeverity={vi.fn()}
      />
    );

    expect(screen.getByText("52.4%")).toBeDefined();
    expect(screen.getByText("POOR")).toBeDefined();
  });

  it("renders incomplete audit warning notice when access denied checks exist", () => {
    render(
      <PostureSummary
        summary={initialSampleData.summary}
        selectedSeverity="ALL"
        onSelectSeverity={vi.fn()}
      />
    );

    expect(
      screen.getByText(/Incomplete Security Audit Notice/i)
    ).toBeDefined();
  });
});
