import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { RemediationModal } from "../components/RemediationModal";
import type { Finding } from "../types";

const mockPassingCriticalFinding: Finding = {
  id: "test-pass-1",
  check_id: "s3_bucket_public_access",
  check_title: "Ensure Amazon S3 Buckets Prohibit Public Access",
  service: "s3",
  severity: "CRITICAL",
  status: "PASS",
  status_extended: "Bucket is secure and compliant.",
  resource_id: "secure-bucket-demo",
  resource_arn: "arn:aws:s3:::secure-bucket-demo",
  region: "us-east-1",
  remediation: {
    description: "Bucket is secure.",
    recommendation: "Maintain configuration.",
    cli_command: "# compliant",
    terraform_fix: "# compliant",
  },
  compliance: ["CIS-AWS-1.4:2.1.5"],
  timestamp: new Date().toISOString(),
};

const mockFailingCriticalFinding: Finding = {
  ...mockPassingCriticalFinding,
  id: "test-fail-1",
  status: "FAIL",
  status_extended: "Bucket is public to the internet.",
};

describe("RemediationModal Component", () => {
  it("renders COMPLIANT badge for passing checks instead of CRITICAL danger badge", () => {
    render(<RemediationModal finding={mockPassingCriticalFinding} onClose={vi.fn()} />);
    expect(screen.getByText("COMPLIANT")).toBeDefined();
    expect(screen.queryByText("CRITICAL")).toBeNull();
  });

  it("renders CRITICAL badge for failing checks", () => {
    render(<RemediationModal finding={mockFailingCriticalFinding} onClose={vi.fn()} />);
    expect(screen.getByText("CRITICAL")).toBeDefined();
  });
});
