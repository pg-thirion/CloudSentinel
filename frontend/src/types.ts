export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type FindingStatus = "PASS" | "FAIL" | "ACCESS_DENIED" | "ERROR";

export interface Remediation {
  description: string;
  recommendation: string;
  cli_command: string;
  terraform_fix: string;
  documentation_url?: string;
}

export interface Finding {
  id: string;
  check_id: string;
  check_title: string;
  service: "s3" | "iam" | "encryption" | "ec2";
  severity: SeverityLevel;
  status: FindingStatus;
  status_extended: string;
  resource_id: string;
  resource_arn: string;
  region: string;
  remediation: Remediation;
  compliance: string[];
  timestamp: string;
}

export interface ServiceScore {
  total: number;
  passed: number;
  failed: number;
  access_denied: number;
  score: number;
}

export interface ScanSummary {
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  access_denied_checks: number;
  error_checks: number;
  security_score: number;
  score_band: "CRITICAL" | "POOR" | "FAIR" | "GOOD" | "EXCELLENT";
  is_complete: boolean;
  completeness_percentage: number;
  severity_breakdown: Record<SeverityLevel, number>;
  service_breakdown: Record<string, ServiceScore>;
}

export interface ScoreExplanation {
  formula: string;
  weights: Record<string, number>;
  evaluated_passed_weight: number;
  evaluated_total_weight: number;
  raw_percentage: number;
  score_band: string;
  incomplete_notice: string;
}

export interface ScanApiResponse {
  summary: ScanSummary;
  findings: Finding[];
  score_explanation: ScoreExplanation;
  read_only_verified: boolean;
  mode?: string;
  notice?: string;
  caller?: {
    valid: boolean;
    account_masked: string;
    arn: string;
    user_id: string;
    read_only: boolean;
  };
}
