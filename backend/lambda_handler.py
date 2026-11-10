"""
CloudSentinel AWS Lambda Handler & API Gateway Adapter
Provides serverless scan execution, credential protection, CORS headers,
and detailed scoring breakdown.
"""
import json
import os
import boto3
from typing import Dict, Any
from scanner.engine import CloudSentinelEngine, CredentialProtector
from scanner.mock_data import get_mock_scan_response
from scanner.scoring import SEVERITY_WEIGHTS


CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Content-Type": "application/json",
}


def build_response(status_code: int, body_data: Any) -> Dict[str, Any]:
    """Build API Gateway compatible HTTP response."""
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body_data),
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point.
    Handles HTTP API / REST API events or direct invocations.
    """
    # Handle CORS preflight
    http_method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or "GET"
    )
    if http_method == "OPTIONS":
        return build_response(200, {"message": "CORS OK"})

    path = (
        event.get("requestContext", {}).get("http", {}).get("path")
        or event.get("path")
        or "/"
    )

    query_params = event.get("queryStringParameters") or {}
    mode = query_params.get("mode", os.environ.get("SCAN_MODE", "auto")).lower()

    # Route: Health check
    if path in ("/health", "/api/health"):
        return build_response(
            200,
            {
                "status": "healthy",
                "service": "CloudSentinel AWS Scanner",
                "version": "1.0.0",
                "read_only_mode": True,
                "supported_categories": [
                    "s3_bucket_public_access",
                    "iam_risky_policies",
                    "missing_encryption",
                    "exposed_security_groups",
                ],
            },
        )

    # Route: Score Explanation
    if path in ("/api/score-explanation", "/score-explanation"):
        return build_response(
            200,
            {
                "name": "CloudSentinel ThreatScore",
                "formula": "Score = (Weighted Passed Points / Total Evaluated Points) * 100",
                "weights": {k.value: v for k, v in SEVERITY_WEIGHTS.items() if v > 0},
                "bands": {
                    "EXCELLENT": "90% - 100%",
                    "GOOD": "75% - 89.9%",
                    "FAIR": "60% - 74.9%",
                    "POOR": "40% - 59.9%",
                    "CRITICAL": "0% - 39.9%",
                },
                "incomplete_handling": (
                    "Checks returning AccessDenied / ClientError are categorized as ACCESS_DENIED. "
                    "They do not count as PASS to avoid false positive security confidence. "
                    "Incomplete scans are explicitly separated from healthy results."
                ),
            },
        )

    # Route: Scan
    if path in ("/", "/scan", "/api/scan"):
        # If demo mode requested or if AWS credentials not found
        if mode == "demo":
            return build_response(200, get_mock_scan_response())

        try:
            # Attempt real scan with read-only boto3 session
            session = boto3.Session()
            engine = CloudSentinelEngine(session=session)
            
            # First verify caller identity (read-only verification)
            caller_info = engine.verify_read_only_access()
            if not caller_info.get("valid"):
                # If no AWS credentials or invalid, fallback cleanly to demo dataset with clear notation
                response = get_mock_findings_response_with_note(caller_info.get("error", "No AWS credentials detected"))
                return build_response(200, response)

            result = engine.run_all_checks()
            result["caller"] = caller_info
            result["mode"] = "LIVE_AWS_SCAN"
            return build_response(200, result)

        except Exception as e:
            redacted_err = CredentialProtector.redact(str(e))
            # Fail safely to demo dataset with error disclosure
            response = get_mock_findings_response_with_note(f"Scan fallback: {redacted_err}")
            return build_response(200, response)

    return build_response(404, {"error": "Not Found", "path": path})


def get_mock_findings_response_with_note(note: str) -> Dict[str, Any]:
    """Helper returning mock scan with notification of credential status."""
    res = get_mock_scan_response()
    res["notice"] = (
        f"Displaying demo security audit findings (Standard reference environment). "
        f"Reason: {note}. Connect live AWS credentials or execute in Lambda to scan real resources."
    )
    return res


# Allow local standalone testing with python
if __name__ == "__main__":
    resp = lambda_handler({"path": "/api/scan", "httpMethod": "GET"}, None)
    print("Lambda Handler Output Status:", resp["statusCode"])
    data = json.loads(resp["body"])
    print("Security Score:", data["summary"]["security_score"])
    print("Completeness:", data["summary"]["completeness_percentage"])
    print("Total Findings:", len(data["findings"]))
