"""
CloudSentinel Security Scoring Engine
Implements Prowler ThreatScore-calibrated weighted compliance scoring,
with explicit mathematical explanation and strict separation of incomplete / access-denied results.
"""
from typing import List, Dict, Any, Tuple
from .models import Finding, Severity, Status, ScanSummary


SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFORMATIONAL: 0.0,
}


def calculate_score_band(score: float) -> str:
    """Return health band corresponding to ThreatScore percentage."""
    if score >= 90.0:
        return "EXCELLENT"
    elif score >= 75.0:
        return "GOOD"
    elif score >= 60.0:
        return "FAIR"
    elif score >= 40.0:
        return "POOR"
    else:
        return "CRITICAL"


def compute_scan_summary(findings: List[Finding]) -> Tuple[ScanSummary, Dict[str, Any]]:
    """
    Compute weighted security score and scan summary.
    
    Formula:
      Weight(Critical) = 10, Weight(High) = 5, Weight(Medium) = 3, Weight(Low) = 1
      Passed Points = sum(Weight[f.severity] for f in evaluated_findings if f.status == PASS)
      Total Possible Points = sum(Weight[f.severity] for f in evaluated_findings)
      Security Score = (Passed Points / Total Possible Points) * 100 if Total > 0 else 100.0
      
    Incomplete / Access Denied Treatment:
      Access denied findings are EXCLUDED from passed points.
      They are tracked under access_denied_checks and flag is_complete = False.
      Scan Completeness = (evaluated_checks / total_checks) * 100.
    """
    total = len(findings)
    passed = 0
    failed = 0
    access_denied = 0
    errors = 0

    severity_counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFORMATIONAL.value: 0,
    }

    service_stats: Dict[str, Dict[str, Any]] = {}

    evaluated_passed_weight = 0.0
    evaluated_total_weight = 0.0

    for f in findings:
        # Tally severity for failed findings
        if f.status == Status.FAIL:
            severity_counts[f.severity.value] += 1

        # Track per-service statistics
        if f.service not in service_stats:
            service_stats[f.service] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "access_denied": 0,
                "passed_weight": 0.0,
                "total_weight": 0.0,
                "score": 100.0,
            }
        service_stats[f.service]["total"] += 1

        if f.status == Status.PASS:
            passed += 1
            service_stats[f.service]["passed"] += 1
            weight = SEVERITY_WEIGHTS.get(f.severity, 1.0)
            service_stats[f.service]["passed_weight"] += weight
            service_stats[f.service]["total_weight"] += weight
            evaluated_passed_weight += weight
            evaluated_total_weight += weight
        elif f.status == Status.FAIL:
            failed += 1
            service_stats[f.service]["failed"] += 1
            weight = SEVERITY_WEIGHTS.get(f.severity, 1.0)
            service_stats[f.service]["total_weight"] += weight
            evaluated_total_weight += weight
        elif f.status == Status.ACCESS_DENIED:
            access_denied += 1
            service_stats[f.service]["access_denied"] += 1
        elif f.status == Status.ERROR:
            errors += 1

    # Security score computation
    if evaluated_total_weight > 0:
        raw_score = (evaluated_passed_weight / evaluated_total_weight) * 100.0
        score = round(raw_score, 1)
    else:
        # If no checks were evaluated (e.g. all access denied or zero checks)
        score = 0.0 if (access_denied + errors) > 0 else 100.0

    # Calculate per-service scores using identical severity-weighted ThreatScore math
    for svc, stats in service_stats.items():
        if stats["total_weight"] > 0:
            stats["score"] = round((stats["passed_weight"] / stats["total_weight"]) * 100.0, 1)
        else:
            stats["score"] = 0.0 if stats["access_denied"] > 0 else 100.0

    evaluated_count = passed + failed
    completeness = round((evaluated_count / total * 100.0), 1) if total > 0 else 100.0
    is_complete = (access_denied == 0 and errors == 0)

    score_band = calculate_score_band(score)

    summary = ScanSummary(
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        access_denied_checks=access_denied,
        error_checks=errors,
        security_score=score,
        score_band=score_band,
        is_complete=is_complete,
        completeness_percentage=completeness,
        severity_breakdown=severity_counts,
        service_breakdown=service_stats,
    )

    explanation = {
        "formula": "Score = (Weighted Passed Points / Total Evaluated Points) * 100",
        "weights": {sev.value: weight for sev, weight in SEVERITY_WEIGHTS.items() if weight > 0},
        "evaluated_passed_weight": evaluated_passed_weight,
        "evaluated_total_weight": evaluated_total_weight,
        "raw_percentage": score,
        "score_band": score_band,
        "incomplete_notice": (
            "All checks completed cleanly."
            if is_complete
            else f"WARNING: {access_denied} check(s) returned AccessDenied / insufficient IAM permissions. "
                 "These checks are excluded from pass calculations to prevent false confidence. "
                 f"Scan completeness is currently {completeness}%."
        ),
    }

    return summary, explanation
