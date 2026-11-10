"""
Unit Tests for CloudSentinel Lambda Handler and API Gateway Adapter.
Tests routing, CORS handling, health checks, score explanations, demo mode, and error recovery.
"""
import json
import pytest
from backend.lambda_handler import lambda_handler, build_response, CORS_HEADERS


def test_cors_preflight_options():
    event = {
        "httpMethod": "OPTIONS",
        "path": "/api/scan",
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
    body = json.loads(resp["body"])
    assert body["message"] == "CORS OK"


def test_health_check_route():
    event = {
        "httpMethod": "GET",
        "path": "/health",
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "healthy"
    assert "supported_categories" in body
    assert len(body["supported_categories"]) == 4


def test_score_explanation_route():
    event = {
        "httpMethod": "GET",
        "path": "/api/score-explanation",
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert "formula" in body
    assert "weights" in body
    assert body["weights"]["CRITICAL"] == 10.0


def test_demo_mode_scan():
    event = {
        "httpMethod": "GET",
        "path": "/api/scan",
        "queryStringParameters": {"mode": "demo"},
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["mode"] == "DEMO_ENVIRONMENT"
    assert "summary" in body
    assert "findings" in body
    assert body["summary"]["total_checks"] > 0


def test_not_found_route():
    event = {
        "httpMethod": "GET",
        "path": "/api/unknown-endpoint",
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 404
    body = json.loads(resp["body"])
    assert body["error"] == "Not Found"


def test_http_api_v2_payload_format():
    """Verify API Gateway HTTP API v2 payload format with requestContext.http."""
    event = {
        "requestContext": {
            "http": {
                "method": "GET",
                "path": "/health",
            }
        }
    }
    resp = lambda_handler(event, None)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["status"] == "healthy"
