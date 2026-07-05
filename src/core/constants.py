"""Core constants for the reachability-enhanced SCA platform.

Defines reachability multipliers, priority tier thresholds, retry configuration,
and metric names used across the system.
"""

from __future__ import annotations

from dataclasses import dataclass


# --- Reachability Multipliers ---
# Applied to CVSS base score to compute exploitability score.
# Formula: exploitability_score = cvss_base_score * reachability_multiplier

REACHABILITY_MULTIPLIERS: dict[str, float] = {
    "reachable": 1.0,
    "unreachable": 0.2,
    "indeterminate": 0.6,
}

REACHABILITY_MULTIPLIER_REACHABLE: float = 1.0
REACHABILITY_MULTIPLIER_UNREACHABLE: float = 0.2
REACHABILITY_MULTIPLIER_INDETERMINATE: float = 0.6


# --- Priority Tier Thresholds ---
# Exploitability score boundaries for tier classification.
# Critical: score >= 9.0
# High: 7.0 <= score < 9.0
# Medium: 4.0 <= score < 7.0
# Low: score < 4.0

PRIORITY_TIER_CRITICAL_THRESHOLD: float = 9.0
PRIORITY_TIER_HIGH_THRESHOLD: float = 7.0
PRIORITY_TIER_MEDIUM_THRESHOLD: float = 4.0

PRIORITY_TIER_THRESHOLDS: dict[str, tuple[float, float | None]] = {
    "critical": (9.0, None),      # >= 9.0
    "high": (7.0, 9.0),           # 7.0 <= score < 9.0
    "medium": (4.0, 7.0),         # 4.0 <= score < 7.0
    "low": (0.0, 4.0),            # score < 4.0
}


# --- Retry Configuration ---
# Used for token acquisition retries, logging retries, and Secrets Manager access.

@dataclass(frozen=True)
class RetryConfig:
    """Configuration for retry with exponential backoff.

    Attributes:
        max_attempts: Maximum number of retry attempts.
        base_delay_ms: Initial delay in milliseconds before the first retry.
        multiplier: Multiplier applied to the delay after each attempt.
        max_delay_ms: Maximum delay cap in milliseconds.
    """

    max_attempts: int = 3
    base_delay_ms: int = 100
    multiplier: int = 2
    max_delay_ms: int = 5000


DEFAULT_RETRY_CONFIG = RetryConfig()


# --- Metric Names ---
# OpenTelemetry metric names emitted by the agents.

class MetricNames:
    """Metric name constants for OpenTelemetry instrumentation."""

    # Authentication counters
    AUTH_SUCCESS: str = "AuthSuccess"
    AUTH_FAILURE: str = "AuthFailure"
    TOKEN_REFRESH: str = "TokenRefresh"
    AUTHZ_DENIAL: str = "AuthzDenial"

    # Latency histograms (milliseconds)
    JWT_VALIDATION_DURATION: str = "JwtValidationDuration"
    TOKEN_RETRIEVAL_DURATION: str = "TokenRetrievalDuration"
    TOKEN_REFRESH_DURATION: str = "TokenRefreshDuration"
    MTLS_VALIDATION_DURATION: str = "MTLSValidationDuration"

    # SCA-specific metrics
    CALL_GRAPH_BUILD_DURATION: str = "CallGraphBuildDuration"
    VULNERABILITIES_ANALYZED: str = "VulnerabilitiesAnalyzed"
    REACHABLE_VULNERABILITIES: str = "ReachableVulnerabilities"
    SBOM_GENERATION_DURATION: str = "SBOMGenerationDuration"


# --- Identity Context ---
IDENTITY_CONTEXT_VERSION: str = "1.0"

# --- Supported Languages for Call Graph Analysis ---
SUPPORTED_LANGUAGES: list[str] = [
    "javascript",
    "typescript",
    "python",
    "java",
    "go",
    "rust",
]

# --- Supported Dependency Manifest Files ---
SUPPORTED_MANIFESTS: list[str] = [
    "package.json",
    "requirements.txt",
    "pom.xml",
    "go.mod",
    "Cargo.toml",
]

# --- SBOM Format ---
SBOM_FORMAT: str = "CycloneDX"
SBOM_FORMAT_VERSION: str = "1.5"

# --- CloudWatch Configuration ---
CLOUDWATCH_LOG_RETENTION_DAYS: int = 90
METRICS_NAMESPACE: str = "AgentCoreReachabilitySCA"
METRICS_AGGREGATION_INTERVAL_SECONDS: int = 60

# --- Auth Failure Rate Alarm ---
DEFAULT_FAILURE_RATE_THRESHOLD_PERCENT: float = 10.0
MIN_FAILURE_RATE_THRESHOLD_PERCENT: float = 1.0
MAX_FAILURE_RATE_THRESHOLD_PERCENT: float = 100.0

# --- Token Refresh Buffer ---
TOKEN_REFRESH_BUFFER_SECONDS: int = 60
