# Data source for current AWS account ID
data "aws_caller_identity" "current" {}

# --- CloudWatch Log Groups ---

# Application logs exported via OpenTelemetry Collector
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/agentcore/reachability-sca/logs"
  retention_in_days = var.log_retention_days

  tags = {
    Component = "observability"
    Purpose   = "application-logs"
  }
}

# Metrics logs for CloudWatch EMF (Embedded Metric Format) via OpenTelemetry Collector
resource "aws_cloudwatch_log_group" "metrics_logs" {
  name              = "/agentcore/reachability-sca/metrics"
  retention_in_days = var.log_retention_days

  tags = {
    Component = "observability"
    Purpose   = "metrics-emf"
  }
}

# --- CloudWatch Dashboard ---

resource "aws_cloudwatch_dashboard" "auth_dashboard" {
  dashboard_name = "${var.project_name}-${var.environment}-auth-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Auth Success/Failure Rates per Agent
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Auth Success Rate per Agent"
          region = var.region
          period = 60
          stat   = "Sum"
          metrics = [
            ["AgentCoreReachabilitySCA", "AuthSuccess", "AgentName", "orchestrator-agent"],
            ["AgentCoreReachabilitySCA", "AuthSuccess", "AgentName", "scanner-agent"],
            ["AgentCoreReachabilitySCA", "AuthSuccess", "AgentName", "analysis-agent"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Auth Failure Rate per Agent"
          region = var.region
          period = 60
          stat   = "Sum"
          metrics = [
            ["AgentCoreReachabilitySCA", "AuthFailure", "AgentName", "orchestrator-agent"],
            ["AgentCoreReachabilitySCA", "AuthFailure", "AgentName", "scanner-agent"],
            ["AgentCoreReachabilitySCA", "AuthFailure", "AgentName", "analysis-agent"],
          ]
        }
      },
      # Latency Percentiles (p50, p90, p99)
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "JWT Validation Latency (p50, p90, p99)"
          region = var.region
          period = 60
          metrics = [
            ["AgentCoreReachabilitySCA", "JwtValidationDuration", "AgentName", "orchestrator-agent", { stat = "p50" }],
            ["AgentCoreReachabilitySCA", "JwtValidationDuration", "AgentName", "orchestrator-agent", { stat = "p90" }],
            ["AgentCoreReachabilitySCA", "JwtValidationDuration", "AgentName", "orchestrator-agent", { stat = "p99" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Token Retrieval Latency (p50, p90, p99)"
          region = var.region
          period = 60
          metrics = [
            ["AgentCoreReachabilitySCA", "TokenRetrievalDuration", "AgentName", "scanner-agent", { stat = "p50" }],
            ["AgentCoreReachabilitySCA", "TokenRetrievalDuration", "AgentName", "scanner-agent", { stat = "p90" }],
            ["AgentCoreReachabilitySCA", "TokenRetrievalDuration", "AgentName", "scanner-agent", { stat = "p99" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "Token Refresh Latency (p50, p90, p99)"
          region = var.region
          period = 60
          metrics = [
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "orchestrator-agent", { stat = "p50" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "orchestrator-agent", { stat = "p90" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "orchestrator-agent", { stat = "p99" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "scanner-agent", { stat = "p50" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "scanner-agent", { stat = "p90" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "scanner-agent", { stat = "p99" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "analysis-agent", { stat = "p50" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "analysis-agent", { stat = "p90" }],
            ["AgentCoreReachabilitySCA", "TokenRefreshDuration", "AgentName", "analysis-agent", { stat = "p99" }],
          ]
        }
      },
      # Token Expiration Timeline per Agent
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        properties = {
          title  = "Token Expiration Timeline per Agent"
          region = var.region
          period = 60
          stat   = "Sum"
          metrics = [
            ["AgentCoreReachabilitySCA", "TokenRefresh", "AgentName", "orchestrator-agent"],
            ["AgentCoreReachabilitySCA", "TokenRefresh", "AgentName", "scanner-agent"],
            ["AgentCoreReachabilitySCA", "TokenRefresh", "AgentName", "analysis-agent"],
          ]
          annotations = {
            horizontal = [
              {
                label = "Token Refresh Events (indicates approaching expiration)"
                value = 0
              }
            ]
          }
        }
      }
    ]
  })
}

# --- CloudWatch Alarm: Auth Failure Rate ---

# Math expression alarm using metric math to calculate failure rate percentage
resource "aws_cloudwatch_metric_alarm" "auth_failure_rate" {
  alarm_name          = "${var.project_name}-${var.environment}-auth-failure-rate"
  alarm_description   = "Triggers when authentication failure rate exceeds ${var.failure_rate_threshold}% over a 5-minute sliding window"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = var.failure_rate_threshold

  metric_query {
    id          = "failure_rate"
    expression  = "(failures / (successes + failures)) * 100"
    label       = "Auth Failure Rate (%)"
    return_data = true
  }

  metric_query {
    id = "failures"

    metric {
      metric_name = "AuthFailure"
      namespace   = "AgentCoreReachabilitySCA"
      period      = 300
      stat        = "Sum"
    }
  }

  metric_query {
    id = "successes"

    metric {
      metric_name = "AuthSuccess"
      namespace   = "AgentCoreReachabilitySCA"
      period      = 300
      stat        = "Sum"
    }
  }

  tags = {
    Component = "observability"
    Purpose   = "auth-failure-alarm"
  }
}
