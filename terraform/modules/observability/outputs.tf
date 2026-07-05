output "app_log_group_name" {
  description = "Name of the CloudWatch log group for application logs"
  value       = aws_cloudwatch_log_group.app_logs.name
}

output "app_log_group_arn" {
  description = "ARN of the CloudWatch log group for application logs"
  value       = aws_cloudwatch_log_group.app_logs.arn
}

output "metrics_log_group_name" {
  description = "Name of the CloudWatch log group for EMF metrics"
  value       = aws_cloudwatch_log_group.metrics_logs.name
}

output "metrics_log_group_arn" {
  description = "ARN of the CloudWatch log group for EMF metrics"
  value       = aws_cloudwatch_log_group.metrics_logs.arn
}

output "dashboard_arn" {
  description = "ARN of the CloudWatch authentication dashboard"
  value       = aws_cloudwatch_dashboard.auth_dashboard.dashboard_arn
}

output "dashboard_name" {
  description = "Name of the CloudWatch authentication dashboard"
  value       = aws_cloudwatch_dashboard.auth_dashboard.dashboard_name
}

output "auth_failure_alarm_arn" {
  description = "ARN of the authentication failure rate alarm"
  value       = aws_cloudwatch_metric_alarm.auth_failure_rate.arn
}

output "auth_failure_alarm_name" {
  description = "Name of the authentication failure rate alarm"
  value       = aws_cloudwatch_metric_alarm.auth_failure_rate.alarm_name
}
