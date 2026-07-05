output "orchestrator_role_arn" {
  description = "ARN of the Orchestrator Agent IAM role"
  value       = aws_iam_role.orchestrator.arn
}

output "orchestrator_role_name" {
  description = "Name of the Orchestrator Agent IAM role"
  value       = aws_iam_role.orchestrator.name
}

output "scanner_role_arn" {
  description = "ARN of the Scanner Agent IAM role"
  value       = aws_iam_role.scanner.arn
}

output "scanner_role_name" {
  description = "Name of the Scanner Agent IAM role"
  value       = aws_iam_role.scanner.name
}

output "analysis_role_arn" {
  description = "ARN of the Analysis Agent IAM role"
  value       = aws_iam_role.analysis.arn
}

output "analysis_role_name" {
  description = "Name of the Analysis Agent IAM role"
  value       = aws_iam_role.analysis.name
}

output "deployment_role_arn" {
  description = "ARN of the Deployment role (Terraform state access)"
  value       = aws_iam_role.deployment.arn
}

output "deployment_role_name" {
  description = "Name of the Deployment role"
  value       = aws_iam_role.deployment.name
}
