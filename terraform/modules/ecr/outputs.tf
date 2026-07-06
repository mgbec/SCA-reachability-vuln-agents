# Outputs for the ECR module

output "orchestrator_repository_url" {
  description = "ECR repository URL for the Orchestrator Agent"
  value       = aws_ecr_repository.sca_orchestrator.repository_url
}

output "scanner_repository_url" {
  description = "ECR repository URL for the Scanner Agent"
  value       = aws_ecr_repository.sca_scanner.repository_url
}

output "analysis_repository_url" {
  description = "ECR repository URL for the Analysis Agent"
  value       = aws_ecr_repository.sca_analysis.repository_url
}

output "orchestrator_repository_arn" {
  description = "ECR repository ARN for the Orchestrator Agent"
  value       = aws_ecr_repository.sca_orchestrator.arn
}

output "scanner_repository_arn" {
  description = "ECR repository ARN for the Scanner Agent"
  value       = aws_ecr_repository.sca_scanner.arn
}

output "analysis_repository_arn" {
  description = "ECR repository ARN for the Analysis Agent"
  value       = aws_ecr_repository.sca_analysis.arn
}
