output "cognito_user_pool_endpoint" {
  description = "Cognito user pool endpoint URL for authentication"
  value       = module.cognito.user_pool_endpoint
}

output "cognito_client_id" {
  description = "Cognito user pool client ID for OAuth flows"
  value       = module.cognito.client_id
}

output "orchestrator_agent_runtime_arn" {
  description = "Orchestrator Agent Runtime ARN"
  value       = module.agentcore.orchestrator_agent_runtime_arn
}

output "scanner_agent_runtime_arn" {
  description = "Scanner Agent Runtime ARN"
  value       = module.agentcore.scanner_agent_runtime_arn
}

output "analysis_agent_runtime_arn" {
  description = "Analysis Agent Runtime ARN"
  value       = module.agentcore.analysis_agent_runtime_arn
}

output "workload_identity_arns" {
  description = "Map of agent names to their workload identity ARNs"
  value       = module.agentcore.workload_identity_arns
}
