output "cognito_user_pool_endpoint" {
  description = "Cognito user pool endpoint URL for authentication"
  value       = module.cognito.user_pool_endpoint
}

output "cognito_client_id" {
  description = "Cognito user pool client ID for OAuth flows"
  value       = module.cognito.client_id
  sensitive   = true
}

output "orchestrator_agent_endpoint" {
  description = "Orchestrator Agent invocation endpoint URL"
  value       = module.agentcore.orchestrator_agent_endpoint
}

output "scanner_agent_endpoint" {
  description = "Scanner Agent invocation endpoint URL"
  value       = module.agentcore.scanner_agent_endpoint
}

output "analysis_agent_endpoint" {
  description = "Analysis Agent invocation endpoint URL"
  value       = module.agentcore.analysis_agent_endpoint
}
