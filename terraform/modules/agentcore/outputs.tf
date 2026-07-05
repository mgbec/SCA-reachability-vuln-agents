# Outputs for the AgentCore module

output "orchestrator_agent_endpoint" {
  description = "Orchestrator Agent invocation endpoint URL"
  value       = aws_bedrock_agentcore_runtime.orchestrator.invoke_endpoint
}

output "scanner_agent_endpoint" {
  description = "Scanner Agent invocation endpoint URL"
  value       = aws_bedrock_agentcore_runtime.scanner.invoke_endpoint
}

output "analysis_agent_endpoint" {
  description = "Analysis Agent invocation endpoint URL"
  value       = aws_bedrock_agentcore_runtime.analysis.invoke_endpoint
}

output "workload_identity_arns" {
  description = "Map of agent names to their workload identity ARNs"
  value = {
    orchestrator = aws_bedrock_agentcore_workload_identity.orchestrator.arn
    scanner      = aws_bedrock_agentcore_workload_identity.scanner.arn
    analysis     = aws_bedrock_agentcore_workload_identity.analysis.arn
  }
}

output "orchestrator_workload_identity_arn" {
  description = "ARN of the Orchestrator Agent workload identity"
  value       = aws_bedrock_agentcore_workload_identity.orchestrator.arn
}

output "scanner_workload_identity_arn" {
  description = "ARN of the Scanner Agent workload identity"
  value       = aws_bedrock_agentcore_workload_identity.scanner.arn
}

output "analysis_workload_identity_arn" {
  description = "ARN of the Analysis Agent workload identity"
  value       = aws_bedrock_agentcore_workload_identity.analysis.arn
}

output "scanner_credential_provider_id" {
  description = "ID of the Scanner Agent's GitHub OAuth credential provider"
  value       = aws_bedrock_agentcore_credential_provider.scanner_github_oauth.id
}

output "analysis_credential_provider_id" {
  description = "ID of the Analysis Agent's M2M credential provider"
  value       = aws_bedrock_agentcore_credential_provider.analysis_m2m.id
}
