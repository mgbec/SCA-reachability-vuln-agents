# Outputs for the AgentCore module

output "orchestrator_agent_runtime_id" {
  description = "Orchestrator Agent Runtime ID"
  value       = aws_bedrockagentcore_agent_runtime.orchestrator.agent_runtime_id
}

output "scanner_agent_runtime_id" {
  description = "Scanner Agent Runtime ID"
  value       = aws_bedrockagentcore_agent_runtime.scanner.agent_runtime_id
}

output "analysis_agent_runtime_id" {
  description = "Analysis Agent Runtime ID"
  value       = aws_bedrockagentcore_agent_runtime.analysis.agent_runtime_id
}

output "orchestrator_agent_runtime_arn" {
  description = "Orchestrator Agent Runtime ARN"
  value       = aws_bedrockagentcore_agent_runtime.orchestrator.agent_runtime_arn
}

output "scanner_agent_runtime_arn" {
  description = "Scanner Agent Runtime ARN"
  value       = aws_bedrockagentcore_agent_runtime.scanner.agent_runtime_arn
}

output "analysis_agent_runtime_arn" {
  description = "Analysis Agent Runtime ARN"
  value       = aws_bedrockagentcore_agent_runtime.analysis.agent_runtime_arn
}

output "workload_identity_arns" {
  description = "Map of agent names to their workload identity ARNs"
  value = {
    orchestrator = aws_bedrockagentcore_workload_identity.orchestrator.workload_identity_arn
    scanner      = aws_bedrockagentcore_workload_identity.scanner.workload_identity_arn
    analysis     = aws_bedrockagentcore_workload_identity.analysis.workload_identity_arn
  }
}

output "scanner_credential_provider_arn" {
  description = "ARN of the Scanner Agent's GitHub OAuth credential provider"
  value       = aws_bedrockagentcore_oauth2_credential_provider.scanner_github.credential_provider_arn
}

output "analysis_credential_provider_arn" {
  description = "ARN of the Analysis Agent's M2M credential provider"
  value       = aws_bedrockagentcore_oauth2_credential_provider.analysis_m2m.credential_provider_arn
}

# --- Endpoint ARNs ---

output "orchestrator_endpoint_arn" {
  description = "ARN of the Orchestrator Agent Runtime Endpoint"
  value       = aws_bedrockagentcore_agent_runtime_endpoint.orchestrator.agent_runtime_endpoint_arn
}

output "scanner_endpoint_arn" {
  description = "ARN of the Scanner Agent Runtime Endpoint"
  value       = aws_bedrockagentcore_agent_runtime_endpoint.scanner.agent_runtime_endpoint_arn
}

output "analysis_endpoint_arn" {
  description = "ARN of the Analysis Agent Runtime Endpoint"
  value       = aws_bedrockagentcore_agent_runtime_endpoint.analysis.agent_runtime_endpoint_arn
}
