# Outputs for the Certificates/mTLS module
# Exposes CA certificate PEM (for trust store distribution), agent cert ARNs
# (for Secrets Manager retrieval by runtimes), and private key ARNs
# (for IAM policy attachment).

output "ca_certificate_pem" {
  description = "PEM-encoded CA certificate for distribution to agent trust stores"
  value       = tls_self_signed_cert.ca.cert_pem
}

output "agent_certificate_pems" {
  description = "Map of agent name to PEM-encoded public certificate"
  value = {
    for name in local.agent_names : name => tls_locally_signed_cert.agent[name].cert_pem
  }
}

output "agent_cert_arns" {
  description = "Map of agent name to Secrets Manager ARN for the agent certificate"
  value = {
    for name in local.agent_names : name => aws_secretsmanager_secret.agent_certificate[name].arn
  }
}

output "agent_private_key_arns" {
  description = "Map of agent name to Secrets Manager ARN for the agent private key"
  value = {
    for name in local.agent_names : name => aws_secretsmanager_secret.agent_private_key[name].arn
  }
}

output "ca_certificate_arn" {
  description = "Secrets Manager ARN for the CA public certificate"
  value       = aws_secretsmanager_secret.ca_certificate.arn
}

output "ca_private_key_arn" {
  description = "Secrets Manager ARN for the CA private key (restrict access carefully)"
  value       = aws_secretsmanager_secret.ca_private_key.arn
}

output "all_certificate_secret_arns" {
  description = "List of all Secrets Manager ARNs for certificate resources (for IAM policies)"
  value = concat(
    [for name in local.agent_names : aws_secretsmanager_secret.agent_private_key[name].arn],
    [for name in local.agent_names : aws_secretsmanager_secret.agent_certificate[name].arn],
    [aws_secretsmanager_secret.ca_certificate.arn],
    [aws_secretsmanager_secret.ca_private_key.arn],
  )
}
