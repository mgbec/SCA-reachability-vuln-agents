output "user_pool_id" {
  description = "The ID of the Cognito user pool"
  value       = aws_cognito_user_pool.main.id
}

output "user_pool_endpoint" {
  description = "The OIDC issuer URL for the Cognito user pool (used for JWT validation and OIDC discovery at /.well-known/openid-configuration)"
  value       = "https://${aws_cognito_user_pool.main.endpoint}"
}

output "client_id" {
  description = "The client ID of the Cognito user pool client"
  value       = aws_cognito_user_pool_client.main.id
}

output "user_pool_arn" {
  description = "The ARN of the Cognito user pool"
  value       = aws_cognito_user_pool.main.arn
}

output "user_pool_domain" {
  description = "The Cognito user pool domain for hosted UI and OAuth endpoints"
  value       = aws_cognito_user_pool_domain.main.domain
}

output "client_secret" {
  description = "The client secret for the Cognito user pool client (sensitive)"
  value       = aws_cognito_user_pool_client.main.client_secret
  sensitive   = true
}

output "oidc_discovery_url" {
  description = "The OpenID Connect discovery endpoint URL"
  value       = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${aws_cognito_user_pool.main.id}/.well-known/openid-configuration"
}
