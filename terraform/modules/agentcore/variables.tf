# Variables for the AgentCore module

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "region" {
  description = "AWS region for resource deployment"
  type        = string
}

variable "cognito_user_pool_endpoint" {
  description = "Cognito User Pool OIDC issuer URL for JWT validation and discovery"
  type        = string
}

variable "cognito_client_id" {
  description = "Cognito User Pool client ID used as allowed audience for JWT validation"
  type        = string
  sensitive   = true
}

variable "github_oauth_client_id_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the GitHub OAuth client ID"
  type        = string
}

variable "github_oauth_client_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the GitHub OAuth client secret"
  type        = string
}

variable "m2m_client_id_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the M2M client ID"
  type        = string
}

variable "m2m_client_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the M2M client secret"
  type        = string
}

variable "tags" {
  description = "Additional tags to apply to all AgentCore resources"
  type        = map(string)
  default     = {}
}
