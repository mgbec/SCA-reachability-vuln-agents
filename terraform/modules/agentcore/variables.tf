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

# --- GitHub OAuth credentials (Scanner Agent) ---

variable "github_oauth_client_id" {
  description = "GitHub OAuth client ID for Scanner Agent"
  type        = string
  sensitive   = true
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth client secret for Scanner Agent"
  type        = string
  sensitive   = true
}

# --- M2M credentials (Analysis Agent) ---

variable "m2m_client_id" {
  description = "M2M OAuth client ID for Analysis Agent"
  type        = string
  sensitive   = true
}

variable "m2m_client_secret" {
  description = "M2M OAuth client secret for Analysis Agent"
  type        = string
  sensitive   = true
}

variable "m2m_token_endpoint_issuer" {
  description = "Issuer URL for the M2M token endpoint (e.g., https://auth.vulnerability-db.example.com)"
  type        = string
  default     = "https://auth.vulnerability-db.example.com"
}

# --- Container URIs ---

variable "orchestrator_container_uri" {
  description = "ECR container URI for the Orchestrator Agent"
  type        = string
  default     = ""
}

variable "scanner_container_uri" {
  description = "ECR container URI for the Scanner Agent"
  type        = string
  default     = ""
}

variable "analysis_container_uri" {
  description = "ECR container URI for the Analysis Agent"
  type        = string
  default     = ""
}

# --- Tags ---

variable "tags" {
  description = "Additional tags to apply to all AgentCore resources"
  type        = map(string)
  default     = {}
}
