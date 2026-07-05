variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "region" {
  description = "AWS region for ARN construction"
  type        = string
}

variable "account_id" {
  description = "AWS account ID for ARN construction"
  type        = string
}

variable "state_bucket_arn" {
  description = "ARN of the S3 bucket used for Terraform state"
  type        = string
}

variable "secrets_arns" {
  description = "List of Secrets Manager secret ARNs that agents can read"
  type        = list(string)
  default     = []
}

variable "scanner_agent_arn" {
  description = "ARN of the Scanner Agent AgentCore runtime for invoke permissions"
  type        = string
  default     = ""
}

variable "analysis_agent_arn" {
  description = "ARN of the Analysis Agent AgentCore runtime for invoke permissions"
  type        = string
  default     = ""
}
