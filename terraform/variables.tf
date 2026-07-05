variable "region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "agentcore-reachability-sca"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "failure_rate_threshold" {
  description = "Authentication failure rate percentage threshold for triggering the CloudWatch alarm (1-100)"
  type        = number
  default     = 10

  validation {
    condition     = var.failure_rate_threshold >= 1 && var.failure_rate_threshold <= 100
    error_message = "Failure rate threshold must be between 1 and 100 (percent)."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch log entries"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention value."
  }
}
