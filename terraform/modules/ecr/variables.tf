# Variables for the ECR module

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "tags" {
  description = "Additional tags to apply to all ECR resources"
  type        = map(string)
  default     = {}
}
