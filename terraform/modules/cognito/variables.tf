variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "callback_urls" {
  description = "Allowed OAuth 2.0 callback URLs for the user pool client"
  type        = list(string)
  default     = ["http://localhost:8080/callback"]
}

variable "logout_urls" {
  description = "Allowed logout URLs for the user pool client"
  type        = list(string)
  default     = ["http://localhost:8080/logout"]
}

variable "test_user_username" {
  description = "Username for the demonstration test user"
  type        = string
  default     = "testuser"
}

variable "test_user_password" {
  description = "Password for the demonstration test user"
  type        = string
  default     = "TestUser@2025!"
  sensitive   = true
}

variable "test_user_email" {
  description = "Email for the demonstration test user"
  type        = string
  default     = "testuser@example.com"
}
