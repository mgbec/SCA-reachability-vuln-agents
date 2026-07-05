# Variables for the Certificates/mTLS module

variable "project_name" {
  description = "Project name used for resource naming prefix"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "cert_validity_days" {
  description = "Number of days agent certificates remain valid"
  type        = number
  default     = 365

  validation {
    condition     = var.cert_validity_days >= 1 && var.cert_validity_days <= 3650
    error_message = "Certificate validity must be between 1 and 3650 days."
  }
}

variable "ca_validity_days" {
  description = "Number of days the CA certificate remains valid (should exceed agent cert validity)"
  type        = number
  default     = 3650

  validation {
    condition     = var.ca_validity_days >= 1 && var.ca_validity_days <= 7300
    error_message = "CA validity must be between 1 and 7300 days."
  }
}

variable "ca_algorithm" {
  description = "Cryptographic algorithm for CA and agent keys (RSA or ECDSA)"
  type        = string
  default     = "ECDSA"

  validation {
    condition     = contains(["RSA", "ECDSA"], var.ca_algorithm)
    error_message = "CA algorithm must be RSA or ECDSA."
  }
}

variable "ca_ecdsa_curve" {
  description = "ECDSA curve to use when ca_algorithm is ECDSA"
  type        = string
  default     = "P384"

  validation {
    condition     = contains(["P224", "P256", "P384", "P521"], var.ca_ecdsa_curve)
    error_message = "ECDSA curve must be one of: P224, P256, P384, P521."
  }
}

variable "ca_rsa_bits" {
  description = "RSA key size in bits when ca_algorithm is RSA"
  type        = number
  default     = 4096

  validation {
    condition     = contains([2048, 4096], var.ca_rsa_bits)
    error_message = "RSA key size must be 2048 or 4096."
  }
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt secrets at rest"
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to all certificate-related resources"
  type        = map(string)
  default     = {}
}
