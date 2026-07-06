# Certificates/mTLS module for AgentCore Reachability-Enhanced SCA Platform
# Provisions an internal Certificate Authority, issues unique X.509 certificates
# per agent runtime, stores private keys in Secrets Manager, and distributes
# public certificates to agent runtimes for mutual TLS enforcement.

terraform {
  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.53.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Local values — agent identity names used as certificate Common Names (CN)
# -----------------------------------------------------------------------------

locals {
  agent_names = ["orchestrator-agent", "scanner-agent", "analysis-agent"]
}

# -----------------------------------------------------------------------------
# Internal Certificate Authority (CA)
# Self-signed root CA used to issue and validate agent client certificates.
# -----------------------------------------------------------------------------

resource "tls_private_key" "ca" {
  algorithm   = var.ca_algorithm
  ecdsa_curve = var.ca_algorithm == "ECDSA" ? var.ca_ecdsa_curve : null
  rsa_bits    = var.ca_algorithm == "RSA" ? var.ca_rsa_bits : null
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name         = "${var.project_name}-internal-ca"
    organization        = var.project_name
    organizational_unit = "Security"
  }

  validity_period_hours = var.ca_validity_days * 24
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
  ]
}

# -----------------------------------------------------------------------------
# Per-Agent Private Keys
# One unique private key per agent runtime.
# -----------------------------------------------------------------------------

resource "tls_private_key" "agent" {
  for_each = toset(local.agent_names)

  algorithm   = var.ca_algorithm
  ecdsa_curve = var.ca_algorithm == "ECDSA" ? var.ca_ecdsa_curve : null
  rsa_bits    = var.ca_algorithm == "RSA" ? var.ca_rsa_bits : null
}

# -----------------------------------------------------------------------------
# Per-Agent X.509 Certificates (signed by internal CA)
# CN matches the agent identity name for mTLS validation.
# -----------------------------------------------------------------------------

resource "tls_locally_signed_cert" "agent" {
  for_each = toset(local.agent_names)

  cert_request_pem   = tls_cert_request.agent[each.key].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = var.cert_validity_days * 24

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
    "server_auth",
  ]
}

# -----------------------------------------------------------------------------
# Certificate Signing Requests (CSR) per agent
# -----------------------------------------------------------------------------

resource "tls_cert_request" "agent" {
  for_each = toset(local.agent_names)

  private_key_pem = tls_private_key.agent[each.key].private_key_pem

  subject {
    common_name         = each.key
    organization        = var.project_name
    organizational_unit = "AgentRuntime"
  }
}

# -----------------------------------------------------------------------------
# Store private keys in AWS Secrets Manager (encrypted at rest)
# Private keys NEVER appear in Terraform outputs or state plaintext references.
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "agent_private_key" {
  for_each = toset(local.agent_names)

  name        = "${var.project_name}/${var.environment}/mtls/${each.key}-private-key"
  description = "mTLS private key for ${each.key}"
  kms_key_id  = var.kms_key_arn

  tags = merge(var.tags, {
    SecretType = "mtls-private-key"
    Agent      = each.key
  })
}

resource "aws_secretsmanager_secret_version" "agent_private_key" {
  for_each = toset(local.agent_names)

  secret_id     = aws_secretsmanager_secret.agent_private_key[each.key].id
  secret_string = tls_private_key.agent[each.key].private_key_pem
}

# Store the CA private key in Secrets Manager as well (for future cert issuance)
resource "aws_secretsmanager_secret" "ca_private_key" {
  name        = "${var.project_name}/${var.environment}/mtls/ca-private-key"
  description = "Internal CA private key for certificate issuance"
  kms_key_id  = var.kms_key_arn

  tags = merge(var.tags, {
    SecretType = "mtls-ca-private-key"
    Agent      = "certificate-authority"
  })
}

resource "aws_secretsmanager_secret_version" "ca_private_key" {
  secret_id     = aws_secretsmanager_secret.ca_private_key.id
  secret_string = tls_private_key.ca.private_key_pem
}

# -----------------------------------------------------------------------------
# Store agent certificates in Secrets Manager for distribution to runtimes
# Public certs are less sensitive but stored centrally for consistent retrieval.
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "agent_certificate" {
  for_each = toset(local.agent_names)

  name        = "${var.project_name}/${var.environment}/mtls/${each.key}-certificate"
  description = "mTLS public certificate for ${each.key}"
  kms_key_id  = var.kms_key_arn

  tags = merge(var.tags, {
    SecretType = "mtls-certificate"
    Agent      = each.key
  })
}

resource "aws_secretsmanager_secret_version" "agent_certificate" {
  for_each = toset(local.agent_names)

  secret_id     = aws_secretsmanager_secret.agent_certificate[each.key].id
  secret_string = tls_locally_signed_cert.agent[each.key].cert_pem
}

# Store the CA certificate for distribution (agents use this to validate peers)
resource "aws_secretsmanager_secret" "ca_certificate" {
  name        = "${var.project_name}/${var.environment}/mtls/ca-certificate"
  description = "Internal CA public certificate for mTLS validation"
  kms_key_id  = var.kms_key_arn

  tags = merge(var.tags, {
    SecretType = "mtls-ca-certificate"
    Agent      = "all-agents"
  })
}

resource "aws_secretsmanager_secret_version" "ca_certificate" {
  secret_id     = aws_secretsmanager_secret.ca_certificate.id
  secret_string = tls_self_signed_cert.ca.cert_pem
}
