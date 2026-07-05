terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.53"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# --- Module Instantiations ---

module "cognito" {
  source = "./modules/cognito"

  project_name = var.project_name
  environment  = var.environment
}

module "certificates" {
  source = "./modules/certificates"

  project_name = var.project_name
  environment  = var.environment
}

module "secrets" {
  source = "./modules/secrets"

  project_name = var.project_name
  environment  = var.environment
}

module "agentcore" {
  source = "./modules/agentcore"

  project_name = var.project_name
  environment  = var.environment
  region       = var.region

  # Cognito integration for JWT validation
  cognito_user_pool_endpoint = module.cognito.user_pool_endpoint
  cognito_client_id          = module.cognito.client_id

  # Secret ARNs from the secrets module (referenced by ARN, never plaintext)
  github_oauth_client_id_secret_arn = module.secrets.github_oauth_client_id_arn
  github_oauth_client_secret_arn    = module.secrets.github_oauth_client_secret_arn
  m2m_client_id_secret_arn          = module.secrets.m2m_client_id_arn
  m2m_client_secret_arn             = module.secrets.m2m_client_secret_arn
}

module "observability" {
  source = "./modules/observability"

  region                 = var.region
  project_name           = var.project_name
  environment            = var.environment
  failure_rate_threshold = var.failure_rate_threshold
  log_retention_days     = var.log_retention_days
}
