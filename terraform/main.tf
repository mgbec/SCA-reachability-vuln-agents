terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.53.0"
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

module "ecr" {
  source = "./modules/ecr"

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

  # GitHub OAuth credentials (Scanner Agent)
  github_oauth_client_id     = var.github_oauth_client_id
  github_oauth_client_secret = var.github_oauth_client_secret

  # M2M credentials (Analysis Agent)
  m2m_client_id             = var.m2m_client_id
  m2m_client_secret         = var.m2m_client_secret
  m2m_token_endpoint_issuer = var.m2m_token_endpoint_issuer

  # Container URIs (ECR)
  orchestrator_container_uri = "${module.ecr.orchestrator_repository_url}:latest"
  scanner_container_uri      = "${module.ecr.scanner_repository_url}:latest"
  analysis_container_uri     = "${module.ecr.analysis_repository_url}:latest"

  # ECR repository ARNs (for IAM policy)
  ecr_repository_arns = [
    module.ecr.orchestrator_repository_arn,
    module.ecr.scanner_repository_arn,
    module.ecr.analysis_repository_arn,
  ]
}

module "observability" {
  source = "./modules/observability"

  region                 = var.region
  project_name           = var.project_name
  environment            = var.environment
  failure_rate_threshold = var.failure_rate_threshold
  log_retention_days     = var.log_retention_days
}
