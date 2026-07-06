# AgentCore module — Runtime instances, Workload Identities, Credential Providers
#
# Uses the official Terraform AWS provider (>= 6.53.0) resource types:
#   - aws_bedrockagentcore_agent_runtime
#   - aws_bedrockagentcore_workload_identity
#   - aws_bedrockagentcore_oauth2_credential_provider

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region

  # OIDC discovery URL derived from the Cognito User Pool endpoint
  oidc_discovery_url = "${var.cognito_user_pool_endpoint}/.well-known/openid-configuration"
}

# =============================================================================
# IAM Role for AgentCore Runtime
# =============================================================================

data "aws_iam_policy_document" "agentcore_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "agentcore_runtime" {
  name               = "${var.project_name}-${var.environment}-agentcore-runtime-role"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume_role.json

  tags = merge(var.tags, {
    Component = "agentcore-iam"
  })
}

# =============================================================================
# Workload Identities
# =============================================================================

resource "aws_bedrockagentcore_workload_identity" "orchestrator" {
  name = "${var.project_name}-${var.environment}-orchestrator-agent"

  allowed_resource_oauth2_return_urls = [
    "https://${var.project_name}-${var.environment}-orchestrator.agentcore.${local.region}.amazonaws.com/oauth/callback"
  ]
}

resource "aws_bedrockagentcore_workload_identity" "scanner" {
  name = "${var.project_name}-${var.environment}-scanner-agent"

  allowed_resource_oauth2_return_urls = [
    "https://${var.project_name}-${var.environment}-scanner.agentcore.${local.region}.amazonaws.com/oauth/callback"
  ]
}

resource "aws_bedrockagentcore_workload_identity" "analysis" {
  name = "${var.project_name}-${var.environment}-analysis-agent"

  allowed_resource_oauth2_return_urls = [
    "https://${var.project_name}-${var.environment}-analysis.agentcore.${local.region}.amazonaws.com/oauth/callback"
  ]
}

# =============================================================================
# OAuth2 Credential Providers
# =============================================================================

# Scanner Agent: GitHub OAuth (User-delegated access)
resource "aws_bedrockagentcore_oauth2_credential_provider" "scanner_github" {
  name = "${var.project_name}-${var.environment}-scanner-github-oauth"

  credential_provider_vendor = "GithubOauth2"

  oauth2_provider_config {
    github_oauth2_provider_config {
      client_id     = var.github_oauth_client_id
      client_secret = var.github_oauth_client_secret
    }
  }

  tags = merge(var.tags, {
    Component = "agentcore-credential-provider"
    Agent     = "scanner-agent"
    AuthFlow  = "USER_FEDERATION"
  })
}

# Analysis Agent: Custom OAuth2 (M2M client credentials for vuln DBs)
resource "aws_bedrockagentcore_oauth2_credential_provider" "analysis_m2m" {
  name = "${var.project_name}-${var.environment}-analysis-m2m"

  credential_provider_vendor = "CustomOauth2"

  oauth2_provider_config {
    custom_oauth2_provider_config {
      client_id     = var.m2m_client_id
      client_secret = var.m2m_client_secret

      oauth_discovery {
        authorization_server_metadata {
          issuer                 = var.m2m_token_endpoint_issuer
          authorization_endpoint = "${var.m2m_token_endpoint_issuer}/authorize"
          token_endpoint         = "${var.m2m_token_endpoint_issuer}/oauth2/token"
          response_types         = ["code"]
        }
      }
    }
  }

  tags = merge(var.tags, {
    Component = "agentcore-credential-provider"
    Agent     = "analysis-agent"
    AuthFlow  = "M2M"
  })
}

# =============================================================================
# AgentCore Agent Runtime Instances
# =============================================================================

resource "aws_bedrockagentcore_agent_runtime" "orchestrator" {
  agent_runtime_name = "${var.project_name}-${var.environment}-orchestrator-agent"
  description        = "Orchestrator Agent — coordinates vulnerability analysis pipeline"
  role_arn           = aws_iam_role.agentcore_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = var.orchestrator_container_uri
    }
  }

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = local.oidc_discovery_url
      allowed_audience = [var.cognito_client_id]
      allowed_clients  = [var.cognito_client_id]
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = {
    AGENT_NAME         = "orchestrator-agent"
    SCANNER_ENDPOINT   = "https://${var.project_name}-${var.environment}-scanner.agentcore.${local.region}.amazonaws.com"
    ANALYSIS_ENDPOINT  = "https://${var.project_name}-${var.environment}-analysis.agentcore.${local.region}.amazonaws.com"
    COGNITO_ISSUER     = var.cognito_user_pool_endpoint
    COGNITO_AUDIENCE   = var.cognito_client_id
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "orchestrator-agent"
  })
}

resource "aws_bedrockagentcore_agent_runtime" "scanner" {
  agent_runtime_name = "${var.project_name}-${var.environment}-scanner-agent"
  description        = "Scanner Agent — GitHub OAuth access for Dependabot alerts and source code"
  role_arn           = aws_iam_role.agentcore_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = var.scanner_container_uri
    }
  }

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = local.oidc_discovery_url
      allowed_audience = [var.cognito_client_id]
      allowed_clients  = [var.cognito_client_id]
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = {
    AGENT_NAME = "scanner-agent"
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "scanner-agent"
  })
}

resource "aws_bedrockagentcore_agent_runtime" "analysis" {
  agent_runtime_name = "${var.project_name}-${var.environment}-analysis-agent"
  description        = "Analysis Agent — tree-sitter call graph, exploitability scoring, fix recommendations"
  role_arn           = aws_iam_role.agentcore_runtime.arn

  agent_runtime_artifact {
    container_configuration {
      container_uri = var.analysis_container_uri
    }
  }

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = local.oidc_discovery_url
      allowed_audience = [var.cognito_client_id]
      allowed_clients  = [var.cognito_client_id]
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  environment_variables = {
    AGENT_NAME = "analysis-agent"
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "analysis-agent"
  })
}
