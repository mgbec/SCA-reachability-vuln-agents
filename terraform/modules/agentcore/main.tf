# AgentCore module — Runtime instances, Identity Directory, Credential Providers, JWT Authorizers
#
# This module provisions:
# - Three AgentCore Runtime instances (Orchestrator, Scanner, Analysis)
# - Workload identity registrations in the Identity Directory for each agent
# - Credential Providers: USER_FEDERATION for Scanner (GitHub OAuth), M2M for Analysis
# - JWT Authorizer configuration on each runtime with Cognito discovery URL
#
# Note: AWS Bedrock AgentCore is a newer service. Resource type names
# (aws_bedrock_agentcore_*) are used to model the correct configuration intent.
# If no native Terraform provider resource exists yet, these serve as
# infrastructure-as-code documentation of the intended provisioning.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  agent_names = ["orchestrator-agent", "scanner-agent", "analysis-agent"]

  # ARN pattern for workload identities
  workload_identity_arn_prefix = "arn:aws:bedrock-agentcore:${local.region}:${local.account_id}:workload-identity/directory/default/workload-identity"

  # OIDC discovery URL derived from the Cognito User Pool endpoint
  oidc_discovery_url = "${var.cognito_user_pool_endpoint}/.well-known/openid-configuration"
}

# =============================================================================
# Identity Directory — Workload Identity Registrations
# =============================================================================
# Each agent is registered as a distinct workload identity with a unique ARN
# following: arn:aws:bedrock-agentcore:{region}:{account}:workload-identity/directory/default/workload-identity/{agent-name}

resource "aws_bedrock_agentcore_workload_identity" "orchestrator" {
  name         = "orchestrator-agent"
  directory_id = "default"

  allowed_oauth_return_urls = [
    "https://${var.project_name}-${var.environment}-orchestrator.agentcore.${var.region}.amazonaws.com/oauth/callback"
  ]

  metadata = {
    project     = var.project_name
    environment = var.environment
    role        = "orchestrator"
  }

  tags = merge(var.tags, {
    Component = "agentcore-identity"
    Agent     = "orchestrator-agent"
  })
}

resource "aws_bedrock_agentcore_workload_identity" "scanner" {
  name         = "scanner-agent"
  directory_id = "default"

  allowed_oauth_return_urls = [
    "https://${var.project_name}-${var.environment}-scanner.agentcore.${var.region}.amazonaws.com/oauth/callback"
  ]

  metadata = {
    project     = var.project_name
    environment = var.environment
    role        = "scanner"
  }

  tags = merge(var.tags, {
    Component = "agentcore-identity"
    Agent     = "scanner-agent"
  })
}

resource "aws_bedrock_agentcore_workload_identity" "analysis" {
  name         = "analysis-agent"
  directory_id = "default"

  allowed_oauth_return_urls = [
    "https://${var.project_name}-${var.environment}-analysis.agentcore.${var.region}.amazonaws.com/oauth/callback"
  ]

  metadata = {
    project     = var.project_name
    environment = var.environment
    role        = "analysis"
  }

  tags = merge(var.tags, {
    Component = "agentcore-identity"
    Agent     = "analysis-agent"
  })
}

# =============================================================================
# Credential Providers
# =============================================================================
# Scanner Agent: USER_FEDERATION (GitHub OAuth — Authorization Code Grant)
# Analysis Agent: M2M (Client Credentials Grant)

resource "aws_bedrock_agentcore_credential_provider" "scanner_github_oauth" {
  name                 = "${var.project_name}-${var.environment}-scanner-github-oauth"
  workload_identity_id = aws_bedrock_agentcore_workload_identity.scanner.id
  type                 = "USER_FEDERATION"

  oauth_config {
    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint         = "https://github.com/login/oauth/access_token"

    # Client credentials retrieved from Secrets Manager (never plaintext in state)
    client_id_secret_arn     = var.github_oauth_client_id_secret_arn
    client_secret_secret_arn = var.github_oauth_client_secret_arn

    # Allowed scopes for user-delegated GitHub access
    allowed_scopes = ["security_events", "repo"]

    # CSRF protection via state parameter is handled automatically by AgentCore Identity
    enable_state_parameter = true

    # Callback URL registered in Identity Directory
    redirect_uri = aws_bedrock_agentcore_workload_identity.scanner.allowed_oauth_return_urls[0]
  }

  tags = merge(var.tags, {
    Component = "agentcore-credential-provider"
    Agent     = "scanner-agent"
    AuthFlow  = "USER_FEDERATION"
  })
}

resource "aws_bedrock_agentcore_credential_provider" "analysis_m2m" {
  name                 = "${var.project_name}-${var.environment}-analysis-m2m"
  workload_identity_id = aws_bedrock_agentcore_workload_identity.analysis.id
  type                 = "M2M"

  client_credentials_config {
    token_endpoint = "https://auth.vulnerability-db.example.com/oauth2/token"

    # Client credentials retrieved from Secrets Manager (never plaintext in state)
    client_id_secret_arn     = var.m2m_client_id_secret_arn
    client_secret_secret_arn = var.m2m_client_secret_arn

    # Scopes for vulnerability database access
    allowed_scopes = ["read:vulnerabilities", "read:advisories"]

    # Proactive refresh: obtain new token when within 60 seconds of expiration
    proactive_refresh_buffer_seconds = 60
  }

  tags = merge(var.tags, {
    Component = "agentcore-credential-provider"
    Agent     = "analysis-agent"
    AuthFlow  = "M2M"
  })
}

# =============================================================================
# AgentCore Runtime Instances
# =============================================================================
# Each agent runs as a separate AgentCore Runtime instance with JWT Authorizer.

resource "aws_bedrock_agentcore_runtime" "orchestrator" {
  name = "${var.project_name}-${var.environment}-orchestrator-agent"

  workload_identity_id = aws_bedrock_agentcore_workload_identity.orchestrator.id

  # JWT Authorizer — validates inbound JWT bearer tokens from the Demo CLI / callers
  jwt_authorizer {
    issuer_url         = var.cognito_user_pool_endpoint
    discovery_url      = local.oidc_discovery_url
    allowed_audiences  = [var.cognito_client_id]
    allowed_client_ids = [var.cognito_client_id]
  }

  # Runtime configuration
  runtime_config {
    memory_size_mb  = 512
    timeout_seconds = 300
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "orchestrator-agent"
  })
}

resource "aws_bedrock_agentcore_runtime" "scanner" {
  name = "${var.project_name}-${var.environment}-scanner-agent"

  workload_identity_id = aws_bedrock_agentcore_workload_identity.scanner.id

  # JWT Authorizer — validates inbound tokens (from Orchestrator delegation)
  jwt_authorizer {
    issuer_url         = var.cognito_user_pool_endpoint
    discovery_url      = local.oidc_discovery_url
    allowed_audiences  = [var.cognito_client_id]
    allowed_client_ids = [var.cognito_client_id]
  }

  # Associate credential providers for outbound OAuth
  credential_provider_ids = [
    aws_bedrock_agentcore_credential_provider.scanner_github_oauth.id
  ]

  # Runtime configuration
  runtime_config {
    memory_size_mb  = 1024
    timeout_seconds = 600
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "scanner-agent"
  })
}

resource "aws_bedrock_agentcore_runtime" "analysis" {
  name = "${var.project_name}-${var.environment}-analysis-agent"

  workload_identity_id = aws_bedrock_agentcore_workload_identity.analysis.id

  # JWT Authorizer — validates inbound tokens (from Orchestrator delegation)
  jwt_authorizer {
    issuer_url         = var.cognito_user_pool_endpoint
    discovery_url      = local.oidc_discovery_url
    allowed_audiences  = [var.cognito_client_id]
    allowed_client_ids = [var.cognito_client_id]
  }

  # Associate credential providers for outbound M2M auth
  credential_provider_ids = [
    aws_bedrock_agentcore_credential_provider.analysis_m2m.id
  ]

  # Runtime configuration — larger memory for tree-sitter call graph analysis
  runtime_config {
    memory_size_mb  = 2048
    timeout_seconds = 900
  }

  tags = merge(var.tags, {
    Component = "agentcore-runtime"
    Agent     = "analysis-agent"
  })
}
