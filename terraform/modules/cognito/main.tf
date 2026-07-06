# Data source for current AWS region
data "aws_region" "current" {}

# Cognito User Pool - Identity Provider for end-user authentication
resource "aws_cognito_user_pool" "main" {
  name = "${var.project_name}-${var.environment}-user-pool"

  # Password policy for demonstration purposes
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  # Auto-verify email to simplify test user creation
  auto_verified_attributes = ["email"]

  # Schema attributes
  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Account recovery via email
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = {
    Component = "cognito"
  }
}

# Cognito User Pool Domain - Required for hosted UI and OIDC discovery endpoint
resource "aws_cognito_user_pool_domain" "main" {
  domain       = "${var.project_name}-${var.environment}"
  user_pool_id = aws_cognito_user_pool.main.id
}

# Cognito User Pool Client - Authorization Code Grant flow
resource "aws_cognito_user_pool_client" "main" {
  name         = "${var.project_name}-${var.environment}-client"
  user_pool_id = aws_cognito_user_pool.main.id

  # OAuth 2.0 Authorization Code Grant configuration
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "profile", "email"]

  # Supported identity providers
  supported_identity_providers = ["COGNITO"]

  # Callback and logout URLs
  callback_urls = var.callback_urls
  logout_urls   = var.logout_urls

  # Token validity configuration
  access_token_validity  = 1  # 1 hour
  id_token_validity      = 1  # 1 hour
  refresh_token_validity = 30 # 30 days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Public client — no secret needed (PKCE provides security for native/CLI apps per OAuth 2.1)
  generate_secret = false

  # Explicit auth flows for password-based authentication (demo purposes)
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
  ]

  # Prevent user existence errors from leaking information
  prevent_user_existence_errors = "ENABLED"
}

# Test user for demonstration purposes (password-based auth)
resource "aws_cognito_user" "test_user" {
  user_pool_id = aws_cognito_user_pool.main.id
  username     = var.test_user_username
  password     = var.test_user_password

  attributes = {
    email          = var.test_user_email
    email_verified = "true"
  }

  # Ensure user is confirmed and ready for authentication
  message_action = "SUPPRESS"
}

# Resource Server for custom scopes (optional, supports scope enforcement)
resource "aws_cognito_resource_server" "agentcore" {
  identifier   = "https://agentcore.${var.project_name}.${var.environment}"
  name         = "AgentCore API"
  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "invoke"
    scope_description = "Invoke agent endpoints"
  }

  scope {
    scope_name        = "delegate"
    scope_description = "Delegate tasks between agents"
  }
}
