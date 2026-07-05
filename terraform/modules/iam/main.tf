# =============================================================================
# IAM Module - Least-Privilege Roles for AgentCore SCA Platform
# =============================================================================
# Defines IAM roles for each agent and a deployment role for Terraform state
# access. Each role follows least-privilege principles.
# =============================================================================

data "aws_iam_policy_document" "agentcore_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

# -----------------------------------------------------------------------------
# Orchestrator Agent Role
# Permissions: Invoke Scanner/Analysis agents, read Secrets Manager
# -----------------------------------------------------------------------------

resource "aws_iam_role" "orchestrator" {
  name               = "${var.project_name}-orchestrator-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume_role.json

  tags = {
    Agent = "orchestrator"
  }
}

data "aws_iam_policy_document" "orchestrator_policy" {
  # Invoke Scanner and Analysis agents via AgentCore
  statement {
    sid    = "InvokeSubAgents"
    effect = "Allow"
    actions = [
      "bedrock:InvokeAgent",
      "bedrock:InvokeAgentAlias",
    ]
    resources = [
      var.scanner_agent_arn,
      "${var.scanner_agent_arn}/*",
      var.analysis_agent_arn,
      "${var.analysis_agent_arn}/*",
    ]
  }

  # Read secrets (HMAC signing keys, OAuth config)
  statement {
    sid    = "ReadSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = var.secrets_arns
  }
}

resource "aws_iam_role_policy" "orchestrator" {
  name   = "${var.project_name}-orchestrator-policy"
  role   = aws_iam_role.orchestrator.id
  policy = data.aws_iam_policy_document.orchestrator_policy.json
}

# -----------------------------------------------------------------------------
# Scanner Agent Role
# Permissions: Read Secrets Manager, access GitHub OAuth via AgentCore Identity
# -----------------------------------------------------------------------------

resource "aws_iam_role" "scanner" {
  name               = "${var.project_name}-scanner-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume_role.json

  tags = {
    Agent = "scanner"
  }
}

data "aws_iam_policy_document" "scanner_policy" {
  # Read secrets (GitHub OAuth client credentials)
  statement {
    sid    = "ReadSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = var.secrets_arns
  }

  # Access AgentCore Identity for OAuth token management (GitHub user-delegated)
  statement {
    sid    = "AgentCoreIdentityAccess"
    effect = "Allow"
    actions = [
      "bedrock:GetAgentCoreIdentity",
      "bedrock:RetrieveAgentCoreCredential",
      "bedrock:InitiateAgentCoreOAuthFlow",
    ]
    resources = [
      "arn:aws:bedrock:${var.region}:${var.account_id}:workload-identity/*",
      "arn:aws:bedrock:${var.region}:${var.account_id}:credential-provider/*",
    ]
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "${var.project_name}-scanner-policy"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner_policy.json
}

# -----------------------------------------------------------------------------
# Analysis Agent Role
# Permissions: Read Secrets Manager, access vulnerability databases
# -----------------------------------------------------------------------------

resource "aws_iam_role" "analysis" {
  name               = "${var.project_name}-analysis-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume_role.json

  tags = {
    Agent = "analysis"
  }
}

data "aws_iam_policy_document" "analysis_policy" {
  # Read secrets (M2M client credentials for vulnerability DBs)
  statement {
    sid    = "ReadSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = var.secrets_arns
  }

  # Access AgentCore Identity for M2M credential retrieval
  statement {
    sid    = "AgentCoreIdentityAccess"
    effect = "Allow"
    actions = [
      "bedrock:GetAgentCoreIdentity",
      "bedrock:RetrieveAgentCoreCredential",
    ]
    resources = [
      "arn:aws:bedrock:${var.region}:${var.account_id}:workload-identity/*",
      "arn:aws:bedrock:${var.region}:${var.account_id}:credential-provider/*",
    ]
  }
}

resource "aws_iam_role_policy" "analysis" {
  name   = "${var.project_name}-analysis-policy"
  role   = aws_iam_role.analysis.id
  policy = data.aws_iam_policy_document.analysis_policy.json
}

# -----------------------------------------------------------------------------
# Deployment Role
# Permissions: Full access to S3 state bucket (restricted from agent roles)
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "deployment_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "deployment" {
  name               = "${var.project_name}-deployment-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.deployment_assume_role.json

  tags = {
    Agent = "deployment"
  }
}

data "aws_iam_policy_document" "deployment_policy" {
  # Full access to Terraform state bucket
  statement {
    sid    = "StateBucketAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]
    resources = [
      var.state_bucket_arn,
      "${var.state_bucket_arn}/*",
    ]
  }

  # DynamoDB state lock table access
  statement {
    sid    = "StateLockAccess"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    resources = [
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/agentcore-sca-tfstate-lock",
    ]
  }

  # KMS access for state encryption/decryption
  statement {
    sid    = "StateEncryptionAccess"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [
      "arn:aws:kms:${var.region}:${var.account_id}:alias/terraform-state-key",
    ]
  }
}

resource "aws_iam_role_policy" "deployment" {
  name   = "${var.project_name}-deployment-policy"
  role   = aws_iam_role.deployment.id
  policy = data.aws_iam_policy_document.deployment_policy.json
}

# -----------------------------------------------------------------------------
# Deny state bucket access for agent roles (defense in depth)
# Ensures agent roles cannot access Terraform state even if misconfigured
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "deny_state_bucket" {
  statement {
    sid    = "DenyStateBucketAccess"
    effect = "Deny"
    actions = [
      "s3:*",
    ]
    resources = [
      var.state_bucket_arn,
      "${var.state_bucket_arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "orchestrator_deny_state" {
  name   = "${var.project_name}-orchestrator-deny-state"
  role   = aws_iam_role.orchestrator.id
  policy = data.aws_iam_policy_document.deny_state_bucket.json
}

resource "aws_iam_role_policy" "scanner_deny_state" {
  name   = "${var.project_name}-scanner-deny-state"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.deny_state_bucket.json
}

resource "aws_iam_role_policy" "analysis_deny_state" {
  name   = "${var.project_name}-analysis-deny-state"
  role   = aws_iam_role.analysis.id
  policy = data.aws_iam_policy_document.deny_state_bucket.json
}
