################################################################################
# VPC
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-${var.environment}-vpc"
  }
}

################################################################################
# Private Subnets (one per AZ for agent runtimes)
################################################################################

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-${var.environment}-private-${var.availability_zones[count.index]}"
    Tier = "private"
  }
}

################################################################################
# Security Groups — one per agent runtime
################################################################################

# Orchestrator Agent Security Group
resource "aws_security_group" "orchestrator" {
  name        = "${var.project_name}-${var.environment}-orchestrator-sg"
  description = "Security group for Orchestrator Agent runtime - allows outbound mTLS to Scanner and Analysis agents"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name  = "${var.project_name}-${var.environment}-orchestrator-sg"
    Agent = "orchestrator"
  }
}

# Scanner Agent Security Group
resource "aws_security_group" "scanner" {
  name        = "${var.project_name}-${var.environment}-scanner-sg"
  description = "Security group for Scanner Agent runtime - allows inbound mTLS from Orchestrator only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name  = "${var.project_name}-${var.environment}-scanner-sg"
    Agent = "scanner"
  }
}

# Analysis Agent Security Group
resource "aws_security_group" "analysis" {
  name        = "${var.project_name}-${var.environment}-analysis-sg"
  description = "Security group for Analysis Agent runtime - allows inbound mTLS from Orchestrator only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name  = "${var.project_name}-${var.environment}-analysis-sg"
    Agent = "analysis"
  }
}

################################################################################
# Security Group Rules — mTLS port access enforcement
################################################################################

# Orchestrator → Scanner: outbound on mTLS port
resource "aws_vpc_security_group_egress_rule" "orchestrator_to_scanner" {
  security_group_id            = aws_security_group.orchestrator.id
  description                  = "Allow outbound mTLS to Scanner Agent"
  ip_protocol                  = "tcp"
  from_port                    = var.mtls_port
  to_port                      = var.mtls_port
  referenced_security_group_id = aws_security_group.scanner.id
}

# Orchestrator → Analysis: outbound on mTLS port
resource "aws_vpc_security_group_egress_rule" "orchestrator_to_analysis" {
  security_group_id            = aws_security_group.orchestrator.id
  description                  = "Allow outbound mTLS to Analysis Agent"
  ip_protocol                  = "tcp"
  from_port                    = var.mtls_port
  to_port                      = var.mtls_port
  referenced_security_group_id = aws_security_group.analysis.id
}

# Scanner ← Orchestrator: inbound on mTLS port
resource "aws_vpc_security_group_ingress_rule" "scanner_from_orchestrator" {
  security_group_id            = aws_security_group.scanner.id
  description                  = "Allow inbound mTLS from Orchestrator Agent"
  ip_protocol                  = "tcp"
  from_port                    = var.mtls_port
  to_port                      = var.mtls_port
  referenced_security_group_id = aws_security_group.orchestrator.id
}

# Analysis ← Orchestrator: inbound on mTLS port
resource "aws_vpc_security_group_ingress_rule" "analysis_from_orchestrator" {
  security_group_id            = aws_security_group.analysis.id
  description                  = "Allow inbound mTLS from Orchestrator Agent"
  ip_protocol                  = "tcp"
  from_port                    = var.mtls_port
  to_port                      = var.mtls_port
  referenced_security_group_id = aws_security_group.orchestrator.id
}

################################################################################
# Deny all other inter-agent traffic (default deny via no additional rules)
# AWS security groups are deny-by-default — only explicitly allowed traffic
# passes. No additional egress/ingress rules means all other inter-agent
# communication is implicitly denied.
################################################################################

# Orchestrator: allow HTTPS egress for external API calls (Cognito, Secrets Manager)
resource "aws_vpc_security_group_egress_rule" "orchestrator_https_egress" {
  security_group_id = aws_security_group.orchestrator.id
  description       = "Allow HTTPS egress to AWS services and external APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Scanner: allow HTTPS egress for GitHub API and AWS services
resource "aws_vpc_security_group_egress_rule" "scanner_https_egress" {
  security_group_id = aws_security_group.scanner.id
  description       = "Allow HTTPS egress to GitHub API and AWS services"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Analysis: allow HTTPS egress for vulnerability DBs and AWS services
resource "aws_vpc_security_group_egress_rule" "analysis_https_egress" {
  security_group_id = aws_security_group.analysis.id
  description       = "Allow HTTPS egress to vulnerability databases and AWS services"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

################################################################################
# VPC Endpoints for AWS service access from private subnets
################################################################################

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true

  security_group_ids = [
    aws_security_group.orchestrator.id,
    aws_security_group.scanner.id,
    aws_security_group.analysis.id,
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}-secretsmanager-vpce"
  }
}

################################################################################
# Data sources
################################################################################

data "aws_region" "current" {}
