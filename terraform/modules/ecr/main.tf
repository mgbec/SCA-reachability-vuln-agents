# ECR module — Container repositories for AgentCore Runtime agents

resource "aws_ecr_repository" "sca_orchestrator" {
  name                 = "${var.project_name}-${var.environment}/sca-orchestrator"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Component = "ecr"
    Agent     = "orchestrator"
  })
}

resource "aws_ecr_repository" "sca_scanner" {
  name                 = "${var.project_name}-${var.environment}/sca-scanner"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Component = "ecr"
    Agent     = "scanner"
  })
}

resource "aws_ecr_repository" "sca_analysis" {
  name                 = "${var.project_name}-${var.environment}/sca-analysis"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Component = "ecr"
    Agent     = "analysis"
  })
}

# Lifecycle policies — keep only the last 5 images per repository

resource "aws_ecr_lifecycle_policy" "sca_orchestrator" {
  repository = aws_ecr_repository.sca_orchestrator.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "sca_scanner" {
  repository = aws_ecr_repository.sca_scanner.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "sca_analysis" {
  repository = aws_ecr_repository.sca_analysis.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
