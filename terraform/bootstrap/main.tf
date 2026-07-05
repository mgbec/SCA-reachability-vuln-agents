# Bootstrap — creates the Terraform state backend resources.
#
# Run this ONCE before switching to the S3 backend:
#   cd terraform/bootstrap
#   terraform init
#   terraform apply
#
# Then uncomment the S3 backend block in ../backend.tf and run:
#   cd ..
#   terraform init -migrate-state

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # Bootstrap uses local state (by necessity)
  backend "local" {
    path = "bootstrap.tfstate"
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region for state resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "S3 bucket name for Terraform state"
  type        = string
  default     = "agentcore-sca-tfstate"
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for state locking"
  type        = string
  default     = "agentcore-sca-tfstate-lock"
}

variable "kms_key_alias" {
  description = "KMS key alias for state encryption"
  type        = string
  default     = "alias/terraform-state-key"
}

# --- KMS Key for state encryption ---

resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose = "terraform-state-encryption"
    ManagedBy = "bootstrap"
  }
}

resource "aws_kms_alias" "terraform_state" {
  name          = var.kms_key_alias
  target_key_id = aws_kms_key.terraform_state.key_id
}

# --- S3 Bucket for state ---

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.bucket_name

  tags = {
    Purpose = "terraform-state"
    ManagedBy = "bootstrap"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- DynamoDB Table for state locking ---

resource "aws_dynamodb_table" "terraform_lock" {
  name         = var.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Purpose = "terraform-state-locking"
    ManagedBy = "bootstrap"
  }
}

# --- Outputs ---

output "state_bucket_name" {
  value = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  value = aws_s3_bucket.terraform_state.arn
}

output "lock_table_name" {
  value = aws_dynamodb_table.terraform_lock.name
}

output "kms_key_arn" {
  value = aws_kms_key.terraform_state.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.terraform_state.name
}

output "next_steps" {
  value = <<-EOT
    Bootstrap complete! Next steps:
    1. Uncomment the S3 backend block in ../backend.tf
    2. Run: cd .. && terraform init -migrate-state
    3. Terraform will now use encrypted remote state with locking.
  EOT
}
