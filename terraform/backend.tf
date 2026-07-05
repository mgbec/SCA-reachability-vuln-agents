terraform {
  # Remote S3 backend — uncomment after bootstrapping the bucket/DynamoDB table.
  # See terraform/bootstrap/ for the one-time setup.
  #
  # backend "s3" {
  #   bucket         = "agentcore-sca-tfstate"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   kms_key_id     = "alias/terraform-state-key"
  #   dynamodb_table = "agentcore-sca-tfstate-lock"
  # }

  # Local backend (default) — used until the S3 bucket is bootstrapped.
  backend "local" {
    path = "terraform.tfstate"
  }
}
