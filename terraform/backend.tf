terraform {
  backend "s3" {
    bucket         = "agentcore-sca-tfstate-339712707840-us-east-1"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "agentcore-sca-tfstate-lock"
  }
}
