terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # RESOURCE_CONTROL_POLICY support in aws_organizations_policy landed in 5.78.0.
      version = ">= 5.78.0, < 7.0.0"
    }
  }

  # Configure remote state before applying, e.g.:
  # backend "s3" {
  #   bucket       = "my-terraform-state"
  #   key          = "organizations/rcp/terraform.tfstate"
  #   region       = "us-east-1"
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region
}
