terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Remote state in the bucket created by bootstrap/. The bucket name contains
  # the AWS account ID, so it is passed at init time:
  #   terraform init -backend-config="bucket=<TF_STATE_BUCKET>"
  # use_lockfile = native S3 state locking (no DynamoDB lock table needed).
  backend "s3" {
    key          = "infra/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Repo      = "talhayilmaz-cybrsec/aws-vuln-management-pipeline"
    }
  }
}

data "aws_caller_identity" "current" {}
