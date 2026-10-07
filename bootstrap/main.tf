# -----------------------------------------------------------------------------
# Bootstrap stack - run ONCE, manually, from AWS CloudShell.
#
# Creates the two things the automated pipeline needs before it can run:
#   1. An S3 bucket that stores Terraform state for the main `infra/` stack.
#   2. A GitHub OIDC trust + IAM role, so GitHub Actions can deploy to AWS
#      with short-lived credentials instead of stored access keys.
#
# This stack keeps its own state locally (in CloudShell's persistent home
# directory). It is tiny and rarely changes, which is the standard way to
# solve the "where does the state bucket's own state live" problem.
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform-bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  state_bucket = "${var.project}-tfstate-${local.account_id}"

  # GitHub's OIDC subject includes immutable numeric IDs next to the names.
  # Matching on the IDs means a deleted-and-recreated account or repository
  # with the same name can NOT inherit this role's trust.
  github_sub = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}:ref:refs/heads/main"
}

# =============================================================================
# 1. Terraform state bucket
# =============================================================================

resource "aws_s3_bucket" "tfstate" {
  bucket = local.state_bucket

  # State is the source of truth for every deployed resource. Guard it.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled" # recover from a corrupted or deleted state file
  }
}

# Accepted risk (documented exception): the AWS managed S3 key is used instead
# of a customer managed key. The bucket is private, TLS-only and versioned, and
# only the account's admin and the deploy role can read it. A CMK here would
# add cost and a second bootstrap dependency for little benefit in a lab.
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Reject any request that is not over TLS.
resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# =============================================================================
# 2. GitHub Actions OIDC trust
# =============================================================================

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

# Only workflows running from the main branch of THIS repository can assume
# the role. Forks, other branches, and other repositories are rejected.
data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_sub]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name                 = "${var.project}-github-deploy"
  description          = "Assumed by GitHub Actions (OIDC) to deploy the infra/ stack"
  assume_role_policy   = data.aws_iam_policy_document.github_trust.json
  max_session_duration = 3600
}

# Broad service access for the resources this project deploys...
resource "aws_iam_role_policy_attachment" "power_user" {
  role       = aws_iam_role.github_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# ...but PowerUserAccess deliberately excludes IAM. Grant IAM only for roles
# and instance profiles whose names start with the project prefix, so the
# pipeline cannot create or modify any other identity in the account.
data "aws_iam_policy_document" "scoped_iam" {
  statement {
    sid = "ManageProjectRolesOnly"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole",
      "iam:TagRole", "iam:UntagRole", "iam:ListRoleTags",
      "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy",
      "iam:ListRolePolicies", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
      "iam:PassRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.project}-*"]
  }

  statement {
    sid = "ManageProjectInstanceProfilesOnly"
    actions = [
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
      "iam:GetInstanceProfile", "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile",
      "iam:UntagInstanceProfile",
    ]
    resources = ["arn:aws:iam::${local.account_id}:instance-profile/${var.project}-*"]
  }

  statement {
    sid       = "ServiceLinkedRolesForSecurityServices"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "inspector2.amazonaws.com",
        "agentless.inspector2.amazonaws.com",
        "securityhub.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "scoped_iam" {
  name   = "scoped-iam"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.scoped_iam.json
}
