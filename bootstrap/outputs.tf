# These two values are saved as GitHub repository variables
# (Settings -> Secrets and variables -> Actions -> Variables).
# Neither is a secret: the role can only be assumed through GitHub's OIDC
# token for this repository's main branch.

output "AWS_ROLE_ARN" {
  description = "IAM role GitHub Actions assumes via OIDC"
  value       = aws_iam_role.github_deploy.arn
}

output "TF_STATE_BUCKET" {
  description = "S3 bucket holding Terraform state for the infra/ stack"
  value       = aws_s3_bucket.tfstate.bucket
}
