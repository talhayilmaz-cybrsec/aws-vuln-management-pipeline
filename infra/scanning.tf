# -----------------------------------------------------------------------------
# Runtime vulnerability scanning
#
# Amazon Inspector continuously scans:
#   - EC2 instances (OS + language packages, via the SSM agent)
#   - ECR container images (on push, then continuously as new CVEs appear)
#   - Lambda functions (code dependencies)
# Findings are published to EventBridge (consumed by the risk engine) and to
# Security Hub (central aggregation view).
# -----------------------------------------------------------------------------

resource "aws_inspector2_enabler" "this" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]

  # Disabling Inspector across three resource types can take well over the
  # provider's 5-minute default; observed during teardown.
  timeouts {
    create = "15m"
    delete = "20m"
  }
}

# Security Hub as the aggregation layer. Inspector findings arrive through the
# built-in product integration. Default compliance standards are disabled to
# keep cost near zero; this project uses Security Hub only for aggregation.
resource "aws_securityhub_account" "this" {
  enable_default_standards = false
  auto_enable_controls     = false
}

# Container registry for the demo image. Inspector's enhanced scanning covers
# every repository once ECR scanning is enabled above.
resource "aws_ecr_repository" "demo_app" {
  name                 = "${var.project}/demo-app"
  image_tag_mutability = "IMMUTABLE" # a tag always points at the image that was scanned
  force_delete         = true        # allow `terraform destroy` with images present

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}
