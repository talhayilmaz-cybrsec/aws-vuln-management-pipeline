# One customer managed key for the project's data at rest (SNS alerts,
# DynamoDB findings). A CMK, unlike an AWS managed key, gives us a key policy
# we control, automatic rotation, and CloudTrail visibility into every use.
# Cost: about $1/month while it exists.
resource "aws_kms_key" "project" {
  description             = "${var.project}: encrypts alerts and findings data"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # shortest window; this is a disposable lab
  policy                  = data.aws_iam_policy_document.kms.json
}

data "aws_iam_policy_document" "kms" {
  # Standard first statement: the account (via IAM policies) administers and
  # uses the key. Without it the key could become unmanageable.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # CloudWatch Logs encrypts the risk engine's log group with this key.
  # Scoped by encryption context to this account's log groups only.
  statement {
    sid = "CloudWatchLogs"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_alias" "project" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.project.key_id
}
