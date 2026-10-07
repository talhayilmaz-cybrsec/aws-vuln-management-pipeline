# -----------------------------------------------------------------------------
# Destinations for prioritized findings (used by the risk engine in Phase 3)
# -----------------------------------------------------------------------------

# Alerts for findings that cross the risk threshold (critical / CISA KEV).
resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-alerts"
  kms_master_key_id = aws_kms_key.project.arn # encrypted at rest with the project CMK
}

# Email subscriptions must be confirmed from the inbox before they deliver.
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# System of record for every finding: risk score, SLA due date, status.
# Feeds the weekly metrics report (Phase 4): counts, SLA breaches, MTTR.
resource "aws_dynamodb_table" "findings" {
  name         = "${var.project}-findings"
  billing_mode = "PAY_PER_REQUEST" # no idle cost
  hash_key     = "finding_arn"

  attribute {
    name = "finding_arn"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.project.arn
  }
}
