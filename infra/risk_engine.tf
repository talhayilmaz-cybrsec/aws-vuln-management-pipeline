# -----------------------------------------------------------------------------
# Phase 3: risk engine
#
# Inspector finding --EventBridge--> Lambda --> DynamoDB (every finding)
#                                          \--> SNS (P1 alerts, once each)
# -----------------------------------------------------------------------------

data "archive_file" "risk_engine" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/risk_engine"
  output_path = "${path.module}/.build/risk_engine.zip"
  excludes    = ["__pycache__"]
}

# --- Identity: only what the function needs ---------------------------------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "risk_engine" {
  name               = "${var.project}-risk-engine"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "risk_engine" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.risk_engine.arn}:*"]
  }

  statement {
    sid       = "FindingsTable"
    actions   = ["dynamodb:UpdateItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # The table and topic are encrypted with the project CMK.
  statement {
    sid       = "UseProjectKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.project.arn]
  }

  # Active tracing: send X-Ray trace segments (these APIs take no resource ARN).
  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }

  # Read-only, for the one-time backfill of findings that predate the engine.
  # ListFindings does not support resource-level permissions.
  statement {
    sid       = "BackfillReadFindings"
    actions   = ["inspector2:ListFindings"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "risk_engine" {
  name   = "risk-engine"
  role   = aws_iam_role.risk_engine.id
  policy = data.aws_iam_policy_document.risk_engine.json
}

# --- Function -----------------------------------------------------------------

resource "aws_cloudwatch_log_group" "risk_engine" {
  name              = "/aws/lambda/${var.project}-risk-engine"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.project.arn
}

resource "aws_lambda_function" "risk_engine" {
  function_name    = "${var.project}-risk-engine"
  description      = "Scores Inspector findings with CVSS + EPSS + CISA KEV + asset context"
  role             = aws_iam_role.risk_engine.arn
  runtime          = "python3.13"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.risk_engine.output_path
  source_code_hash = data.archive_file.risk_engine.output_base64sha256
  timeout          = 300 # backfill pages through every existing finding
  memory_size      = 256

  environment {
    variables = {
      TABLE_NAME       = aws_dynamodb_table.findings.name
      TOPIC_ARN        = aws_sns_topic.alerts.arn
      SLA_DAYS         = jsonencode(var.sla_days)
      ALERT_PRIORITIES = join(",", var.alert_priorities)
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_iam_role_policy.risk_engine, aws_cloudwatch_log_group.risk_engine]
}

# --- Trigger --------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "inspector_findings" {
  name        = "${var.project}-inspector-findings"
  description = "Every Amazon Inspector finding event (created, updated, closed)"
  event_pattern = jsonencode({
    source        = ["aws.inspector2"]
    "detail-type" = ["Inspector2 Finding"]
  })
}

resource "aws_cloudwatch_event_target" "risk_engine" {
  rule = aws_cloudwatch_event_rule.inspector_findings.name
  arn  = aws_lambda_function.risk_engine.arn

  retry_policy {
    maximum_retry_attempts       = 10
    maximum_event_age_in_seconds = 3600
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.risk_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector_findings.arn
}
