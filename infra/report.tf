# -----------------------------------------------------------------------------
# Phase 4: weekly metrics report
#
# EventBridge schedule (Mondays) -> Lambda -> reads the findings table ->
# emails open counts, SLA compliance, MTTR and top risks via the alerts topic.
# -----------------------------------------------------------------------------

data "archive_file" "report" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/report"
  output_path = "${path.module}/.build/report.zip"
  excludes    = ["__pycache__"]
}

resource "aws_iam_role" "report" {
  name               = "${var.project}-report"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "report" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.report.arn}:*"]
  }

  statement {
    sid       = "ReadFindings"
    actions   = ["dynamodb:Scan"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "PublishReport"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "UseProjectKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.project.arn]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "report" {
  name   = "report"
  role   = aws_iam_role.report.id
  policy = data.aws_iam_policy_document.report.json
}

resource "aws_cloudwatch_log_group" "report" {
  name              = "/aws/lambda/${var.project}-report"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.project.arn
}

resource "aws_lambda_function" "report" {
  function_name    = "${var.project}-report"
  description      = "Weekly vulnerability metrics: open by priority, SLA compliance, MTTR"
  role             = aws_iam_role.report.arn
  runtime          = "python3.13"
  handler          = "report.lambda_handler"
  filename         = data.archive_file.report.output_path
  source_code_hash = data.archive_file.report.output_base64sha256
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.findings.name
      TOPIC_ARN  = aws_sns_topic.alerts.arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_iam_role_policy.report, aws_cloudwatch_log_group.report]
}

resource "aws_cloudwatch_event_rule" "weekly_report" {
  name                = "${var.project}-weekly-report"
  description         = "Weekly vulnerability metrics report"
  schedule_expression = var.report_schedule
}

resource "aws_cloudwatch_event_target" "weekly_report" {
  rule = aws_cloudwatch_event_rule.weekly_report.name
  arn  = aws_lambda_function.report.arn
}

resource "aws_lambda_permission" "weekly_report" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.weekly_report.arn
}
