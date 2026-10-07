output "ecr_repository_url" {
  description = "Push the demo image here for Inspector to scan"
  value       = aws_ecr_repository.demo_app.repository_url
}

output "scan_target_instance_id" {
  description = "EC2 instance Inspector scans (null when deploy_scan_target = false)"
  value       = one(aws_instance.target[*].id)
}

output "alerts_topic_arn" {
  description = "SNS topic for prioritized alerts"
  value       = aws_sns_topic.alerts.arn
}

output "findings_table_name" {
  description = "DynamoDB table holding scored findings"
  value       = aws_dynamodb_table.findings.name
}
