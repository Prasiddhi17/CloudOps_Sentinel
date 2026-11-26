
output "aws_region" {
  description = "AWS deployment region"
  value       = var.aws_region
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.security_processor.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.security_processor.arn
}

output "dynamodb_table_name" {
  description = "DynamoDB incidents table"
  value       = aws_dynamodb_table.incidents.name
}

output "sns_topic_arn" {
  description = "SNS security alert topic ARN"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket containing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "cloudtrail_trail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.security_trail.name
}

output "failed_login_rule_name" {
  description = "EventBridge failed-login rule"
  value       = aws_cloudwatch_event_rule.failed_login.name
}

output "iam_changes_rule_name" {
  description = "EventBridge IAM-changes rule"
  value       = aws_cloudwatch_event_rule.iam_changes.name
}
