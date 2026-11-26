
terraform {
  required_version = ">= 1.5.0"

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
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# Package the Python Lambda function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/lambda.zip"
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.project_name}-trail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Project = var.project_name
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudTrail bucket policy
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# CloudTrail audit trail
resource "aws_cloudtrail" "security_trail" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs
  ]

  tags = {
    Project = var.project_name
  }
}

# DynamoDB table for detected incidents
resource "aws_dynamodb_table" "incidents" {
  name           = "SecurityIncidents"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  tags = {
    Project = var.project_name
  }
}

# SNS topic for email alerts
resource "aws_sns_topic" "security_alerts" {
  name = "SecurityAlerts"

  tags = {
    Project = var.project_name
  }
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = 7

  tags = {
    Project = var.project_name
  }
}

# Lambda execution role and permissions are defined in iam.tf

# Python Lambda function
resource "aws_lambda_function" "security_processor" {
  function_name = var.project_name
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "handler.lambda_handler"
  runtime       = var.lambda_runtime

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.incidents.name
      TOPIC_ARN  = aws_sns_topic.security_alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_permissions
  ]

  tags = {
    Project = var.project_name
  }
}

# EventBridge rule: failed AWS Console sign-ins
resource "aws_cloudwatch_event_rule" "failed_login" {
  name        = "${var.project_name}-failed-login"
  description = "Detect failed AWS Console sign-in attempts"

  event_pattern = jsonencode({
    source        = ["aws.signin"]
    "detail-type" = ["AWS Console Sign In via CloudTrail"]

    detail = {
      eventSource = ["signin.amazonaws.com"]
      eventName   = ["ConsoleLogin"]

      responseElements = {
        ConsoleLogin = ["Failure"]
      }
    }
  })

  tags = {
    Project = var.project_name
  }
}

# EventBridge rule: sensitive IAM changes
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "${var.project_name}-iam-changes"
  description = "Detect sensitive IAM policy and access changes"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]

    detail = {
      eventSource = ["iam.amazonaws.com"]

      eventName = [
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateAccessKey",
        "UpdateAssumeRolePolicy",
        "AddUserToGroup"
      ]
    }
  })

  tags = {
    Project = var.project_name
  }
}

# Connect failed-login events to Lambda
resource "aws_cloudwatch_event_target" "failed_login_target" {
  rule      = aws_cloudwatch_event_rule.failed_login.name
  target_id = "SecurityLambda"
  arn       = aws_lambda_function.security_processor.arn

  depends_on = [
    aws_lambda_permission.failed_login
  ]
}

# Connect IAM-change events to Lambda
resource "aws_cloudwatch_event_target" "iam_changes_target" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "SecurityLambda"
  arn       = aws_lambda_function.security_processor.arn

  depends_on = [
    aws_lambda_permission.iam_changes
  ]
}

# Allow EventBridge to invoke Lambda for failed logins
resource "aws_lambda_permission" "failed_login" {
  statement_id  = "AllowEventBridgeFailedLogin"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.failed_login.arn
}

# Allow EventBridge to invoke Lambda for IAM changes
resource "aws_lambda_permission" "iam_changes" {
  statement_id  = "AllowEventBridgeIAMChanges"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_changes.arn
}
