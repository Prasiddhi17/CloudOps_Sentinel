
variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the cloud security project"
  type        = string
  default     = "cloudops-sentinel"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "lambda_runtime" {
  description = "Python runtime for Lambda"
  type        = string
  default     = "python3.12"
}
