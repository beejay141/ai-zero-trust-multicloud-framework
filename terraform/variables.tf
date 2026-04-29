variable "aws_region" {
  description = "AWS region for the reference deployment"
  type        = string
  default     = "us-east-1"
}

variable "security_log_bucket_name" {
  description = "Unique S3 bucket name for security logs"
  type        = string
  default     = "zero-trust-security-logs-reference"
}
