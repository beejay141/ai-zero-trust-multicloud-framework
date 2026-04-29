resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/zero-trust-security-trail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security_controls.arn
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "zeroTrustCloudTrailCloudWatchRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "zero-trust-cloudtrail-cloudwatch"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# Multi-region CloudTrail audit coverage
resource "aws_cloudtrail" "audit" {
  name                          = "zero-trust-security-trail"
  s3_bucket_name                = aws_s3_bucket.security_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security_controls.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn

  depends_on = [
    aws_s3_bucket_policy.security_logs_policy,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
}
