resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/zero-trust-security-trail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security_controls.arn
  tags = merge(local.common_tags, {
    Name = "zero-trust-security-trail"
  })
}

# kics-scan ignore-block
resource "aws_sns_topic" "cloudtrail_notifications" {
  name              = "zero-trust-cloudtrail-notifications"
  kms_master_key_id = aws_kms_key.security_controls.arn
  tags = merge(local.common_tags, {
    Name = "zero-trust-cloudtrail-notifications"
  })
}

resource "aws_sns_topic_policy" "cloudtrail_notifications" {
  arn = aws_sns_topic.cloudtrail_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.cloudtrail_notifications.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowS3Notifications"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.cloudtrail_notifications.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = [
              aws_s3_bucket.access_logs.arn,
              aws_s3_bucket.security_logs.arn
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "zeroTrustCloudTrailCloudWatchRole"
  tags = merge(local.common_tags, {
    Name = "zeroTrustCloudTrailCloudWatchRole"
  })

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
  sns_topic_name                = aws_sns_topic.cloudtrail_notifications.name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security_controls.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn
  tags = merge(local.common_tags, {
    Name = "zero-trust-security-trail"
  })

  depends_on = [
    aws_s3_bucket_policy.security_logs_policy,
    aws_iam_role_policy.cloudtrail_cloudwatch,
    aws_sns_topic_policy.cloudtrail_notifications
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
