terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  access_log_bucket_name = "${var.security_log_bucket_name}-access"
  common_tags = {
    Project         = "ai-zero-trust-multicloud-framework"
    Environment     = "security"
    ManagedBy       = "terraform"
    SecurityControl = "zero-trust"
  }
}

resource "aws_kms_key" "security_controls" {
  description             = "KMS key for Zero Trust logging and compliance controls"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(local.common_tags, {
    Name = "zero-trust-security-controls"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailUsage"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowConfigUsage"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "security_controls" {
  name          = "alias/zero-trust-security-controls"
  target_key_id = aws_kms_key.security_controls.key_id
}

resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "zero-trust-account-analyzer"
  type          = "ACCOUNT"

  tags = merge(local.common_tags, {
    Name = "zero-trust-account-analyzer"
  })
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is intentionally excluded from this standalone reference implementation.
  bucket = local.access_log_bucket_name
  tags = merge(local.common_tags, {
    Name = local.access_log_bucket_name
  })
}

resource "aws_s3_bucket_versioning" "access_logs_versioning" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_enc" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_controls.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_block" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs_ownership" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_lifecycle" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "retain-audit-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "access_logs_notifications" {
  bucket = aws_s3_bucket.access_logs.id

  topic {
    topic_arn = aws_sns_topic.cloudtrail_notifications.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sns_topic_policy.cloudtrail_notifications]
}

resource "aws_s3_bucket_policy" "access_logs_policy" {
  bucket = aws_s3_bucket.access_logs.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "${aws_s3_bucket.access_logs.arn}",
        "${aws_s3_bucket.access_logs.arn}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "AllowS3AccessLogs",
      "Effect": "Allow",
      "Principal": {
        "Service": "logging.s3.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.access_logs.arn}/s3-access-logs/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    }
  ]
}
POLICY
}

# Encrypted S3 bucket for security logs
resource "aws_s3_bucket" "security_logs" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is intentionally excluded from this standalone reference implementation.
  bucket = var.security_log_bucket_name
  tags = merge(local.common_tags, {
    Name = var.security_log_bucket_name
  })
}

resource "aws_s3_bucket_versioning" "security_logs_versioning" {
  bucket = aws_s3_bucket.security_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs_enc" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.security_controls.arn
      sse_algorithm     = "aws:kms"
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs_block" {
  bucket                  = aws_s3_bucket.security_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "security_logs_ownership" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_logging" "security_logs_logging" {
  bucket        = aws_s3_bucket.security_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access-logs/security-logs/"

  depends_on = [aws_s3_bucket_policy.access_logs_policy]
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs_lifecycle" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "retain-security-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "security_logs_notifications" {
  bucket = aws_s3_bucket.security_logs.id

  topic {
    topic_arn = aws_sns_topic.cloudtrail_notifications.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic_policy.cloudtrail_notifications]
}

resource "aws_s3_bucket_policy" "security_logs_policy" {
  bucket = aws_s3_bucket.security_logs.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "${aws_s3_bucket.security_logs.arn}",
        "${aws_s3_bucket.security_logs.arn}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "AllowCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.security_logs.arn}",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    },
    {
      "Sid": "AllowCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.security_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
        }
      }
    },
    {
      "Sid": "AllowConfigWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": [
        "s3:GetBucketAcl",
        "s3:ListBucket"
      ],
      "Resource": "${aws_s3_bucket.security_logs.arn}",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    },
    {
      "Sid": "AllowConfigObjectWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.security_logs.arn}/config/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}",
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
POLICY
}
