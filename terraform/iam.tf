resource "aws_iam_policy" "strict_policy" {
  name        = "zero-trust-strict-policy"
  description = "Least-privilege IAM policy for Zero Trust reference controls"
  tags = merge(local.common_tags, {
    Name = "zero-trust-strict-policy"
  })

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListSecurityLogsBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.security_logs.arn]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      },
      {
        Sid      = "WriteSecurityLogsObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.security_logs.arn}/*"]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
          StringEquals = {
            "s3:x-amz-server-side-encryption"                = "aws:kms"
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.security_controls.arn
          }
        }
      }
    ]
  })
}

resource "aws_iam_account_password_policy" "strict_policy" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
