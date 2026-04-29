# AWS Config for continuous compliance monitoring
resource "aws_iam_role" "config_role" {
  name = "zeroTrustAWSConfigRole"
  tags = merge(local.common_tags, {
    Name = "zeroTrustAWSConfigRole"
  })

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "zero-trust-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "delivery" {
  name           = "zero-trust-config-delivery"
  s3_bucket_name = aws_s3_bucket.security_logs.bucket
  s3_key_prefix  = "config"

  depends_on = [aws_s3_bucket_policy.security_logs_policy]
}

resource "aws_config_configuration_recorder_status" "recorder_status" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.delivery]
}
