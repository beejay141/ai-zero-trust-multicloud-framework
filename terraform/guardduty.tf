resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:This reference repo provisions a standalone GuardDuty detector and does not model organization-wide GuardDuty administration.
  enable = true
  tags = merge(local.common_tags, {
    Name = "zero-trust-guardduty-detector"
  })
}

# Enable GuardDuty malware protection
resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}
