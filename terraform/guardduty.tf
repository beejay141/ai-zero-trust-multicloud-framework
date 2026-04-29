resource "aws_guardduty_detector" "main" {
  enable = true
}

# Enable GuardDuty malware protection
resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}
