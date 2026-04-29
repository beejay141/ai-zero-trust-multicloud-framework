# GCP Zero Trust IAM and Organizational Policies
variable "org_id" {
  type = string
}

variable "project_id" {
  type = string
}

# Require OS Login for all compute instances
resource "google_organization_policy" "require_os_login" {
  org_id     = var.org_id
  constraint = "compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

# Disable serial port access
resource "google_organization_policy" "disable_serial_port" {
  org_id     = var.org_id
  constraint = "compute.disableSerialPortAccess"

  boolean_policy {
    enforced = true
  }
}

# Least privilege IAM binding with time-bound condition
resource "google_project_iam_binding" "least_privilege_binding" {
  project = var.project_id
  role    = "roles/viewer"
  members = ["group:security-team@example.com"]

  condition {
    title      = "Zero Trust Time-Bound Access"
    expression = "request.time < timestamp('2027-01-01T00:00:00Z')"
  }
}
