# Azure Zero Trust Conditional Access
# Requires MFA and compliant device for all users and applications
resource "azuread_conditional_access_policy" "zero_trust" {
  display_name = "Zero Trust - Require MFA and Compliant Device"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    users {
      included_users = ["All"]
    }

    applications {
      included_applications = ["All"]
    }

    locations {
      included_locations = ["All"]
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "compliantDevice"]
  }
}
