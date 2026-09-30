mock_provider "aws" {
  override_data {
    target = data.aws_organizations_organization.current
    values = {
      id = "o-exampleorg1"
      roots = [{
        arn          = "arn:aws:organizations::111111111111:root/o-exampleorg1/r-ab12"
        id           = "r-ab12"
        name         = "Root"
        policy_types = [{ type = "RESOURCE_CONTROL_POLICY", status = "ENABLED" }]
      }]
    }
  }
}

variables {
  target_ids = ["r-ab12"]
}

run "defaults_render_all_nine_controls" {
  command = plan

  assert {
    condition     = local.policies["identity-perimeter"].controls == ["CT.KMS.PV.7", "CT.S3.PV.4", "CT.SECRETSMANAGER.PV.1", "CT.SQS.PV.1", "CT.STS.PV.1"]
    error_message = "identity-perimeter should contain the five org-perimeter controls."
  }

  assert {
    condition     = local.policies["s3-data-protection"].controls == ["CT.S3.PV.2", "CT.S3.PV.3", "CT.S3.PV.5", "CT.S3.PV.6"]
    error_message = "s3-data-protection should contain the four S3 request controls."
  }

  assert {
    condition = [for s in jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement : s.Sid] == [
      "CTKMSPV7", "CTS3PV4", "CTSECRETSMANAGERPV1", "CTSQSPV1", "CTSTSPV1",
    ]
    error_message = "Unexpected Sids in identity-perimeter."
  }

  assert {
    condition     = [for s in jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement : s.Sid] == ["CTS3PV2", "CTS3PV3", "CTS3PV5", "CTS3PV6"]
    error_message = "Unexpected Sids in s3-data-protection."
  }

  # Matches the CT.KMS.PV.7 template with OrganizationIds populated and no exemptions.
  assert {
    condition = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[0] == {
      Sid       = "CTKMSPV7"
      Effect    = "Deny"
      Principal = "*"
      Action    = "kms:*"
      Resource  = "*"
      Condition = {
        BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
        StringNotEqualsIfExists = { "aws:PrincipalOrgID" = ["o-exampleorg1"] }
      }
    }
    error_message = "CT.KMS.PV.7 statement does not match the AWS template."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[4].Action == ["sts:AssumeRole", "sts:SetContext"]
    error_message = "CT.STS.PV.1 must only cover sts:AssumeRole and sts:SetContext."
  }

  # Matches the CT.S3.PV.6 template without ExemptedResourceArns.
  assert {
    condition = jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement[3] == {
      Sid       = "CTS3PV6"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "*"
      Condition = { Null = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "true" } }
    }
    error_message = "CT.S3.PV.6 statement does not match the AWS template."
  }

  assert {
    condition     = alltrue([for c in values(local.policy_content) : !strcontains(c, "ArnNotLike") && !strcontains(c, "NotResource")])
    error_message = "No optional blocks should render without parameters."
  }

  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : p.type == "RESOURCE_CONTROL_POLICY"])
    error_message = "Policies must be RCPs."
  }

  assert {
    condition     = keys(aws_organizations_policy_attachment.this) == ["identity-perimeter/r-ab12", "s3-data-protection/r-ab12"]
    error_message = "Each policy should attach to each target."
  }
}

run "parameters_render_optional_blocks" {
  command = plan

  variables {
    additional_trusted_organization_ids = ["o-partnerorg12"]
    exempted_principal_arns = {
      "CT.STS.PV.1" = ["arn:aws:iam::*:role/VendorAccess"]
    }
    s3_sse_kms_exempted_resource_arns = ["arn:aws:s3:::legacy-bucket/*"]
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[4].Condition.ArnNotLike == { "aws:PrincipalArn" = ["arn:aws:iam::*:role/VendorAccess"] }
    error_message = "CT.STS.PV.1 should carry the exempted principal."
  }

  assert {
    condition     = length(regexall("ArnNotLike", aws_organizations_policy.this["identity-perimeter"].content)) == 1
    error_message = "Exemptions must only apply to the control they are keyed to."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[0].Condition.StringNotEqualsIfExists["aws:PrincipalOrgID"] == ["o-exampleorg1", "o-partnerorg12"]
    error_message = "Additional trusted organizations should be appended."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement[3].NotResource == ["arn:aws:s3:::legacy-bucket/*"]
    error_message = "CT.S3.PV.6 should use NotResource for exempted resources."
  }

  assert {
    condition     = !can(jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement[3].Resource)
    error_message = "CT.S3.PV.6 must not set both Resource and NotResource."
  }
}

run "subset_of_controls_skips_empty_policy" {
  command = plan

  variables {
    enabled_controls = ["CT.S3.PV.5"]
    target_ids       = ["ou-ab12-cdef3456", "123456789012"]
  }

  assert {
    condition     = keys(aws_organizations_policy.this) == ["s3-data-protection"]
    error_message = "Only the S3 policy should be created."
  }

  assert {
    condition     = length(jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement) == 1
    error_message = "Only CT.S3.PV.5 should be rendered."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 2
    error_message = "The S3 policy should attach to both targets."
  }
}

run "rejects_unknown_control" {
  command = plan

  variables {
    enabled_controls = ["CT.S3.PV.99"]
  }

  expect_failures = [var.enabled_controls]
}

run "rejects_bad_target" {
  command = plan

  variables {
    target_ids = ["not-a-target"]
  }

  expect_failures = [var.target_ids]
}

run "rejects_empty_targets" {
  command = plan

  variables {
    target_ids = []
  }

  expect_failures = [var.target_ids]
}

run "fails_when_rcp_type_disabled" {
  command = plan

  override_data {
    target = data.aws_organizations_organization.current
    values = {
      id = "o-exampleorg1"
      roots = [{
        arn          = "arn:aws:organizations::111111111111:root/o-exampleorg1/r-ab12"
        id           = "r-ab12"
        name         = "Root"
        policy_types = [{ type = "SERVICE_CONTROL_POLICY", status = "ENABLED" }]
      }]
    }
  }

  expect_failures = [aws_organizations_policy.this]
}
