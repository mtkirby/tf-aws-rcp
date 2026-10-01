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

run "full_org_restrict_off_by_default" {
  command = plan

  assert {
    condition     = !contains(keys(aws_organizations_policy.this), "RCPFullOrgRestrict")
    error_message = "RCPFullOrgRestrict must not be created unless enabled."
  }
}

run "full_org_restrict_renders_template" {
  command = plan

  variables {
    enable_rcp_full_org_restrict = true
    full_org_restrict_services   = ["kms", "s3", "dynamodb"]
  }

  # The requested template, with Action listing services because RCPs reject "Action": "*".
  assert {
    condition = jsondecode(aws_organizations_policy.this["RCPFullOrgRestrict"].content) == {
      Version = "2012-10-17"
      Statement = [{
        Sid       = "RCPFullOrgRestrict"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["kms:*", "s3:*", "dynamodb:*", "sts:AssumeRole", "sts:SetContext"]
        Resource  = "*"
        Condition = {
          BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
          StringNotEqualsIfExists = { "aws:PrincipalOrgID" = ["o-exampleorg1"] }
        }
      }]
    }
    error_message = "RCPFullOrgRestrict does not match the expected template."
  }

  assert {
    condition     = keys(aws_organizations_policy_attachment.this) == ["RCPFullOrgRestrict/r-ab12", "identity-perimeter/r-ab12", "s3-data-protection/r-ab12"]
    error_message = "All three policies should attach to the target."
  }
}

run "full_org_restrict_default_services_allow_federation" {
  command = plan

  variables {
    enable_rcp_full_org_restrict = true
  }

  assert {
    condition     = !contains(jsondecode(aws_organizations_policy.this["RCPFullOrgRestrict"].content).Statement[0].Action, "*")
    error_message = "RCPs reject \"Action\": \"*\"."
  }

  assert {
    condition = length(setintersection(
      jsondecode(aws_organizations_policy.this["RCPFullOrgRestrict"].content).Statement[0].Action,
      ["sts:*", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:TagSession", "sts:SetSourceIdentity", "cognito-identity:*", "cognito-idp:*", "rolesanywhere:*", "signin:*"]
    )) == 0
    error_message = "Federation and sign-in actions must not be denied."
  }

  assert {
    condition     = length(aws_organizations_policy.this["RCPFullOrgRestrict"].content) <= 5120
    error_message = "The default service list must fit in one RCP."
  }
}

run "full_org_restrict_exemption_and_standalone" {
  command = plan

  variables {
    enable_rcp_full_org_restrict = true
    enabled_controls             = []
    exempted_principal_arns = {
      "RCPFullOrgRestrict" = ["arn:aws:iam::*:role/BreakGlass"]
    }
  }

  assert {
    condition     = keys(aws_organizations_policy.this) == ["RCPFullOrgRestrict"]
    error_message = "With no CT controls enabled, only RCPFullOrgRestrict should be created."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["RCPFullOrgRestrict"].content).Statement[0].Condition.ArnNotLike == { "aws:PrincipalArn" = ["arn:aws:iam::*:role/BreakGlass"] }
    error_message = "RCPFullOrgRestrict should carry its exempted principals."
  }
}

run "bypass_tag_off_by_default" {
  command = plan

  variables {
    enable_rcp_full_org_restrict = true
  }

  assert {
    condition     = alltrue([for c in values(local.policy_content) : !strcontains(c, "BypassRCP")])
    error_message = "Without the option, no policy should mention the bypass tag."
  }
}

run "bypass_tag_applies_to_every_statement" {
  command = plan

  variables {
    enable_rcp_full_org_restrict = true
    full_org_restrict_services   = ["kms", "s3"]
    enable_rcp_bypass_tag        = true
    exempted_principal_arns = {
      "CT.STS.PV.1" = ["arn:aws:iam::*:role/VendorAccess"]
    }
  }

  assert {
    condition = alltrue(flatten([
      for c in values(local.policy_content) : [
        for st in jsondecode(c).Statement : st.Condition.StringNotEquals["aws:ResourceTag/BypassRCP"] == "True"
      ]
    ]))
    error_message = "Every statement should skip resources tagged BypassRCP = True."
  }

  assert {
    condition = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[0].Condition == {
      BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
      StringNotEqualsIfExists = { "aws:PrincipalOrgID" = ["o-exampleorg1"] }
      StringNotEquals         = { "aws:ResourceTag/BypassRCP" = "True" }
    }
    error_message = "CT.KMS.PV.7 should gain only the bypass condition."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["s3-data-protection"].content).Statement[0].Condition.StringNotEquals == { "s3:authType" = "REST-HEADER", "aws:ResourceTag/BypassRCP" = "True" }
    error_message = "CT.S3.PV.2 should keep its own StringNotEquals key alongside the bypass tag."
  }

  assert {
    condition     = jsondecode(aws_organizations_policy.this["identity-perimeter"].content).Statement[4].Condition.ArnNotLike == { "aws:PrincipalArn" = ["arn:aws:iam::*:role/VendorAccess"] }
    error_message = "Principal exemptions should still render with the bypass tag on."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 3
    error_message = "The bypass tag should not change the RCP attachments."
  }
}

run "rejects_sts_in_full_org_services" {
  command = plan

  variables {
    full_org_restrict_services = ["kms", "sts"]
  }

  expect_failures = [var.full_org_restrict_services]
}

run "rejects_wildcard_full_org_service" {
  command = plan

  variables {
    full_org_restrict_services = ["*"]
  }

  expect_failures = [var.full_org_restrict_services]
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
