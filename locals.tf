locals {
  organization_ids = distinct(concat([data.aws_organizations_organization.current.id], var.additional_trusted_organization_ids))

  # Condition shared by the "principals in my organization, or an AWS service" controls.
  org_perimeter_condition = {
    BoolIfExists            = { "aws:PrincipalIsAWSService" = "false" }
    StringNotEqualsIfExists = { "aws:PrincipalOrgID" = local.organization_ids }
  }

  # Statement bodies taken from the AWS Control Tower RCP templates:
  # https://docs.aws.amazon.com/controltower/latest/controlreference/list-of-rcp-controls.html
  control_statements = {
    "CT.KMS.PV.7" = {
      Sid       = "CTKMSPV7"
      Action    = "kms:*"
      Condition = local.org_perimeter_condition
    }
    "CT.S3.PV.2" = {
      Sid       = "CTS3PV2"
      Action    = "s3:*"
      Condition = { StringNotEquals = { "s3:authType" = "REST-HEADER" } }
    }
    "CT.S3.PV.3" = {
      Sid       = "CTS3PV3"
      Action    = "s3:*"
      Condition = { NumericLessThan = { "s3:TlsVersion" = "1.3" } }
    }
    "CT.S3.PV.4" = {
      Sid       = "CTS3PV4"
      Action    = "s3:*"
      Condition = local.org_perimeter_condition
    }
    "CT.S3.PV.5" = {
      Sid       = "CTS3PV5"
      Action    = "s3:*"
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }
    "CT.S3.PV.6" = {
      Sid       = "CTS3PV6"
      Action    = "s3:PutObject"
      Condition = { Null = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "true" } }
    }
    "CT.SECRETSMANAGER.PV.1" = {
      Sid       = "CTSECRETSMANAGERPV1"
      Action    = "secretsmanager:*"
      Condition = local.org_perimeter_condition
    }
    "CT.SQS.PV.1" = {
      Sid       = "CTSQSPV1"
      Action    = "sqs:*"
      Condition = local.org_perimeter_condition
    }
    "CT.STS.PV.1" = {
      Sid       = "CTSTSPV1"
      Action    = ["sts:AssumeRole", "sts:SetContext"]
      Condition = local.org_perimeter_condition
    }
  }

  # Full statements with the template's optional parameters applied. Keys whose value is null
  # (Resource/NotResource) and an empty ArnNotLike block are dropped, matching the {% if %} blocks.
  statements = {
    for id, s in local.control_statements : id => {
      for k, v in {
        Sid         = s.Sid
        Effect      = "Deny"
        Principal   = "*"
        Action      = s.Action
        NotResource = id == "CT.S3.PV.6" && length(var.s3_sse_kms_exempted_resource_arns) > 0 ? var.s3_sse_kms_exempted_resource_arns : null
        Resource    = id == "CT.S3.PV.6" && length(var.s3_sse_kms_exempted_resource_arns) > 0 ? null : "*"
        Condition = merge(s.Condition, {
          for op, cond in { ArnNotLike = { "aws:PrincipalArn" = lookup(var.exempted_principal_arns, id, []) } } :
          op => cond if length(lookup(var.exempted_principal_arns, id, [])) > 0
        })
      } : k => v if v != null
    }
  }

  # An account/OU can have at most 5 RCPs attached (including RCPFullAWSAccess), so the nine
  # controls are packed into two policies rather than one policy per control.
  policy_groups = {
    "identity-perimeter" = {
      description = "Only principals in the organization, or AWS services, may access KMS, S3, Secrets Manager, SQS and STS resources."
      controls    = ["CT.KMS.PV.7", "CT.S3.PV.4", "CT.SECRETSMANAGER.PV.1", "CT.SQS.PV.1", "CT.STS.PV.1"]
    }
    "s3-data-protection" = {
      description = "S3 requests must use header auth, TLS 1.3, HTTPS, and SSE-KMS on upload."
      controls    = ["CT.S3.PV.2", "CT.S3.PV.3", "CT.S3.PV.5", "CT.S3.PV.6"]
    }
  }

  policies = {
    for name, group in local.policy_groups : name => {
      description = group.description
      controls    = [for id in group.controls : id if contains(var.enabled_controls, id)]
    }
    if length([for id in group.controls : id if contains(var.enabled_controls, id)]) > 0
  }

  policy_content = {
    for name, policy in local.policies : name => jsonencode({
      Version   = "2012-10-17"
      Statement = [for id in policy.controls : local.statements[id]]
    })
  }

  attachments = {
    for pair in setproduct(keys(local.policies), var.target_ids) : "${pair[0]}/${pair[1]}" => {
      policy    = pair[0]
      target_id = pair[1]
    }
  }

  rcp_enabled = contains([
    for pt in data.aws_organizations_organization.current.roots[0].policy_types : pt.type if pt.status == "ENABLED"
  ], "RESOURCE_CONTROL_POLICY")
}
