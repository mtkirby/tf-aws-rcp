data "aws_organizations_organization" "current" {}

resource "aws_organizations_policy" "this" {
  for_each = local.policies

  name        = "${var.policy_name_prefix}-${each.key}"
  description = "${each.value.description} Controls: ${join(", ", each.value.controls)}"
  type        = "RESOURCE_CONTROL_POLICY"
  tags        = var.tags

  content = local.policy_content[each.key]

  lifecycle {
    precondition {
      condition     = local.rcp_enabled
      error_message = "The RESOURCE_CONTROL_POLICY policy type is not enabled on the organization root. Enable it first (aws_organizations_organization.enabled_policy_types or `aws organizations enable-policy-type`)."
    }

    precondition {
      condition     = length(local.policy_content[each.key]) <= 5120
      error_message = "RCP ${each.key} exceeds the 5,120 character limit. Reduce the exempted ARNs or split the policy."
    }
  }
}

resource "aws_organizations_policy_attachment" "this" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.this[each.value.policy].id
  target_id = each.value.target_id
}
