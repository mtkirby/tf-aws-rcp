output "policy_ids" {
  description = "RCP IDs keyed by policy group."
  value       = { for name, policy in aws_organizations_policy.this : name => policy.id }
}

output "policy_controls" {
  description = "Control Tower control IDs implemented by each RCP."
  value       = { for name, policy in local.policies : name => policy.controls }
}

output "policy_content" {
  description = "Rendered RCP JSON keyed by policy group."
  value       = { for name, policy in aws_organizations_policy.this : name => policy.content }
}

output "attachments" {
  description = "Policy/target attachments created."
  value       = keys(aws_organizations_policy_attachment.this)
}
