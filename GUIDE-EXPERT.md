# Expert Guide: RCP and Terraform Implementation

This guide is for engineers already familiar with AWS Organizations, IAM policy evaluation, Terraform, and AWS Control Tower RCP templates. It documents the implementation contracts and operational boundaries of this root module.

## Scope and deployment model

The module creates self-managed `RESOURCE_CONTROL_POLICY` policies with `aws_organizations_policy` and attaches them with `aws_organizations_policy_attachment`. It does not call the Control Tower control API, so the controls are not represented as enabled Control Tower controls. Do not enable matching Control Tower controls on the same targets; duplicate RCPs consume additional attachment slots and can complicate lifecycle ownership.

RCPs are resource-side organization guardrails: they limit the maximum permissions available for supported resources but do not grant access. Effective access remains subject to the other applicable authorization mechanisms. RCPs do not apply to resources in the Organizations management account. Service-principal exceptions in these templates do not solve cross-service confused-deputy risks; add appropriate `aws:SourceOrgID` or `aws:SourceAccount` controls where required.

The module has two policy groups:

| Group | Control statements |
|---|---|
| `identity-perimeter` | CT.KMS.PV.7, CT.S3.PV.4, CT.SECRETSMANAGER.PV.1, CT.SQS.PV.1, CT.STS.PV.1 |
| `s3-data-protection` | CT.S3.PV.2, CT.S3.PV.3, CT.S3.PV.5, CT.S3.PV.6 |

The nine statements are packed into two policies because an account, OU, or root can have at most five attached RCPs, including `RCPFullAWSAccess`. The two policies are attached to every ID in `target_ids` for which at least one control in the group is enabled.

## Policy statement semantics

All statements are explicit `Deny` statements with `Principal = "*"`. They follow AWS Control Tower RCP templates, preserve template Sids, and use the template action and condition keys:

| Control | Action and deny condition |
|---|---|
| CT.KMS.PV.7 | `kms:*` when the principal is neither an AWS service nor in a listed organization |
| CT.S3.PV.4 | `s3:*` with the same organization-perimeter condition |
| CT.SECRETSMANAGER.PV.1 | `secretsmanager:*` with the same organization-perimeter condition |
| CT.SQS.PV.1 | `sqs:*` with the same organization-perimeter condition |
| CT.STS.PV.1 | Only `sts:AssumeRole` and `sts:SetContext`, with the same organization-perimeter condition |
| CT.S3.PV.2 | `s3:*` when `s3:authType` is not `REST-HEADER` |
| CT.S3.PV.3 | `s3:*` when `s3:TlsVersion` is numerically below `1.3` |
| CT.S3.PV.5 | `s3:*` when `aws:SecureTransport` is `false` |
| CT.S3.PV.6 | `s3:PutObject` when the SSE-KMS key ID request context key is null |

The shared perimeter condition is:

```hcl
BoolIfExists = {
  "aws:PrincipalIsAWSService" = "false"
}
StringNotEqualsIfExists = {
  "aws:PrincipalOrgID" = local.organization_ids
}
```

The condition operators are deliberately template-compatible. The AWS service principal condition prevents these perimeter denies from matching a direct AWS service principal. `organization_ids` contains the current organization ID plus `additional_trusted_organization_ids`. `StringNotEqualsIfExists` is evaluated as a deny condition; requests without the key can match the deny unless another condition exempts them. Do not replace these operators with superficially similar operators without re-evaluating missing-key and service-principal behavior.

`exempted_principal_arns` is keyed by control ID. Nonempty entries add an `ArnNotLike` condition to only that statement. Wildcards are therefore scoped to the named control, not globally. For CT.S3.PV.6, nonempty `s3_sse_kms_exempted_resource_arns` changes the statement from `Resource = "*"` to `NotResource = [...]`; both fields are never emitted together. This is the template's resource exception, not a principal exemption.

The SSE-KMS condition is not equivalent to checking the effective encryption setting in the bucket after the request. The AWS control template uses the request context key, and AWS documents that bucket default SSE-KMS can satisfy the requirement when the request omits the header. Validate bucket encryption and workload behavior before rollout.

## Terraform construction

The resource and rendering path is split across these files:

- [variables.tf](variables.tf) defines target IDs, enabled controls, trusted organization IDs, principal exemptions, resource exemptions, policy prefix, tags, and validation.
- [locals.tf](locals.tf) defines the template statements, optional-block rendering, group membership, compact policy set, policy JSON, attachment keys, and RCP-enabled status.
- [main.tf](main.tf) reads the organization, creates policy resources, enforces plan preconditions, and creates attachments.
- [outputs.tf](outputs.tf) exposes policy IDs, control IDs per policy, rendered policy content, and attachment addresses.
- [rcp.tftest.hcl](tests/rcp.tftest.hcl) verifies rendered statements and module behavior with a mocked AWS provider.

`local.statements` omits null values and only adds `ArnNotLike` when the control has a nonempty exemption list. `local.policies` filters disabled controls and omits groups with no enabled controls; this avoids creating empty RCPs. `local.policy_content` JSON-encodes the selected statements. Attachment `for_each` keys are `<policy-group>/<target-id>`.

`target_ids` must contain at least one syntactically valid root, OU, or account ID. The current validation does not reject duplicate IDs; provide a unique list because generated attachment keys are expected to be unique. `enabled_controls` and exemption-map keys are restricted to the nine supported control IDs. Organization IDs are syntax-checked, and resource exemption ARNs are checked for the `arn:` prefix; these validations do not prove that referenced AWS entities exist or that exemptions are appropriately scoped.

`aws_region` selects the AWS API endpoint; Organizations is global. The AWS provider constraint is `>= 5.78.0, < 7.0.0`, and Terraform must be `>= 1.7.0`. The backend block is intentionally commented out. Configure remote state, encryption, access controls, and locking for team/production use before applying.

## Preconditions and limits

Each policy has two lifecycle preconditions:

1. `RESOURCE_CONTROL_POLICY` must be enabled on the organization root. The organization data source determines this status during planning.
2. The rendered JSON string must be no more than 5,120 characters, the Organizations RCP policy size limit used by this module.

The module does **not** preflight all existing RCPs attached to each target inside Terraform. The separate Python script [`scripts/check_rcp_attachment_capacity.py`](scripts/check_rcp_attachment_capacity.py) reads a saved Terraform plan, computes net create/delete deltas for `aws_organizations_policy_attachment` resources, and calls `aws organizations list-policies-for-target --filter RESOURCE_CONTROL_POLICY` for targets with net changes. It fails closed if it cannot determine target IDs or AWS results. Use it on the same saved plan that will be applied:

```sh
terraform plan -out=tfplan
python3 scripts/check_rcp_attachment_capacity.py tfplan --profile organization-admin
terraform apply tfplan
```

The preflight checks direct attachments and does not reserve capacity. Concurrent organization-policy changes can race the check. Serialize applies or otherwise coordinate policy changes. The profile passed to the script is for its AWS CLI calls; configure Terraform's AWS provider credentials separately (for example with `AWS_PROFILE`).

## Tests and verification

The Terraform test file uses `mock_provider "aws"`; it does not need live AWS credentials. It checks default group membership and policy JSON, optional principal and resource blocks, partial control selection, invalid controls, invalid and empty targets, and the policy-type precondition.

Run the repository's documented checks:

```sh
terraform init
terraform fmt -check -recursive
terraform validate
terraform test
python3 -m unittest discover -s tests -p 'test_*.py'
```

The Python unit tests cover saved-plan attachment delta accounting. These checks do not validate authorization against live AWS resources or replace a sandbox deployment. This repository currently has no CI workflow, so these commands are not automatically gated on pull requests unless a consuming pipeline runs them.

## Operational verification

Before rollout, use the [CloudTrail review guide](CLOUDTRAIL-REVIEW.md) to identify candidate requests. Event history only covers management events for a single account and Region over 90 days. S3 object and SQS message activity requires data-event logging that was enabled during the review window. Missing logs are not evidence of no use, and CloudTrail generally does not record all RCP condition context.

Roll out to a sandbox OU, check service-specific and application logs for authorization failures, and inspect CloudTrail `AccessDenied` events. Validate partner access, external role assumptions, S3 presigned or POST workflows, TLS versions, HTTP clients, and SSE-KMS defaults. Exempt only verified principals/resources and keep the exemption scoped to the relevant control.

## AWS references

- [AWS Control Tower RCP controls and templates](https://docs.aws.amazon.com/controltower/latest/controlreference/list-of-rcp-controls.html)
- [AWS Organizations RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Terraform AWS Organizations policy resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/organizations_policy)
