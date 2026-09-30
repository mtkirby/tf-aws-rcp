# tf-aws-rcp

Terraform for AWS Organizations resource control policies (RCPs) that implement these AWS Control Tower RCP controls:

| Control | What it denies | Policy |
|---|---|---|
| CT.KMS.PV.7 | KMS access by principals outside the org (AWS services allowed) | `identity-perimeter` |
| CT.S3.PV.4 | S3 access by principals outside the org (AWS services allowed) | `identity-perimeter` |
| CT.SECRETSMANAGER.PV.1 | Secrets Manager access by principals outside the org (AWS services allowed) | `identity-perimeter` |
| CT.SQS.PV.1 | SQS access by principals outside the org (AWS services allowed) | `identity-perimeter` |
| CT.STS.PV.1 | `sts:AssumeRole` / `sts:SetContext` by principals outside the org (AWS services allowed) | `identity-perimeter` |
| CT.S3.PV.2 | S3 requests not authenticated with the `Authorization` header (presigned URLs, POST uploads) | `s3-data-protection` |
| CT.S3.PV.3 | S3 requests using TLS older than 1.3 | `s3-data-protection` |
| CT.S3.PV.5 | S3 requests over plain HTTP | `s3-data-protection` |
| CT.S3.PV.6 | `s3:PutObject` without SSE-KMS | `s3-data-protection` |

The statements follow the [AWS Control Tower RCP templates](https://docs.aws.amazon.com/controltower/latest/controlreference/list-of-rcp-controls.html). Each Sid matches the AWS template (for example `CTKMSPV7`), and the `OrganizationIds`, `ExemptedPrincipalArns` and `ExemptedResourceArns` parameters work the same way.

These are self-managed RCPs created with `aws_organizations_policy`. They are not enabled through the Control Tower control API, so Control Tower does not show them as enabled controls. Don't also enable the same controls in Control Tower for the same OUs, because you would get duplicate policies.

## Why two policies instead of nine

A root, OU or account can have at most **5 RCPs** attached, and `RCPFullAWSAccess` takes one of those slots. So the nine controls are packed into two policies, with one statement per control. Each policy must stay under 5,120 characters. The defaults render to about 1.3 KB and 0.6 KB, and a precondition fails the plan if exemptions push a policy over the limit.

## Prerequisites

- Run from the **management account**, or from an account that is a delegated administrator for Organizations policy management.
- The `RESOURCE_CONTROL_POLICY` policy type must be enabled on the organization root. The plan fails with a clear error if it is not.
  ```sh
  aws organizations enable-policy-type --root-id r-xxxx --policy-type RESOURCE_CONTROL_POLICY
  ```
  If your organization is managed in Terraform, add it to `aws_organizations_organization.enabled_policy_types` there instead.
- Terraform >= 1.7 and AWS provider >= 5.78.

## Controls likely to break things

- CT.STS.PV.1 blocks vendors that assume roles in your accounts from their own AWS accounts (security scanners, monitoring tools, CI/CD services). Before applying, list those vendor roles in exempted_principal_arns or add the vendors' organization IDs to additional_trusted_organization_ids.
- CT.S3.PV.2 stops presigned URLs from working.
- CT.S3.PV.3 blocks clients that can't use TLS 1.3.
- CT.S3.PV.6 can block CloudTrail and AWS Config from writing to the log archive bucket unless your Control Tower landing zone is set up to encrypt with a KMS key.

## Usage

```sh
cp terraform.tfvars.example terraform.tfvars   # set target_ids etc.
terraform init
terraform plan
terraform apply
```

| Variable | Default | Purpose |
|---|---|---|
| `target_ids` | required | Root, OU or account IDs to attach both policies to |
| `enabled_controls` | all nine | Control IDs to include. Trim this list to stage a rollout |
| `additional_trusted_organization_ids` | `[]` | Other orgs trusted by the identity-perimeter controls |
| `exempted_principal_arns` | `{}` | Per-control `ExemptedPrincipalArns`, keyed by control ID |
| `s3_sse_kms_exempted_resource_arns` | `[]` | `ExemptedResourceArns` for CT.S3.PV.6 |
| `policy_name_prefix` | `ct-rcp` | Policy name prefix |
| `tags` | `{}` | Tags for the policies |

## Before attaching to production

RCPs are deny-only and apply to every resource in the target accounts. Test on a sandbox OU first and check CloudTrail for `AccessDenied` errors. Known ways these controls can break things:

- **CT.STS.PV.1**: third-party integrations that assume roles in your accounts from *their* AWS accounts will be denied. Examples include security/CSPM tools, observability vendors and CI/CD SaaS. Add their role ARNs to `exempted_principal_arns["CT.STS.PV.1"]` or add their org ID to `additional_trusted_organization_ids`.
- **CT.S3.PV.4 / KMS.PV.7 / SQS.PV.1 / SECRETSMANAGER.PV.1**: any cross-org sharing breaks. This includes buckets or keys shared with partners and SQS queues that external accounts send to.
- **CT.S3.PV.2**: presigned URLs and browser POST uploads stop working.
- **CT.S3.PV.3**: clients that can't negotiate TLS 1.3 (older SDKs, JVMs and appliances) are denied.
- **CT.S3.PV.6**: uploads fail unless the request sets a KMS key ID or the bucket's default encryption is SSE-KMS. This includes CloudTrail and AWS Config delivery to the Control Tower log archive bucket if the landing zone isn't configured with a KMS key.
- The identity-perimeter controls do not prevent cross-service confused deputy access. Pair them with `aws:SourceOrgID` / `aws:SourceAccount` service-principal controls if you need that.
- RCPs never apply to resources in the management account.

## Tests

```sh
terraform test
```

The tests use a mocked AWS provider, so they need no credentials. They check the rendered JSON against the AWS templates, the optional parameter blocks, a partial control set, input validation, and the RCP-enabled precondition.
