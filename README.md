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

A root, OU or account can have at most **5 RCPs** attached, and `RCPFullAWSAccess` takes one of those slots. So the nine controls are packed into two policies, with one statement per control. Each policy must stay under 5,120 characters. The defaults render to about 1.3 KB and 0.6 KB, and a precondition fails the plan if exemptions push a policy over the limit. If you also enable the optional [RCPFullOrgRestrict](#optional-rcpfullorgrestrict) policy, each target carries four RCPs, which still leaves one slot free.

The optional attachment-capacity preflight checks the saved plan against the RCPs currently attached directly to each changed target. It requires Python 3.10+ and AWS CLI credentials with permission to call `organizations:ListPoliciesForTarget`. It cannot prevent a concurrent process from attaching another RCP after the check, so serialize organization-policy applies.

## What each control does

**Identity perimeter.** These five controls deny requests from principals outside your organization, unless the principal is an AWS service. They stop other AWS accounts from reaching your resources, even when a resource policy grants them access by mistake. Add partner organizations with `additional_trusted_organization_ids`.

- **CT.KMS.PV.7**: blocks all KMS operations on your keys by identities outside the organization, so no external account can encrypt, decrypt or manage them.
  *Why:* KMS keys protect your other data, so a key policy that trusts the wrong account exposes everything encrypted with that key. This control stops that.
- **CT.S3.PV.4**: blocks all S3 operations on your buckets and objects by identities outside the organization.
  *Why:* bucket policies that grant access to other accounts are a common cause of data exposure. This makes an org-wide guardrail that bucket owners can't override.
- **CT.SECRETSMANAGER.PV.1**: blocks all Secrets Manager operations on your secrets by identities outside the organization.
  *Why:* secrets hold credentials, so one leaked secret can open access to databases and other systems. This keeps secrets inside the organization even if a secret's resource policy is too broad.
- **CT.SQS.PV.1**: blocks all SQS operations on your queues by identities outside the organization, including sending and receiving messages.
  *Why:* an outside account with queue access could read or delete your messages, or inject fake ones into the workflows that consume the queue.
- **CT.STS.PV.1**: blocks identities outside the organization from assuming your IAM roles (`sts:AssumeRole`) or setting trusted context (`sts:SetContext`). SAML and web identity federation are not affected.
  *Why:* a role trust policy that names the wrong account, or trusts any account, gives an outsider a way into your environment. This closes that path across every account at once.

**S3 data protection.** These four controls set request requirements for every S3 bucket in the target accounts.

- **CT.S3.PV.2**: requires requests to be signed with an `Authorization` header. This rules out presigned URLs and browser POST uploads.
  *Why:* anyone who has a presigned URL can use it until it expires. A URL that leaks through logs, chat or email therefore exposes the object with no further identity check.
- **CT.S3.PV.3**: requires TLS 1.3 or later on every request.
  *Why:* TLS 1.3 drops the older cipher suites and handshake options found in earlier versions, and some compliance standards require it.
- **CT.S3.PV.5**: requires HTTPS on every request (`aws:SecureTransport`).
  *Why:* over plain HTTP, object data travels unencrypted and can be read or altered in transit. Frameworks such as PCI DSS and HIPAA expect encryption in transit.
- **CT.S3.PV.6**: requires object uploads to use SSE-KMS encryption. An upload must specify a KMS key or go to a bucket whose default encryption is SSE-KMS.
  *Why:* SSE-KMS adds a second permission check, because reading an object also needs `kms:Decrypt` on the key. CloudTrail logs every use of the key, and disabling the key cuts off access to the data.

## Optional: RCPFullOrgRestrict

`RCPFullOrgRestrict` is a third policy that is **off by default**. It is not a Control Tower control. It applies the same identity perimeter as the controls above to many more services: any principal outside your organization (and outside `additional_trusted_organization_ids`) is denied unless it is an AWS service or listed in its exemptions.

```hcl
enable_rcp_full_org_restrict = true

exempted_principal_arns = {
  "RCPFullOrgRestrict" = ["arn:aws:iam::*:role/BreakGlass"]
}
```

It attaches to the same `target_ids` as the other policies. To run it on its own, also set `enabled_controls = []`.

**Why it lists services instead of using `"Action": "*"`.** A customer-managed RCP can't use `"*"` as its whole `Action`, and RCPs don't support `NotAction` ([RCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html)). So the policy denies `<service>:*` for each prefix in `full_org_restrict_services`. The default is the AWS [list of services that support RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services) as of 2026-10-01, with these exceptions:

- **STS** is limited to `sts:AssumeRole` and `sts:SetContext`, the same actions as CT.STS.PV.1. `sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity`, `sts:TagSession` and `sts:SetSourceIdentity` don't use AWS credentials, so they carry no organization ID and would be denied. Leaving them out keeps SAML federation (including IAM Identity Center), OIDC roles such as GitHub Actions, and EKS service-account roles working. The variable rejects `"sts"` so `sts:*` can't be added by mistake.
- **`cognito-identity`, `cognito-idp`, `rolesanywhere` and `signin`** are left out as a precaution. Their callers often have no AWS organization identity: app users signing in to Cognito, IAM Roles Anywhere sessions that authenticate with an X.509 certificate, and console or CLI sign-in. I haven't confirmed which of their calls RCPs evaluate, so test them on a sandbox account before adding them.
- **`ecr-public`** is left out because public repositories are meant to be pulled by anyone.

Other things to know:

- **Anonymous access.** Unsigned requests carry no organization ID, so anonymous access to resources in the listed services is denied. To allow it for a specific resource, such as a public S3 bucket, use the [bypass tag](#optional-bypass-tag-bypassrcp).
- **Exemptions don't carry over.** A deny in any attached RCP wins. A principal exempted from CT.STS.PV.1 is still denied by RCPFullOrgRestrict unless it's also listed under `exempted_principal_arns["RCPFullOrgRestrict"]`. Trusted organizations are different: `additional_trusted_organization_ids` is shared, so a trusted organization is allowed by both policies.
- **New services aren't covered automatically.** When AWS adds RCP support to a service, add its prefix to `full_org_restrict_services`.

With this policy enabled, the identity-perimeter policy adds no further restriction, because its statements are a subset of this one. It's kept so you can turn this policy off again without losing the perimeter for the five core services.

## Optional: bypass tag (BypassRCP)

Set `enable_rcp_bypass_tag = true` to let individual resources opt out of every control in this repo. Each RCP statement gets one more condition, `"StringNotEquals": { "aws:ResourceTag/BypassRCP": "True" }`, so a resource tagged `BypassRCP = True` is skipped by all of them: the identity perimeter, the S3 request rules and RCPFullOrgRestrict.

```hcl
enable_rcp_bypass_tag = true
```

**Where it works.** The bypass only works where the service puts the resource's tags into the request as `aws:ResourceTag`. Checked against the [AWS service reference data](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) on 2026-10-01:

| Service | What to tag | Covered actions |
|---|---|---|
| KMS | The key | All key actions |
| Secrets Manager | The secret | All secret actions |
| SQS | The queue | All queue actions |
| STS | The role | `AssumeRole` and `SetContext` |
| S3 | The bucket, with ABAC turned on | Bucket and object actions, except Object Lambda and multi-Region access points |
| Other `full_org_restrict_services` | Varies | Check the service before relying on it |

Where the tag isn't exposed, the condition key is missing, `StringNotEquals` still matches, and the deny applies. The bypass fails closed.

**It bypasses everything.** A principal exemption opens a resource to one caller. A tagged resource is open to any caller its own resource policy allows, including anonymous callers and principals in other organizations, and it also loses the TLS 1.3, HTTPS, header-auth and SSE-KMS requirements. Keep it for resources that need it, such as a public S3 bucket or a queue shared with a partner. If you know the outside principal's ARN, `exempted_principal_arns` is narrower.

**Example: a public S3 bucket.** Run in the bucket's account:

```sh
aws s3api put-bucket-abac --bucket my-public-bucket --abac-status Status=Enabled

aws s3control tag-resource \
  --account-id 111122223333 \
  --resource-arn arn:aws:s3:::my-public-bucket \
  --tags Key=BypassRCP,Value=True
```

S3 only evaluates bucket tags once ABAC is on ([S3 bucket tagging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging.html)). These are recent APIs (S3 ABAC launched in November 2025), so use a current AWS CLI. Also:

- **The RCPs don't grant access.** The bucket policy must still allow public reads, and S3 Block Public Access must not block them.
- **Website endpoints work.** CT.S3.PV.5 is bypassed too, so the HTTP-only S3 website endpoint is reachable.
- **ABAC blocks `PutBucketTagging`.** Once ABAC is on, the bucket's tags must be changed with `TagResource`. Check that whatever manages the bucket's tags (Terraform, CloudFormation, scripts) supports that first.
- **The value is case-sensitive.** Only `True` bypasses; `true` doesn't.

**Who can set the tag.** Anyone with permission to tag a resource can bypass the RCPs for it (for an S3 bucket, they also need permission to turn on ABAC). Nothing in this repo limits who that is. To keep an eye on it, look in CloudTrail for tagging calls (`TagResource`, `TagQueue`, `TagRole`, `CreateBucket` and similar) whose request parameters include `BypassRCP`.

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
terraform fmt -check -recursive
terraform validate
terraform test
terraform plan -out=tfplan
python3 scripts/check_rcp_attachment_capacity.py tfplan
terraform apply tfplan
```

Pass `--profile PROFILE` to use a named AWS CLI profile. The script exits nonzero if any target would exceed five directly attached RCPs or if it cannot reliably determine the planned capacity.

| Variable | Default | Purpose |
|---|---|---|
| `target_ids` | required | Root, OU or account IDs to attach the policies to |
| `enabled_controls` | all nine | Control IDs to include. Trim this list to stage a rollout |
| `additional_trusted_organization_ids` | `[]` | Other orgs trusted by the identity-perimeter controls |
| `enable_rcp_full_org_restrict` | `false` | Also create and attach the optional `RCPFullOrgRestrict` policy |
| `full_org_restrict_services` | RCP-supported services as of 2026-10-01, with exceptions | Service prefixes `RCPFullOrgRestrict` covers (see above) |
| `enable_rcp_bypass_tag` | `false` | Let resources tagged `BypassRCP = True` skip every control |
| `exempted_principal_arns` | `{}` | Per-control `ExemptedPrincipalArns`, keyed by control ID or `RCPFullOrgRestrict` |
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

The attachment-capacity preflight's unit tests use only the Python standard library:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```
