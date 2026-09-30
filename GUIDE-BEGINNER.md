# Beginner Guide: AWS RCPs and This Terraform Project

This guide assumes you are new to AWS Organizations Resource Control Policies (RCPs) and Terraform. It explains what this repository manages, what to check before applying it, and how to review the result.

## What this project does

This project creates and attaches AWS Organizations RCPs. RCPs set a maximum permissions boundary for supported resources in member accounts. They do not grant access. Other permissions, such as IAM policies and resource policies, still determine whether a request is allowed. An explicit deny from an RCP prevents access even when another policy allows it.

The repository implements nine AWS Control Tower RCP controls as **self-managed policies**. Terraform creates two RCPs, each containing several statements:

- `identity-perimeter` limits cross-organization access to KMS, S3, Secrets Manager, SQS, and selected STS operations. AWS service principals are allowed by these statements.
- `s3-data-protection` denies selected S3 requests that do not meet authentication, TLS, HTTPS, and SSE-KMS requirements.

The control IDs and short descriptions are in the project [README](README.md). The rendered policies follow AWS Control Tower templates, but they are not registered as Control Tower controls. Do not enable duplicate Control Tower controls for the same targets.

## Important terms

- **Organization:** AWS accounts managed together through AWS Organizations.
- **Root:** The top-level container for accounts and organizational units (OUs).
- **OU:** A folder-like container for accounts and other OUs.
- **Target:** The root, OU, or account to which this project attaches its RCPs.
- **Principal:** The identity making an AWS request, such as an IAM role or an AWS service.
- **Terraform plan:** A preview of the AWS changes Terraform intends to make.
- **Apply:** The operation that makes the planned changes in AWS.

RCPs do not apply to resources in the AWS Organizations management account. They also do not replace service-specific security settings or prevent every AWS service confused-deputy scenario.

## Before you start

1. Confirm the target accounts and OUs with the security and application owners. Start with a sandbox OU rather than the organization root.
2. Run Terraform from the AWS Organizations management account or an authorized delegated administrator account.
3. Confirm that `RESOURCE_CONTROL_POLICY` is enabled on the organization root. This project checks for it when planning. If it is disabled, an authorized administrator must enable it first.
4. Install Terraform 1.7 or newer, AWS CLI, and Python 3.10 or newer. The AWS provider requirement is `>= 5.78.0, < 7.0.0`.
5. Configure AWS credentials for the organization. Terraform needs permission to read Organizations and create, update, attach, and detach RCPs. The capacity preflight also needs `organizations:ListPoliciesForTarget`.
6. Decide whether external partners, vendors, or role integrations need exemptions before applying the identity-perimeter controls.

## Configure targets

Copy the example variables file and replace the example target with a real organization root, OU, or 12-digit account ID:

```sh
cp terraform.tfvars.example terraform.tfvars
```

For example, the `terraform.tfvars` file could contain:

```hcl
target_ids = ["ou-ab12-cdef3456"]
```

At least one target is required. IDs must be valid root, OU, or account ID formats. Use unique targets. The default `enabled_controls` setting includes all nine controls; you can temporarily select fewer controls to stage a rollout.

Optional settings include:

- `additional_trusted_organization_ids`: organization IDs whose principals should be trusted by the identity-perimeter controls.
- `exempted_principal_arns`: role or principal ARNs to exempt from specific controls. Exemptions are keyed by control ID.
- `s3_sse_kms_exempted_resource_arns`: S3 resource ARNs exempted only from the SSE-KMS upload control.
- `policy_name_prefix` and `tags`: naming and tagging for the created policies.

Do not add broad exemptions just to make a plan succeed. Confirm the exact workload and scope with its owner.

## Validate, plan, and apply

Run commands from the repository root. The order below checks configuration and tests first, then inspects capacity and applies the exact saved plan:

```sh
terraform init
terraform fmt -check -recursive
terraform validate
terraform test
terraform plan -out=tfplan
python3 scripts/check_rcp_attachment_capacity.py tfplan
terraform apply tfplan
```

Terraform tests use a mocked AWS provider and do not need AWS credentials. The Python tests can also be run locally:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

The capacity script checks the number of RCPs currently attached directly to each changed target and adjusts that count for planned attachment changes. AWS allows at most five RCPs per target, including `RCPFullAWSAccess`. The script uses AWS CLI credentials; pass `--profile PROFILE` if needed. It cannot reserve capacity, so another administrator could attach an RCP between the check and apply. Coordinate or serialize organization policy changes.

Review the Terraform plan before applying. Confirm the target IDs, policy names, policy contents, and attachment changes. If the plan is unexpected, stop and investigate rather than applying it.

## After applying

Terraform prints outputs including policy IDs, the controls in each policy, rendered policy JSON, and attachment addresses. Save policy IDs with your change record. Run `terraform plan` again after applying; an empty plan indicates Terraform sees the deployed resources as matching the configuration.

For a production rollout:

- Check CloudTrail for new `AccessDenied` errors and ask application owners to validate critical workflows.
- Watch vendor integrations that assume roles from other organizations.
- Check whether any applications use S3 presigned URLs, browser POST uploads, TLS older than 1.3, or plain HTTP.
- Confirm buckets use SSE-KMS by default or that upload clients send the required KMS key ID.
- Review the [CloudTrail query guide](CLOUDTRAIL-REVIEW.md) for candidate activity and its logging limitations.

RCPs can block access immediately when attached. Test in a sandbox, roll out gradually, and have an approved rollback procedure.

## Where to look next

- [Project README](README.md): controls, variables, commands, and known operational impacts.
- [CloudTrail review guide](CLOUDTRAIL-REVIEW.md): AWS CLI/Event history and Athena queries.
- [Expert guide](GUIDE-EXPERT.md): policy semantics, Terraform implementation, and operational details.
- [AWS Control Tower RCP control catalog](https://docs.aws.amazon.com/controltower/latest/controlreference/list-of-rcp-controls.html)
