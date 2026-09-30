# RCP Lab: Test Allowed and Denied Cross-Account Requests

This guide builds a disposable two-account lab to demonstrate how the RCPs in this repository change authorization. The `victim` account owns test resources and receives the RCPs. The `attacker` account is a separate AWS account outside the victim's organization; an explicitly authorized role in that account makes requests to the victim resources.

Use only accounts and resources you own or are explicitly authorized to test. Do not run this procedure in production or against a third party. The setup intentionally grants the attacker role access to lab resources before the RCPs are attached. It does not create internet-facing compute or expose data publicly.

## Lab topology and prerequisites

Use:

- A disposable AWS Organization with RCPs enabled.
- One **victim member account** in that organization. Do not use the Organizations management account as the victim; RCPs do not apply to management-account resources.
- One **attacker account outside the victim organization**. If both accounts are in the same AWS Organization, the identity-perimeter controls will not treat the attacker as external.
- An attacker IAM role that you control, with caller-side permissions for the lab actions below. Use short-lived credentials, such as IAM Identity Center, not long-lived access keys.
- AWS CLI v2, Terraform >= 1.7, Python >= 3.10, `jq`, `curl`, and access to the repository.
- A CloudTrail S3 data-event trail covering the test S3 bucket and SQS queue if you want data-plane events in CloudTrail. Event history alone is insufficient. See [CloudTrail review](CLOUDTRAIL-REVIEW.md).

Use a fresh Terraform state dedicated to this lab. The Terraform provider must authenticate to the victim organization's management account or an authorized delegated administrator. The `victim` target itself must be a member account ID.

Set the values below in a Bash-compatible shell. Replace the example IDs and role ARN. Use a bucket name that is globally unique.

```sh
export ORG_ADMIN_PROFILE=rcp-org-admin
export VICTIM_PROFILE=rcp-victim-admin
export ATTACKER_PROFILE=rcp-attacker
# The create-bucket command below uses the us-east-1 form. If using another
# Region, add --create-bucket-configuration LocationConstraint="$REGION".
export REGION=us-east-1
export VICTIM_ACCOUNT_ID=111122223333
export ATTACKER_ACCOUNT_ID=444455556666
export ATTACKER_ROLE_ARN=arn:aws:iam::444455556666:role/RcpLabAttacker
export BUCKET="rcp-lab-${VICTIM_ACCOUNT_ID}-$(date +%s)"
export SECRET_NAME=rcp-lab-secret
export QUEUE_NAME=rcp-lab-queue
export ROLE_NAME=RcpLabVictimRole
```

Verify the identities before changing anything:

```sh
aws sts get-caller-identity --profile "$ORG_ADMIN_PROFILE"
aws sts get-caller-identity --profile "$VICTIM_PROFILE"
aws sts get-caller-identity --profile "$ATTACKER_PROFILE"
```

The first and second identities should be in the victim organization; the attacker identity must be in the separate account. Confirm the victim account ID is not the management account ID.

If RCPs are not enabled in the disposable organization, an authorized Organizations administrator must enable the policy type on the root before applying this project:

```sh
ROOT_ID=$(aws organizations list-roots \
  --profile "$ORG_ADMIN_PROFILE" \
  --query 'Roots[0].Id' --output text)
aws organizations enable-policy-type \
  --root-id "$ROOT_ID" \
  --policy-type RESOURCE_CONTROL_POLICY \
  --profile "$ORG_ADMIN_PROFILE"
```

The attacker role needs caller-side permissions for `kms:Encrypt`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, the SQS message actions used below, `s3:GetObject`, `s3:PutObject`, and `sts:AssumeRole`. Cross-account access requires both those identity-side permissions and the victim resource policy. The test intentionally configures the latter.

## 1. Create vulnerable victim resources

Run these commands with the victim profile. The resource policies allow only the named attacker role and only the lab resources/actions. The resource policies are deliberately permissive for test purposes; the later RCP is what should override those allows.

### S3 bucket and object

The bucket is intentionally not configured with default SSE-KMS. S3 may still apply its baseline SSE-S3 encryption; CT.S3.PV.6 specifically requires SSE-KMS.

```sh
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE"

printf 'RCP lab object\n' > /tmp/rcp-lab-object.txt
aws s3api put-object \
  --bucket "$BUCKET" \
  --key probe.txt \
  --body /tmp/rcp-lab-object.txt \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE"
```

Add a bucket policy allowing the attacker role to read and write only this bucket/object path:

```sh
jq -n \
  --arg role "$ATTACKER_ROLE_ARN" \
  --arg bucket "$BUCKET" \
  '{Version:"2012-10-17",Statement:[
    {Sid:"RcpLabAttackerList",Effect:"Allow",Principal:{AWS:$role},Action:["s3:ListBucket"],Resource:("arn:aws:s3:::"+$bucket)},
    {Sid:"RcpLabAttackerObjects",Effect:"Allow",Principal:{AWS:$role},Action:["s3:GetObject","s3:PutObject"],Resource:("arn:aws:s3:::"+$bucket+"/*")}
  ]}' > /tmp/rcp-lab-bucket-policy.json

aws s3api put-bucket-policy \
  --bucket "$BUCKET" \
  --policy file:///tmp/rcp-lab-bucket-policy.json \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE"
```

### KMS key

Create a key policy that keeps victim-account administration and permits the attacker role to use the key. Restrict this key to the lab; do not reuse a production key.

```sh
VICTIM_ROOT_ARN="arn:aws:iam::${VICTIM_ACCOUNT_ID}:root"
jq -n \
  --arg root "$VICTIM_ROOT_ARN" \
  --arg role "$ATTACKER_ROLE_ARN" \
  '{Version:"2012-10-17",Statement:[
    {Sid:"EnableVictimAccountAdministration",Effect:"Allow",Principal:{AWS:$root},Action:"kms:*",Resource:"*"},
    {Sid:"AllowLabAttackerUse",Effect:"Allow",Principal:{AWS:$role},Action:["kms:Encrypt","kms:Decrypt","kms:DescribeKey","kms:GenerateDataKey"],Resource:"*"}
  ]}' > /tmp/rcp-lab-kms-policy.json

KMS_KEY_ID=$(aws kms create-key \
  --description "Disposable RCP lab key" \
  --policy file:///tmp/rcp-lab-kms-policy.json \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE" \
  --query KeyMetadata.KeyId \
  --output text)
KMS_KEY_ARN=$(aws kms describe-key \
  --key-id "$KMS_KEY_ID" \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE" \
  --query KeyMetadata.Arn \
  --output text)
printf 'KMS_KEY_ARN=%s\n' "$KMS_KEY_ARN"
```

Keep the key ARN in your shell for the SSE-KMS upload test below.

### Secrets Manager secret

Create a disposable secret and attach a resource policy granting the attacker role read access:

```sh
SECRET_ARN=$(aws secretsmanager create-secret \
  --name "$SECRET_NAME" \
  --secret-string 'disposable-lab-value' \
  --kms-key-id "$KMS_KEY_ARN" \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE" \
  --query ARN \
  --output text)

jq -n --arg role "$ATTACKER_ROLE_ARN" --arg secret "$SECRET_ARN" \
  '{Version:"2012-10-17",Statement:[
    {Sid:"RcpLabAttackerRead",Effect:"Allow",Principal:{AWS:$role},Action:"secretsmanager:GetSecretValue",Resource:$secret}
  ]}' > /tmp/rcp-lab-secret-policy.json

aws secretsmanager put-resource-policy \
  --secret-id "$SECRET_ARN" \
  --resource-policy file:///tmp/rcp-lab-secret-policy.json \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE"
```

### SQS queue

Create a disposable queue and allow the attacker role to send, receive, and delete messages:

```sh
QUEUE_URL=$(aws sqs create-queue \
  --queue-name "$QUEUE_NAME" \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE" \
  --query QueueUrl \
  --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes \
  --queue-url "$QUEUE_URL" \
  --attribute-names QueueArn \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE" \
  --query Attributes.QueueArn \
  --output text)

jq -n \
  --arg queue "$QUEUE_ARN" \
  --arg role "$ATTACKER_ROLE_ARN" \
  '{Version:"2012-10-17",Statement:[
    {Sid:"RcpLabAttackerMessages",Effect:"Allow",Principal:{AWS:$role},Action:["sqs:GetQueueAttributes","sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage"],Resource:$queue}
  ]}' > /tmp/rcp-lab-sqs-policy.json

aws sqs set-queue-attributes \
  --queue-url "$QUEUE_URL" \
  --attributes file:///tmp/rcp-lab-sqs-policy.json \
  --region "$REGION" \
  --profile "$VICTIM_PROFILE"
```

### STS role in the victim account

Create a role whose trust policy allows the attacker role to assume it. The role's permissions are intentionally empty; the lab only tests whether the assume-role request itself is allowed.

```sh
jq -n --arg attacker "$ATTACKER_ROLE_ARN" \
  '{Version:"2012-10-17",Statement:[
    {Sid:"RcpLabAttackerAssumeRole",Effect:"Allow",Principal:{AWS:$attacker},Action:"sts:AssumeRole"}
  ]}' > /tmp/rcp-lab-trust-policy.json

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/rcp-lab-trust-policy.json \
  --description "Disposable RCP lab role" \
  --profile "$VICTIM_PROFILE"
VICTIM_ROLE_ARN="arn:aws:iam::${VICTIM_ACCOUNT_ID}:role/${ROLE_NAME}"
```

Wait for AWS resource propagation before testing. A policy propagation delay can look like a failed baseline test.

## 2. Prove the vulnerable baseline from the attacker account

Run each request using the attacker profile. Before attaching RCPs, these should succeed. A failure here means the baseline resource policy, caller identity policy, credentials, Region, or resource ARN needs to be fixed before RCP testing.

```sh
# CT.KMS.PV.7 candidate
printf 'lab plaintext' > /tmp/rcp-lab-plaintext.txt
aws kms encrypt \
  --key-id "$KMS_KEY_ARN" \
  --plaintext fileb:///tmp/rcp-lab-plaintext.txt \
  --region "$REGION" \
  --profile "$ATTACKER_PROFILE" \
  --query KeyId --output text

# CT.SECRETSMANAGER.PV.1 candidate
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ARN" \
  --region "$REGION" \
  --profile "$ATTACKER_PROFILE" \
  --query Name --output text

# CT.SQS.PV.1 candidate
aws sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body 'disposable RCP lab message' \
  --region "$REGION" \
  --profile "$ATTACKER_PROFILE" \
  --query MessageId --output text

# CT.STS.PV.1 candidate; only print the role ARN, never the returned credentials
aws sts assume-role \
  --role-arn "$VICTIM_ROLE_ARN" \
  --role-session-name rcp-lab-baseline \
  --profile "$ATTACKER_PROFILE" \
  --query AssumedRoleUser.Arn --output text

# CT.S3.PV.4 candidate
aws s3api get-object \
  --bucket "$BUCKET" --key probe.txt /tmp/rcp-lab-downloaded.txt \
  --region "$REGION" --profile "$ATTACKER_PROFILE"
```

The preceding list calls exercise management APIs for KMS, Secrets Manager, STS, and S3, plus an SQS message data event. KMS `Encrypt`, Secrets Manager `GetSecretValue`, and `AssumeRole` produce management events. S3 `GetObject` and SQS `SendMessage` are data events and require the trail selectors described below.

### S3-specific baseline probes

For CT.S3.PV.2, create a presigned URL with the attacker credentials and use it before enabling that control:

```sh
PRESIGNED_URL=$(aws s3 presign "s3://${BUCKET}/probe.txt" \
  --expires-in 300 --region "$REGION" --profile "$ATTACKER_PROFILE")
curl --fail --silent --show-error "$PRESIGNED_URL" -o /tmp/rcp-lab-presigned.txt
```

For CT.S3.PV.3, use the presigned URL with TLS 1.2 forced. This test is meaningful when CT.S3.PV.2 is not attached, because a presigned URL independently violates the auth-type control:

```sh
curl --tls-max 1.2 --fail --silent --show-error \
  "$PRESIGNED_URL" -o /tmp/rcp-lab-tls12.txt
```

For CT.S3.PV.5, make an HTTP request using the presigned URL. The URL is sensitive bearer access; do not print or share it. Some local proxy or endpoint configurations may redirect or prevent this probe, so inspect the HTTP status and confirm the CloudTrail event:

```sh
HTTP_URL="${PRESIGNED_URL/https:/http:}"
curl --max-redirs 0 --silent --show-error \
  -o /dev/null -w 'HTTP status: %{http_code}\n' "$HTTP_URL"
unset HTTP_URL PRESIGNED_URL
```

For CT.S3.PV.6, upload without an SSE-KMS request header. Confirm the bucket has no default SSE-KMS configuration first. This should succeed before the control is attached:

```sh
aws s3api put-object \
  --bucket "$BUCKET" --key no-kms-header.txt \
  --body /tmp/rcp-lab-plaintext.txt \
  --region "$REGION" --profile "$ATTACKER_PROFILE"
```

Also verify an explicitly SSE-KMS-encrypted upload succeeds in the baseline. This isolates the missing-key condition and checks attacker use of the lab key:

```sh
aws s3api put-object \
  --bucket "$BUCKET" --key with-kms-header.txt \
  --body /tmp/rcp-lab-plaintext.txt \
  --server-side-encryption aws:kms \
  --ssekms-key-id "$KMS_KEY_ARN" \
  --region "$REGION" --profile "$ATTACKER_PROFILE"
```

## 3. Enable CloudTrail evidence before attaching policies

Use an existing organization trail delivered to S3 and an Athena table, or an existing CloudTrail Lake event data store if your organization already has Lake. CloudTrail Event history alone does not include S3 object and SQS message data events. Ensure the trail records management events and data events for `AWS::S3::Object` and `AWS::SQS::Queue` for the lab resources. Do not overwrite production trail selectors as part of this lab.

CloudTrail data events have additional charges. Event delivery is not instantaneous. Some services may not emit a CloudTrail record for every request denied by an organization policy, and error messages differ by service. The queries below show recorded successes and failures; they are not proof that an absent request was allowed or denied.

For an Athena table using the standard CloudTrail schema, set the target account and table name in the queries. The queries cover the past 24 hours. If your baseline probes ran earlier than that, widen the interval (for example `INTERVAL '48' HOUR`) so the before-and-after comparison still includes the baseline rows. A baseline success usually has `errorCode IS NULL`; a recorded failure has `errorCode IS NOT NULL`. An RCP denial may include “resource control policy” in `errorMessage`, but do not require that exact wording.

### Cross-account service and STS activity

Run this after baseline probes and again after enabling the identity-perimeter policy. `eventCategory` filtering is omitted so the query can return recorded management and data events. Narrow it by time and resources to control scan cost.

```sql
SELECT
  eventTime,
  eventSource,
  eventName,
  awsRegion,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS caller_account_id,
  userIdentity.arn AS caller_arn,
  userIdentity.invokedBy AS invoked_by,
  COALESCE(errorCode, 'ALLOWED') AS result,
  errorMessage,
  requestParameters
FROM cloudtrail_logs.organization_events
WHERE eventTime >= to_iso8601(current_timestamp - INTERVAL '24' HOUR)
  AND recipientAccountId = '111122223333'
  AND userIdentity.accountId = '444455556666'
  AND eventSource IN (
    'kms.amazonaws.com', 's3.amazonaws.com',
    'secretsmanager.amazonaws.com', 'sqs.amazonaws.com', 'sts.amazonaws.com'
  )
  AND (eventSource <> 'sts.amazonaws.com' OR eventName IN ('AssumeRole', 'SetContext'))
ORDER BY eventTime DESC
LIMIT 500;
```

An `ALLOWED` row before attachment proves the resource-policy baseline worked for that call. A recorded `AccessDenied` after attachment is the expected result. For CT.S3.PV.4 and CT.SQS.PV.1, the query includes management and any logged data events for those services.

### S3 request conditions

Use this query for the S3 probes before and after each S3 control is staged. It returns the condition-related event fields for manual comparison. Check the exact bucket and test object; bucket default encryption is not represented reliably by an object request alone.

```sql
SELECT
  eventTime,
  eventName,
  awsRegion,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS caller_account_id,
  userIdentity.arn AS caller_arn,
  tlsDetails.tlsVersion AS tls_version,
  tlsDetails.clientProvidedHostHeader AS host_header,
  json_extract_scalar(additionalEventData, '$.AuthenticationMethod') AS auth_method,
  requestParameters,
  responseElements,
  COALESCE(errorCode, 'ALLOWED') AS result,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= to_iso8601(current_timestamp - INTERVAL '24' HOUR)
  AND recipientAccountId = '111122223333'
  AND eventSource = 's3.amazonaws.com'
  AND json_extract_scalar(requestParameters, '$.bucketName') = 'REPLACE_WITH_LAB_BUCKET'
ORDER BY eventTime DESC
LIMIT 500;
```

Interpret the candidates carefully:

- CT.S3.PV.2: `AuthenticationMethod = 'QueryString'` identifies presigned URL requests; `AuthHeader` is header authentication. Confirm browser POST behavior with the application because it may not be represented consistently.
- CT.S3.PV.3: a recorded TLS version other than `TLSv1.3` is a candidate. Do not confuse absent `tlsDetails` with old TLS.
- CT.S3.PV.5: this control denies requests when `aws:SecureTransport` is false. CloudTrail's missing `tlsDetails` is not proof the request used HTTP.
- CT.S3.PV.6: inspect the `PutObject` request for a KMS key ID. A request without one can still succeed when bucket default encryption is SSE-KMS; this lab intentionally configures no such default.

The related CloudTrail query examples are also in the [CloudTrail review guide](CLOUDTRAIL-REVIEW.md#3-per-control-checks).

## 4. Attach RCPs to the victim account, one control at a time

The project applies the configured `target_ids` to all enabled policy groups. For a lab, use a separate tfvars file and a dedicated Terraform state. Do not commit account IDs, credentials, generated plans, or sensitive URLs.

Create `lab.tfvars` in the repository root with the victim account ID and only the first control to test:

```hcl
target_ids       = ["111122223333"]
enabled_controls = ["CT.KMS.PV.7"]
```

Set the Terraform credentials to the authorized organization administrator profile, then run the documented checks, plan, and capacity preflight. The preflight itself must query Organizations with credentials allowed to list RCPs; pass its profile explicitly.

```sh
export AWS_PROFILE="$ORG_ADMIN_PROFILE"
terraform init
terraform fmt -check -recursive
terraform validate
terraform test
terraform plan -var-file=lab.tfvars -out=tfplan
python3 scripts/check_rcp_attachment_capacity.py tfplan --profile "$ORG_ADMIN_PROFILE"
terraform apply tfplan
```

Run the matching attacker request again. Expect a recorded denial for the isolated control. Then change `enabled_controls` to the next control and repeat plan, preflight, and apply. Terraform will update the grouped policy as the enabled set changes. Suggested order:

1. CT.KMS.PV.7: `kms:Encrypt` request.
2. CT.SECRETSMANAGER.PV.1: `GetSecretValue` request. The secret uses the customer-managed lab key for cross-account access; enable only CT.SECRETSMANAGER.PV.1 during this test so CT.KMS.PV.7 does not independently deny the required KMS decrypt.
3. CT.SQS.PV.1: `SendMessage` (and `ReceiveMessage` if desired).
4. CT.STS.PV.1: `AssumeRole` request. This control also covers `SetContext`; the lab command exercises `AssumeRole`.
5. CT.S3.PV.4: `GetObject` request. This is a data event, so verify S3 data selectors are enabled.
6. CT.S3.PV.2: presigned URL request.
7. CT.S3.PV.3: TLS 1.2 request. Keep CT.S3.PV.2 disabled for this isolated test because a presigned URL also violates the auth-type rule.
8. CT.S3.PV.5: HTTP request. Keep other S3 request controls disabled while isolating this test.
9. CT.S3.PV.6: upload without SSE-KMS header. Keep CT.KMS.PV.7 disabled for the explicit KMS-header comparison unless you separately add the required key trust for this isolated scenario.

For the S3 controls, changing `enabled_controls` to one ID at a time makes the relevant S3 policy contain only that statement. For the other controls, one selected ID creates one statement in `identity-perimeter`.

Once each isolated test behaves as expected, you can stage a combined policy by listing multiple control IDs in `enabled_controls`. Before using the full default set, review each expected impact with the relevant workload owners. Keep the RCPs attached only as long as needed for the authorized lab, then remove them using the cleanup step.

### Expected results

| Control | Baseline attacker request | With only this control enabled |
|---|---|---|
| CT.KMS.PV.7 | KMS `Encrypt` succeeds | `Encrypt` is denied |
| CT.SECRETSMANAGER.PV.1 | `GetSecretValue` succeeds | Read is denied |
| CT.SQS.PV.1 | `SendMessage` succeeds | Send is denied |
| CT.STS.PV.1 | `AssumeRole` succeeds | Role assumption is denied |
| CT.S3.PV.4 | `GetObject` succeeds | Object access is denied |
| CT.S3.PV.2 | Presigned GET succeeds | Presigned request is denied; a normal header-signed CLI request should remain permitted by this control |
| CT.S3.PV.3 | TLS 1.2 request succeeds | TLS 1.2 request is denied; TLS 1.3 should remain permitted by this control |
| CT.S3.PV.5 | HTTP request succeeds if endpoint/client permits it | HTTP request is denied; HTTPS should remain permitted by this control |
| CT.S3.PV.6 | Upload without KMS header succeeds | Upload without key ID and without default SSE-KMS is denied; explicit SSE-KMS upload should remain permitted if KMS authorization succeeds |

These are expected policy outcomes, not guarantees that every AWS API produces a visible CloudTrail error event. The direct request response is the primary test result; CloudTrail is the audit trail when the request is logged.

## 5. Test an exemption (optional)

For an isolated test of `ExemptedPrincipalArns`, add the attacker role only to the control under test in `lab.tfvars`. Example for STS:

```hcl
target_ids       = ["111122223333"]
enabled_controls = ["CT.STS.PV.1"]
exempted_principal_arns = {
  "CT.STS.PV.1" = ["arn:aws:iam::444455556666:role/RcpLabAttacker"]
}
```

Plan, run the capacity preflight, and apply again. `AssumeRole` should work if the role trust and caller permissions still allow it. Remove the exemption and reapply to verify the denial returns. Exemptions are powerful bypasses; keep them exact and control-specific.

To test `additional_trusted_organization_ids`, the attacker must belong to a separate organization whose organization ID is added to that variable. The current two-account lab attacker is not trusted by default; adding only the attacker account ID is not the same as adding its organization ID.

For CT.S3.PV.6 resource exemptions, use an S3 bucket/object ARN in `s3_sse_kms_exempted_resource_arns`; because the statement uses `NotResource`, uploads to those resources bypass that statement. Test only a dedicated disposable resource.

## 6. Remove the policies and lab resources

First remove the lab RCP attachments and policies using this Terraform state. Ensure the state contains only the lab resources before using `destroy`:

```sh
terraform destroy -var-file=lab.tfvars
```

Then delete resources in the victim account:

```sh
aws s3 rm "s3://${BUCKET}" --recursive --profile "$VICTIM_PROFILE"
aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION" --profile "$VICTIM_PROFILE"
aws secretsmanager delete-secret --secret-id "$SECRET_NAME" --force-delete-without-recovery \
  --region "$REGION" --profile "$VICTIM_PROFILE"
aws sqs delete-queue --queue-url "$QUEUE_URL" --region "$REGION" --profile "$VICTIM_PROFILE"
aws iam delete-role --role-name "$ROLE_NAME" --profile "$VICTIM_PROFILE"
aws kms schedule-key-deletion --key-id "$KMS_KEY_ID" --pending-window-in-days 7 \
  --region "$REGION" --profile "$VICTIM_PROFILE"
```

KMS key deletion is scheduled rather than immediate. Confirm the key is lab-only before scheduling deletion. Remove temporary local policy files, downloaded objects, Terraform plan/state artifacts according to your organization's handling requirements, and any temporary attacker-role permissions. CloudTrail records are retained according to the organization's logging configuration.

## References

- [AWS Control Tower RCP control templates](https://docs.aws.amazon.com/controltower/latest/controlreference/list-of-rcp-controls.html)
- [AWS Organizations RCP behavior](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [CloudTrail review and per-control queries](CLOUDTRAIL-REVIEW.md)
- [Beginner project guide](GUIDE-BEGINNER.md)
- [Project README](README.md)
