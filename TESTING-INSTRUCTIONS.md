# Testing the RCPs in your own AWS environment

This runbook shows how to prove the resource control policies (RCPs) in this repository actually do what they claim: first confirm a request **succeeds**, then attach the RCP, then confirm the same request is **denied**. It also gives CloudTrail queries that show both the allowed and the denied activity.

The identity-perimeter controls (KMS, S3, Secrets Manager, SQS, STS) are about *who* can reach a resource, so testing them needs two accounts. The S3 data-protection controls (TLS, HTTPS, header auth, SSE-KMS) are about *how* a request is made, so they can be tested from a single account.

> A companion document, [RCP-LAB-TESTING.md](RCP-LAB-TESTING.md), covers much of the same ground with a slightly different structure. Use whichever you prefer; don't run both against the same resources at once.

## Before you start: authorization and scope

- **Use only accounts you own and are authorized to change.** This is a test of your own guardrails, not of anyone else's environment.
- **Use non-production, empty test accounts.** The setup grants deliberately broad cross-account access so you have something to block. Never do this to accounts holding real data.
- **RCPs never apply to the management account.** Attach them to a test OU or a member account, not to the org root during a first run.
- **Clean up afterward.** Section 8 removes every resource and policy this runbook creates.

## Two roles, both yours

| Role | What it is | Stands in for |
|---|---|---|
| **Resource account** | A member account in your organization that holds the test resources. | The account whose resources the RCP protects. |
| **External account** | A second account you control, **outside** this organization (a separate standalone account, or one in a different org). | An out-of-organization principal the RCP should keep out. |

The external account must be outside the organization for the identity-perimeter tests to mean anything. A second account *inside* the same org would be allowed by `aws:PrincipalOrgID` and would never be blocked, so it can't demonstrate the control.

## 1. Prerequisites and shared variables

Configure two AWS CLI profiles, one per account, each with enough permission to create and read the resources below. Then set these in your shell:

```sh
REGION=us-east-1

RESOURCE_PROFILE=rcp-resource-acct
EXTERNAL_PROFILE=rcp-external-acct

RESOURCE_ACCT=$(aws sts get-caller-identity --profile "$RESOURCE_PROFILE" --query Account --output text)
EXTERNAL_ACCT=$(aws sts get-caller-identity --profile "$EXTERNAL_PROFILE" --query Account --output text)

# The org that this repo's RCPs protect (the resource account's org).
ORG_ID=$(aws organizations describe-organization \
  --profile "$RESOURCE_PROFILE" \
  --query 'Organization.Id' --output text)

SUFFIX=$(date +%s)   # keeps resource names unique across runs

printf 'resource=%s external=%s org=%s\n' "$RESOURCE_ACCT" "$EXTERNAL_ACCT" "$ORG_ID"
```

For S3 `create-bucket` in a Region other than `us-east-1`, add `--create-bucket-configuration LocationConstraint="$REGION"`.

## 2. Create cross-account-accessible resources in the resource account

Each resource gets a resource policy that grants the external account access. This is the configuration the identity-perimeter RCPs are designed to constrain — a resource whose own policy trusts an account outside the org.

### S3 bucket

```sh
BUCKET="rcp-test-${RESOURCE_ACCT}-${SUFFIX}"

aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
  --profile "$RESOURCE_PROFILE"

echo "hello from the resource account" > object.txt
aws s3api put-object --bucket "$BUCKET" --key object.txt --body object.txt \
  --profile "$RESOURCE_PROFILE"

cat > bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowExternalAccount",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${EXTERNAL_ACCT}:root" },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::${BUCKET}/*"
  }]
}
EOF

aws s3api put-bucket-policy --bucket "$BUCKET" \
  --policy file://bucket-policy.json --profile "$RESOURCE_PROFILE"
```

### KMS key

The key policy must keep granting the resource account's root (so you don't lock yourself out) and also grant the external account.

```sh
cat > key-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ResourceAccountAdmin",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${RESOURCE_ACCT}:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowExternalAccount",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${EXTERNAL_ACCT}:root" },
      "Action": ["kms:Encrypt", "kms:DescribeKey"],
      "Resource": "*"
    }
  ]
}
EOF

KEY_ARN=$(aws kms create-key \
  --policy file://key-policy.json \
  --description "RCP test key ${SUFFIX}" \
  --profile "$RESOURCE_PROFILE" \
  --query 'KeyMetadata.Arn' --output text)

echo "$KEY_ARN"
```

### Secrets Manager secret

```sh
SECRET_ARN=$(aws secretsmanager create-secret \
  --name "rcp-test-secret-${SUFFIX}" \
  --secret-string 'test-value' \
  --profile "$RESOURCE_PROFILE" \
  --query 'ARN' --output text)

cat > secret-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowExternalAccount",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${EXTERNAL_ACCT}:root" },
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "*"
  }]
}
EOF

aws secretsmanager put-resource-policy \
  --secret-id "$SECRET_ARN" \
  --resource-policy file://secret-policy.json \
  --profile "$RESOURCE_PROFILE"
```

### SQS queue

```sh
QUEUE_URL=$(aws sqs create-queue \
  --queue-name "rcp-test-queue-${SUFFIX}" \
  --profile "$RESOURCE_PROFILE" \
  --query 'QueueUrl' --output text)

QUEUE_ARN=$(aws sqs get-queue-attributes \
  --queue-url "$QUEUE_URL" --attribute-names QueueArn \
  --profile "$RESOURCE_PROFILE" \
  --query 'Attributes.QueueArn' --output text)

cat > queue-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowExternalAccount",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${EXTERNAL_ACCT}:root" },
    "Action": "sqs:SendMessage",
    "Resource": "${QUEUE_ARN}"
  }]
}
EOF

aws sqs set-queue-attributes --queue-url "$QUEUE_URL" \
  --attributes Policy="$(cat queue-policy.json | tr -d '\n')" \
  --profile "$RESOURCE_PROFILE"
```

### STS role

A role whose trust policy allows the external account to assume it.

```sh
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${EXTERNAL_ACCT}:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

ROLE_ARN=$(aws iam create-role \
  --role-name "rcp-test-role-${SUFFIX}" \
  --assume-role-policy-document file://trust-policy.json \
  --profile "$RESOURCE_PROFILE" \
  --query 'Role.Arn' --output text)

echo "$ROLE_ARN"
```

In the **external account**, the principal you test with also needs its own identity-based permission for each action (for example an `AdministratorAccess` or a scoped policy allowing `s3:GetObject`, `kms:Encrypt`, `secretsmanager:GetSecretValue`, `sqs:SendMessage`, `sts:AssumeRole`). Cross-account access requires both the resource policy (set above) and an identity policy in the calling account.

## 3. Baseline: confirm the requests succeed (before any RCP)

Run these from the external account. With no RCP attached, each should succeed. That success is the point — it's what the RCP will take away.

```sh
# CT.S3.PV.4
aws s3api get-object --bucket "$BUCKET" --key object.txt /tmp/out.txt \
  --profile "$EXTERNAL_PROFILE" && echo "S3: ALLOWED"

# CT.KMS.PV.7
printf 'test' > /tmp/kms-in.txt
aws kms encrypt --key-id "$KEY_ARN" --plaintext fileb:///tmp/kms-in.txt \
  --profile "$EXTERNAL_PROFILE" --query KeyId --output text && echo "KMS: ALLOWED"

# CT.SECRETSMANAGER.PV.1
aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
  --profile "$EXTERNAL_PROFILE" --query Name --output text && echo "SECRETS: ALLOWED"

# CT.SQS.PV.1
aws sqs send-message --queue-url "$QUEUE_URL" --message-body 'test' \
  --profile "$EXTERNAL_PROFILE" --query MessageId --output text && echo "SQS: ALLOWED"

# CT.STS.PV.1 — check only that the assume-role succeeds; do not print or store the returned credentials
aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name rcp-test \
  --profile "$EXTERNAL_PROFILE" --query 'AssumedRoleUser.Arn' --output text && echo "STS: ALLOWED"
```

Record which succeeded. Anything that fails here is a setup problem (usually a missing identity policy in the external account), not the RCP — the RCP isn't attached yet.

## 4. Turn on CloudTrail evidence

You need CloudTrail recording in the resource account (or an organization trail in your log-archive account) before you attach the policies, so the before/after comparison is captured. Management events (KMS, Secrets Manager, STS, and bucket-level S3/SQS) are on by default. Object-level S3 and message-level SQS are **data events** and must be enabled explicitly. See [CLOUDTRAIL-REVIEW.md](CLOUDTRAIL-REVIEW.md) section on prerequisites and `get-event-selectors` for how to confirm coverage.

## 5. Attach the RCPs with this Terraform

Point the module at the **resource account** (or the test OU that contains it) and apply. Start with all controls, or trim `enabled_controls` to test one at a time.

```hcl
# terraform.tfvars
target_ids = ["123456789012"]   # the resource account ID, or "ou-xxxx-xxxxxxxx"

# Optional: test one control first
# enabled_controls = ["CT.S3.PV.4"]
```

```sh
terraform init
terraform apply
```

Confirm the `RESOURCE_CONTROL_POLICY` type is enabled on the org root first (see [README.md](README.md) prerequisites); the plan fails with a clear message if it isn't. Allow a short time for policy propagation before re-testing.

## 6. Re-test: confirm the requests are now denied

Re-run the exact commands from section 3, from the external account. Each should now fail with `AccessDenied`.

```sh
aws s3api get-object --bucket "$BUCKET" --key object.txt /tmp/out.txt \
  --profile "$EXTERNAL_PROFILE" || echo "S3: DENIED (expected)"

aws kms encrypt --key-id "$KEY_ARN" --plaintext fileb:///tmp/kms-in.txt \
  --profile "$EXTERNAL_PROFILE" || echo "KMS: DENIED (expected)"

aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
  --profile "$EXTERNAL_PROFILE" || echo "SECRETS: DENIED (expected)"

aws sqs send-message --queue-url "$QUEUE_URL" --message-body 'test' \
  --profile "$EXTERNAL_PROFILE" || echo "SQS: DENIED (expected)"

aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name rcp-test \
  --profile "$EXTERNAL_PROFILE" || echo "STS: DENIED (expected)"
```

The resource policies are unchanged and still grant the external account. The only thing that changed is the RCP, so a denial here is the control working.

### S3 data-protection controls (single account)

These don't need the external account. Run from the resource account against the test bucket, before and after attaching the S3 policy.

```sh
# CT.S3.PV.5 — HTTPS required. This forces plain HTTP and should be denied once PV.5 is attached.
curl -s -o /dev/null -w '%{http_code}\n' "http://${BUCKET}.s3.${REGION}.amazonaws.com/object.txt"

# CT.S3.PV.3 — TLS 1.3 required. A TLS 1.2 request should be denied once PV.3 is attached.
curl -s -o /dev/null -w '%{http_code}\n' --tls-max 1.2 \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/object.txt"

# CT.S3.PV.6 — SSE-KMS required on upload. Upload with no encryption header; denied once PV.6 is attached
# (unless the bucket's default encryption is SSE-KMS).
aws s3api put-object --bucket "$BUCKET" --key no-sse.txt --body object.txt \
  --profile "$RESOURCE_PROFILE" || echo "PV.6: DENIED (expected)"

# CT.S3.PV.6 — the same upload WITH an SSE-KMS key should be allowed.
aws s3api put-object --bucket "$BUCKET" --key with-sse.txt --body object.txt \
  --server-side-encryption aws:kms --ssekms-key-id "$KEY_ARN" \
  --profile "$RESOURCE_PROFILE" && echo "PV.6 with key: ALLOWED"
```

For CT.S3.PV.2, header-signed CLI/SDK calls keep working; a **presigned URL** is what the control blocks:

```sh
URL=$(aws s3 presign "s3://${BUCKET}/object.txt" --profile "$RESOURCE_PROFILE")
curl -s -o /dev/null -w '%{http_code}\n' "$URL"   # 403 once PV.2 is attached
```

## 7. CloudTrail queries: allowed vs denied

These show the same principal's activity before (allowed) and after (denied). They reuse the `ct_lookup` helper and Athena setup from [CLOUDTRAIL-REVIEW.md](CLOUDTRAIL-REVIEW.md).

### AWS CLI (management events)

```sh
# All KMS activity from the external account, labeled ALLOWED or with the error code.
ct_lookup EventSource kms.amazonaws.com | grep "$EXTERNAL_ACCT"

# STS assume-role activity from the external account.
for NAME in AssumeRole SetContext; do
  ct_lookup EventName "$NAME"
done | grep "$EXTERNAL_ACCT"
```

Before the RCP, the external account's rows show `ALLOWED`. After, the same calls show `AccessDenied`.

### Athena (management and data events)

Show both outcomes for the external principal side by side. Replace the table name and account IDs. The queries cover the past 24 hours; if you ran the baseline in section 3 earlier than that, widen the interval (for example `INTERVAL '48' HOUR`) so the `ALLOWED` rows are still included.

```sql
SELECT
  eventTime,
  eventSource,
  eventName,
  userIdentity.arn        AS principal_arn,
  userIdentity.accountId  AS principal_account_id,
  COALESCE(errorCode, 'ALLOWED') AS result,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= to_iso8601(current_timestamp - INTERVAL '24' HOUR)
  AND recipientAccountId = '123456789012'          -- resource account
  AND userIdentity.accountId = '999988887777'      -- external account
  AND eventSource IN (
    'kms.amazonaws.com', 's3.amazonaws.com',
    'secretsmanager.amazonaws.com', 'sqs.amazonaws.com', 'sts.amazonaws.com'
  )
ORDER BY eventTime;
```

Rows before the attachment time read `ALLOWED`; rows after read `AccessDenied`. To isolate the RCP denials specifically:

```sql
SELECT eventTime, eventSource, eventName, userIdentity.arn AS principal_arn, errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= to_iso8601(current_timestamp - INTERVAL '24' HOUR)
  AND recipientAccountId = '123456789012'
  AND errorMessage LIKE '%resource control policy%'
ORDER BY eventTime DESC;
```

> The exact denial wording ("...explicit deny in a resource control policy") is what services that include policy detail return; some return a generic `AccessDenied`. Run the query once against your own logs to confirm the wording before relying on the `LIKE` filter, then also review any new `AccessDenied` since the attachment time.

## 8. Test an exemption (optional)

Prove the escape hatch works. Add the external account's role to the relevant control's exemption and re-apply:

```hcl
exempted_principal_arns = {
  "CT.STS.PV.1" = ["arn:aws:iam::999988887777:role/YourExternalTestRole"]
}
```

```sh
terraform apply
```

Re-run the STS test from section 6. It should now succeed again, because the exemption's `ArnNotLike` removes that principal from the deny. This confirms `exempted_principal_arns` reaches the right control without weakening the others.

## 9. Tear down

Remove the policies first, then the resources.

```sh
# Detach and delete the RCPs
terraform destroy

# Resource account cleanup
aws s3 rm "s3://${BUCKET}" --recursive --profile "$RESOURCE_PROFILE"
aws s3api delete-bucket --bucket "$BUCKET" --profile "$RESOURCE_PROFILE"
aws kms schedule-key-deletion --key-id "$KEY_ARN" \
  --pending-window-in-days 7 --profile "$RESOURCE_PROFILE"
aws secretsmanager delete-secret --secret-id "$SECRET_ARN" \
  --force-delete-without-recovery --profile "$RESOURCE_PROFILE"
aws sqs delete-queue --queue-url "$QUEUE_URL" --profile "$RESOURCE_PROFILE"
aws iam delete-role --role-name "rcp-test-role-${SUFFIX}" --profile "$RESOURCE_PROFILE"

rm -f object.txt bucket-policy.json key-policy.json secret-policy.json \
  queue-policy.json trust-policy.json /tmp/out.txt /tmp/kms-in.txt
```

KMS keys can't be deleted immediately; 7 days is the minimum pending window.

## What "pass" looks like

For each control: the request **succeeded** in section 3, the identical request was **denied** in section 6, CloudTrail shows the matching `ALLOWED` then `AccessDenied` rows, and (section 8) an exemption restores access for only the exempted principal. If a request is denied in section 3 before any RCP exists, fix the test setup — that's not the control.

## References

- [README.md](README.md) — the controls, variables, and prerequisites
- [CLOUDTRAIL-REVIEW.md](CLOUDTRAIL-REVIEW.md) — the `ct_lookup` helper, Athena setup, and per-control queries
- [RCP-LAB-TESTING.md](RCP-LAB-TESTING.md) — the companion lab walkthrough
