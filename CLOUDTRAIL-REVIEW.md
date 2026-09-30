# CloudTrail review for the RCP controls

This runbook helps an AWS administrator find recent activity that could be affected by the RCPs in this repository. Run it before attaching policies, review the results with application owners, and investigate the principal, resource, and request details before adding exemptions or enabling controls.

These searches identify candidates, not definitive policy evaluations. CloudTrail does not record every request, and it does not generally record the request-context keys that the RCP conditions evaluate.

## What the searches can show

| Controls | CloudTrail evidence to review |
|---|---|
| CT.KMS.PV.7 | KMS API activity from principals outside this organization or an explicitly trusted organization. KMS events are management events by default, but a trail can exclude them. |
| CT.S3.PV.4 | S3 API activity from external principals. Review both bucket-level management events and object-level data events. |
| CT.SECRETSMANAGER.PV.1 | Secrets Manager API activity from external principals. |
| CT.SQS.PV.1 | SQS API activity from external principals. Review management events and message data events. |
| CT.STS.PV.1 | `AssumeRole` and `SetContext` requests from outside the organization. Other STS actions are outside this control's scope. |
| CT.S3.PV.2 | S3 object requests that may use presigned URL or POST authentication. Review request and additional event details; CloudTrail may not expose the authorization method for every request. |
| CT.S3.PV.3 | S3 requests whose recorded TLS version is below 1.3. |
| CT.S3.PV.5 | S3 requests made over HTTP. Missing TLS details alone are inconclusive. |
| CT.S3.PV.6 | S3 object uploads that may lack an SSE-KMS key ID. Check the bucket's default encryption before treating an upload as affected. |

## Prerequisites and coverage

Use credentials authorized to read CloudTrail and, for Athena, query the CloudTrail log table and read its query-results S3 location. For organization-wide results, use the central logging account and an organization trail, or repeat the Event history lookup in each target account and Region.

CloudTrail Event history and `lookup-events` cover management events in one account and one Region for the past 90 days. They do not show S3 object or SQS message data events. Trails do not log data events by default; data-event logging must have been enabled for the relevant resources and time period. Logging data events can incur additional charges.

Check the trail selectors before relying on data-event query results. Substitute the trail ARN/name and its home Region:

```sh
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --region us-east-1

aws cloudtrail get-event-selectors \
  --trail-name arn:aws:cloudtrail:us-east-1:111122223333:trail/organization-trail \
  --region us-east-1
```

Confirm that the selectors include management events and the required data-event resource types, such as `AWS::S3::Object` and `AWS::SQS::Queue`. If they were not enabled during the review period, CloudTrail cannot provide retrospective data-event records. Do not change trail selectors as part of this review without coordinating with the logging owner; changing selectors may alter existing coverage and incur charges.

CloudTrail Lake SQL is an option only for organizations that already have CloudTrail Lake. AWS stopped accepting new CloudTrail Lake customers on May 31, 2026. The Athena instructions below use existing CloudTrail trail logs in S3 and require an Athena database/table already set up for those logs.

## 1. Search management events with AWS CLI

Choose the target Regions and UTC review window. Repeat the lookup in each target account and Region. `lookup-events` accepts only one lookup attribute at a time, so run one command per event source. AWS CLI automatically paginates unless pagination is disabled.

```sh
PROFILE=security-audit
REGION=us-east-1
START_TIME=2026-09-01T00:00:00Z
END_TIME=2026-09-30T00:00:00Z

for SOURCE in \
  kms.amazonaws.com \
  s3.amazonaws.com \
  secretsmanager.amazonaws.com \
  sqs.amazonaws.com \
  sts.amazonaws.com
do
  aws cloudtrail lookup-events \
    --lookup-attributes "AttributeKey=EventSource,AttributeValue=$SOURCE" \
    --start-time "$START_TIME" \
    --end-time "$END_TIME" \
    --region "$REGION" \
    --profile "$PROFILE" \
    --query 'Events[].{Time:EventTime,Name:EventName,User:Username,RawEvent:CloudTrailEvent}' \
    --output json
  done
```

In the STS results, focus on `AssumeRole` and `SetContext`. In all results, inspect the raw event for `errorCode`, `errorMessage`, `userIdentity`, `recipientAccountId`, and resource ARNs. An `AccessDenied` event is useful evidence of current failures; successful calls by external principals identify integrations that may be denied after the RCP is attached.

Compare the caller's account and principal with the organization and trusted external organizations. A cross-account event is only a candidate: it may be from an account in the same organization, an explicitly trusted organization, or an AWS service. Conversely, not every relevant identity or service-mediated request is represented by a simple account-ID comparison.

To check one control at a time, with results labeled by caller location and outcome, use [section 3](#3-per-control-checks).

## 2. Query S3 and SQS data events with Athena

Set these values for an existing Athena table over the organization's CloudTrail S3 logs. The table should use the standard CloudTrail event schema, including `userIdentity`, `tlsDetails`, `requestParameters`, and `additionalEventData`. Set the date range and target account IDs in each query. Keep the window narrow to control scan cost.

```sh
ATHENA_DATABASE=cloudtrail_logs
ATHENA_WORKGROUP=primary
ATHENA_REGION=us-east-1
ATHENA_RESULTS=s3://example-athena-results/cloudtrail-review/

# Save one of the SQL queries below as query.sql, then start it:
QUERY_ID=$(aws athena start-query-execution \
  --query-string "$(cat query.sql)" \
  --query-execution-context "Database=$ATHENA_DATABASE,Catalog=AwsDataCatalog" \
  --result-configuration "OutputLocation=$ATHENA_RESULTS" \
  --work-group "$ATHENA_WORKGROUP" \
  --region "$ATHENA_REGION" \
  --profile "$PROFILE" \
  --query QueryExecutionId \
  --output text)

printf 'Query ID: %s\n' "$QUERY_ID"
aws athena get-query-execution \
  --query-execution-id "$QUERY_ID" \
  --region "$ATHENA_REGION" \
  --profile "$PROFILE" \
  --query 'QueryExecution.Status.State' \
  --output text

# Repeat get-query-execution until the state is SUCCEEDED, then fetch results.
aws athena get-query-results \
  --query-execution-id "$QUERY_ID" \
  --region "$ATHENA_REGION" \
  --profile "$PROFILE" \
  --output json
```

If the Athena workgroup enforces its own output location, use that configured location instead. `get-query-results` requires both Athena permissions and read access to the query-results S3 location. Replace `cloudtrail_logs.organization_events` below with the actual database and table name.

### Identity-perimeter and STS candidates

This groups events by principal so the administrator can compare caller accounts with the organization and trusted-organization inventory. It includes management and any recorded data events for the listed services. For STS, it limits results to the two actions covered by CT.STS.PV.1.

```sql
SELECT
  eventSource,
  eventName,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS principal_account_id,
  userIdentity.arn AS principal_arn,
  userIdentity.invokedBy AS invoked_by_service,
  errorCode,
  COUNT(*) AS event_count
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource IN (
    'kms.amazonaws.com',
    's3.amazonaws.com',
    'secretsmanager.amazonaws.com',
    'sqs.amazonaws.com',
    'sts.amazonaws.com'
  )
  AND (
    eventSource <> 'sts.amazonaws.com'
    OR eventName IN ('AssumeRole', 'SetContext')
  )
GROUP BY 1, 2, 3, 4, 5, 6, 7
ORDER BY event_count DESC
LIMIT 1000;
```

A principal account outside the organization is not automatically a violation: check whether it belongs to an additional trusted organization or is covered by a per-control principal exemption. Inspect AWS-service-originated activity separately; the identity-perimeter statements allow AWS service principals.

### S3 object requests

This query surfaces object operations useful for reviewing the S3 controls. It returns request and additional event details for manual inspection instead of assuming those fields are always populated or uniform.

```sql
SELECT
  eventTime,
  eventName,
  awsRegion,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS principal_account_id,
  userIdentity.arn AS principal_arn,
  userIdentity.invokedBy AS invoked_by_service,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  json_extract_scalar(requestParameters, '$.key') AS object_key,
  tlsDetails.tlsVersion AS tls_version,
  errorCode,
  errorMessage,
  requestParameters,
  additionalEventData
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND eventCategory = 'Data'
  AND eventName IN (
    'GetObject',
    'PutObject',
    'CreateMultipartUpload',
    'CompleteMultipartUpload'
  )
ORDER BY eventTime DESC
LIMIT 1000;
```

Review events with `tlsVersion` below `TLSv1.3` for CT.S3.PV.3. A missing `tlsDetails` value is not proof of HTTP: CloudTrail omits TLS details for some AWS-service and proxy requests. For CT.S3.PV.5, investigate requests known to use plain HTTP; do not classify every event missing TLS details as HTTP. For CT.S3.PV.2, inspect authentication-related fields when present and confirm presigned URL or POST workflows with their owners; CloudTrail fields do not always conclusively identify the S3 `authType` condition.

For CT.S3.PV.6, review `PutObject` and multipart-upload request parameters for an SSE-KMS key ID. A missing request header alone is not enough to conclude the upload will be denied: check that bucket's default encryption. For each bucket in question, run:

```sh
aws s3api get-bucket-encryption \
  --bucket example-bucket \
  --region us-east-1 \
  --profile "$PROFILE"
```

The control permits the upload when the bucket's default encryption is SSE-KMS, and this repository supports resource ARN exemptions for CT.S3.PV.6.

### SQS message operations

SQS message activity is data-event activity and is not returned by `lookup-events`. Query it only if `AWS::SQS::Queue` data events were being logged for the review period.

```sql
SELECT
  eventTime,
  eventName,
  awsRegion,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS principal_account_id,
  userIdentity.arn AS principal_arn,
  userIdentity.invokedBy AS invoked_by_service,
  json_extract_scalar(requestParameters, '$.queueUrl') AS queue_url,
  errorCode,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 'sqs.amazonaws.com'
  AND eventCategory = 'Data'
  AND eventName IN (
    'SendMessage', 'SendMessageBatch',
    'ReceiveMessage', 'DeleteMessage', 'DeleteMessageBatch',
    'ChangeMessageVisibility', 'ChangeMessageVisibilityBatch'
  )
ORDER BY eventTime DESC
LIMIT 1000;
```

## 3. Per-control checks

Use these checks to review one control at a time. Each check lists allowed calls as well as denied ones.

- **Before you attach the RCPs**, the calls that matter are allowed calls from outside the organization. They show integrations that the control will deny once attached.
- **After you attach the RCPs**, look for new `AccessDenied` errors. See [After rollout: find RCP denials](#after-rollout-find-rcp-denials).

`lookup-events` can only cover the identity-perimeter controls, and only their management events. It returns no S3 object or SQS message data events. It also filters on a single attribute and can't filter by result or caller account. So the commands below pipe its output through `jq`, and the S3 request controls use Athena.

### Setup

Set `PROFILE`, `REGION`, `START_TIME` and `END_TIME` as in section 1. Then save the organization's account IDs. This needs credentials in the management account, or in a delegated administrator account for AWS Organizations:

```sh
ORG_PROFILE=org-management

aws organizations list-accounts \
  --profile "$ORG_PROFILE" \
  --query 'Accounts[].Id' \
  --output json > org-accounts.json
```

If you trust other organizations through `additional_trusted_organization_ids`, add their account IDs to `org-accounts.json` if you know them. Otherwise, callers from those accounts show as `OUTSIDE-ORG` and need to be checked by hand.

Define this helper. It runs `lookup-events` with one attribute and prints one tab-separated row per event: time, API action, caller account, `IN-ORG` or `OUTSIDE-ORG`, caller ARN, result (`ALLOWED` or the error code), and the error message. Calls made by AWS services are skipped, because the identity-perimeter controls allow AWS service principals.

```sh
ct_lookup() {
  aws cloudtrail lookup-events \
    --lookup-attributes "AttributeKey=$1,AttributeValue=$2" \
    --start-time "$START_TIME" \
    --end-time "$END_TIME" \
    --region "$REGION" \
    --profile "$PROFILE" \
    --query 'Events[].CloudTrailEvent' \
    --output json |
  jq -r --slurpfile org org-accounts.json '
    .[] | fromjson
    | select(.userIdentity.type != "AWSService")
    | (.userIdentity.accountId // "") as $acct
    | [ .eventTime,
        .eventName,
        (if $acct == "" then "-" else $acct end),
        (if any($org[0][]; . == $acct) then "IN-ORG" else "OUTSIDE-ORG" end),
        (.userIdentity.arn // "-"),
        (.errorCode // "ALLOWED"),
        (.errorMessage // "") ]
    | @tsv'
}
```

As in section 1, run each command in every target account and Region. Add `| grep OUTSIDE-ORG` to any command to show only the rows that matter before rollout.

### Identity-perimeter controls (AWS CLI)

**CT.KMS.PV.7**: all KMS calls.

```sh
ct_lookup EventSource kms.amazonaws.com
```

**CT.SECRETSMANAGER.PV.1**: all Secrets Manager calls.

```sh
ct_lookup EventSource secretsmanager.amazonaws.com
```

**CT.STS.PV.1**: the two actions this control covers. `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` and `GetCallerIdentity` are out of scope.

```sh
for NAME in AssumeRole SetContext; do
  ct_lookup EventName "$NAME"
done
```

**CT.S3.PV.4**: S3 bucket-level management calls only. For object reads and writes, use the CT.S3.PV.4 Athena query below.

```sh
ct_lookup EventSource s3.amazonaws.com
```

**CT.SQS.PV.1**: SQS queue-level management calls only. For message calls such as `SendMessage` and `ReceiveMessage`, use the SQS query in section 2 and compare `principal_account_id` with `org-accounts.json`.

```sh
ct_lookup EventSource sqs.amazonaws.com
```

How to read the results:

- An `OUTSIDE-ORG` row with `ALLOWED` is a caller the control will deny once attached, unless its organization is trusted or its ARN is in `exempted_principal_arns`.
- A `-` in the caller account column means CloudTrail recorded no account for the caller, for example an anonymous request. The control denies these too.
- `IN-ORG` rows are not affected by these controls.

### S3 request controls (Athena)

These controls apply to object requests, which are data events, so they need Athena and the S3 data events that section 2 describes. Run each query with the `aws athena start-query-execution` commands from section 2. Set the date range and target account IDs in each query, and replace `cloudtrail_logs.organization_events` with your table name.

**CT.S3.PV.4**: object requests from callers outside the organization. To build the account list for the `NOT IN` clause, run:

```sh
jq -r 'map(@sh) | join(", ")' org-accounts.json
```

```sql
SELECT
  eventTime,
  eventName,
  recipientAccountId AS resource_account_id,
  userIdentity.accountId AS principal_account_id,
  userIdentity.arn AS principal_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  COALESCE(errorCode, 'ALLOWED') AS result,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND userIdentity.type <> 'AWSService'
  AND COALESCE(userIdentity.accountId, '') NOT IN ('111122223333', '444455556666')
ORDER BY eventTime DESC
LIMIT 1000;
```

**CT.S3.PV.2**: requests not authenticated with the `Authorization` header. S3 records `additionalEventData.AuthenticationMethod` as `AuthHeader` for header-signed requests and `QueryString` for presigned URLs. Treat any other value, or a missing value, as a candidate and confirm it with the workload owner. CloudTrail may not identify browser POST uploads reliably.

```sql
SELECT
  eventTime,
  eventName,
  recipientAccountId AS resource_account_id,
  userIdentity.arn AS principal_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  json_extract_scalar(additionalEventData, '$.AuthenticationMethod') AS auth_method,
  COALESCE(errorCode, 'ALLOWED') AS result,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND COALESCE(json_extract_scalar(additionalEventData, '$.AuthenticationMethod'), 'none') <> 'AuthHeader'
ORDER BY eventTime DESC
LIMIT 1000;
```

**CT.S3.PV.3**: requests that used a TLS version older than 1.3. This query skips events with no TLS details; CT.S3.PV.5 covers those.

```sql
SELECT
  tlsDetails.tlsVersion AS tls_version,
  userIdentity.arn AS principal_arn,
  userAgent,
  eventName,
  COALESCE(errorCode, 'ALLOWED') AS result,
  COUNT(*) AS event_count
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND tlsDetails.tlsVersion IS NOT NULL
  AND tlsDetails.tlsVersion <> 'TLSv1.3'
GROUP BY 1, 2, 3, 4, 5
ORDER BY event_count DESC
LIMIT 1000;
```

The `userAgent` column shows which SDK or client needs upgrading.

**CT.S3.PV.5**: possible plain-HTTP requests. CloudTrail has no field that marks HTTP directly, so this query lists requests from non-AWS-service callers that have no TLS details. As noted in section 2, missing TLS details are not proof of HTTP. Confirm each caller with its owner.

```sql
SELECT
  userIdentity.arn AS principal_arn,
  userIdentity.invokedBy AS invoked_by_service,
  userAgent,
  sourceIPAddress,
  eventName,
  COALESCE(errorCode, 'ALLOWED') AS result,
  COUNT(*) AS event_count
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND tlsDetails.tlsVersion IS NULL
  AND userIdentity.type <> 'AWSService'
GROUP BY 1, 2, 3, 4, 5, 6
ORDER BY event_count DESC
LIMIT 1000;
```

**CT.S3.PV.6**: uploads that did not name a KMS key in the request. The query also shows the encryption S3 recorded in the response, where available. An upload without a key ID in the request is still allowed if the bucket's default encryption is SSE-KMS, so check each bucket with `get-bucket-encryption` (see section 2).

```sql
SELECT
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  userIdentity.arn AS principal_arn,
  userIdentity.invokedBy AS invoked_by_service,
  eventName,
  json_extract_scalar(responseElements, '$["x-amz-server-side-encryption"]') AS encryption_applied,
  COALESCE(errorCode, 'ALLOWED') AS result,
  COUNT(*) AS event_count
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-01T00:00:00Z'
  AND eventTime <  '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutObject', 'CreateMultipartUpload')
  AND json_extract_scalar(requestParameters, '$["x-amz-server-side-encryption-aws-kms-key-id"]') IS NULL
GROUP BY 1, 2, 3, 4, 5, 6
ORDER BY event_count DESC
LIMIT 1000;
```

Unlike the identity-perimeter controls, this control has no exception for AWS services. Uploads from services such as CloudTrail and AWS Config (`invoked_by_service`) are denied too, unless the bucket defaults to SSE-KMS or its ARN is in `s3_sse_kms_exempted_resource_arns`.

### After rollout: find RCP denials

After you attach the RCPs, search for access-denied errors. For services that include policy details in access-denied messages, the message names the policy type, for example `... with an explicit deny in a resource control policy`. That wording separates RCP denials from other failures. A service that returns only a generic `AccessDenied` won't match this filter, so also review any new `AccessDenied` errors since the attachment time.

With the AWS CLI (management events only), repeat for each control's event source or event name:

```sh
ct_lookup EventSource kms.amazonaws.com | grep -i 'resource control policy'
```

With Athena (management and data events):

```sql
SELECT
  eventTime,
  eventSource,
  eventName,
  recipientAccountId AS resource_account_id,
  userIdentity.arn AS principal_arn,
  errorCode,
  errorMessage
FROM cloudtrail_logs.organization_events
WHERE eventTime >= '2026-09-30T00:00:00Z'
  AND recipientAccountId IN ('111122223333', '444455556666')
  AND errorMessage LIKE '%resource control policy%'
ORDER BY eventTime DESC
LIMIT 1000;
```

Set the start time to when the policies were attached. Match each denial to a control by the event source and the checks above, then either fix the caller or add a targeted exemption.

## Review and report

For each candidate, capture the timestamp, Region, resource account and ARN, principal ARN and account, service caller (if any), API action, error details, and application owner. Confirm whether the principal is in the organization, in an explicitly trusted organization, an AWS service principal, or needs a control-specific exemption. Validate required S3 workflows, including presigned uploads, TLS clients, HTTP use, and SSE-KMS defaults.

A query returning no rows does not prove a control is safe to enable. It may mean that the activity did not occur during the window, that the trail did not cover the account/Region/resource, that data events were not enabled, or that the relevant request context is not captured in the event. Test the controls on a sandbox OU and monitor new `AccessDenied` errors after rollout.

## AWS references

- [CloudTrail Event history limitations](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html#event-history-limitations)
- [AWS CLI `lookup-events`](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html)
- [Logging CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [CloudTrail Lake availability change](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html)
- [Querying CloudTrail logs with Athena](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Identifying S3 requests with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-request-identification.html)
- [Logging SQS API calls with CloudTrail](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-logging-using-cloudtrail.html)
- [Logging KMS API calls with CloudTrail](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)
