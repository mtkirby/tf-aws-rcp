# AWS services that support RCPs

This document lists every AWS service that supports resource control policies (RCPs): 62 services as of 2026-10-01. For each one it explains what's at risk if `RCPFullOrgRestrict` doesn't cover the service, and what can break when it does. Use it to decide what goes in `full_org_restrict_services`.

Sources: the AWS Organizations [list of services that support RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services), the [AWS service reference data](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html) (actions, resource types and condition keys), and the AWS RAM [list of shareable resources](https://docs.aws.amazon.com/ram/latest/userguide/shareable.html). Both lists change as AWS adds features, so recheck them before relying on this.

## How to read this

**The full org restriction** is the optional `RCPFullOrgRestrict` policy in this repo. For each service in `full_org_restrict_services` it denies `<prefix>:*` to any principal outside your organization, unless the caller is an AWS service, is in `additional_trusted_organization_ids` or `exempted_principal_arns["RCPFullOrgRestrict"]`, or the resource has the `BypassRCP` tag.

**Risk without it** means what an outside principal could reach if something grants them access: a resource policy, a sharing feature, or a mistake in either. The RCP is the backstop that still blocks them.

An outsider needs a way in before the RCP matters. Services fall into three groups:

- **Services with resource policies or cross-account sharing.** A policy or share can name another account, or everyone. These carry real risk without the restriction.
- **Services with neither.** The only way in is to assume a role in your account. The STS actions in `RCPFullOrgRestrict`, and CT.STS.PV.1, already stop outsiders from doing that, so the remaining risk is low. Covering these services is defense in depth, in case AWS adds a sharing feature later.
- **Services with no resource-level actions.** RCPs only apply to actions that authorize a specific resource, so these services aren't affected at all.

Ratings used below:

| Rating | Meaning |
|---|---|
| High | A resource policy or share can give outsiders direct access to your data, credentials or deployment pipeline |
| Medium | Outsiders can be given access to configuration, images, metadata, or the ability to send data in |
| Low | No resource policy or sharing feature found; outsiders can only get in through a role in your account |
| None | The service has no actions RCPs apply to |

## Caveats for every service

- **Only resource-level actions are covered.** RCPs apply to actions that authorize a specific resource, the ones with a resource type in the Service Authorization Reference. Actions without a resource type aren't restricted. The appendix shows how many actions each service has of each kind.
- **Some things are never restricted.** RCPs don't apply to resources in the management account, to calls made by service-linked roles, to AWS managed KMS keys, or to `kms:RetireGrant`.
- **AWS services are let through.** Calls made directly by an AWS service principal are allowed (`aws:PrincipalIsAWSService`). That keeps service integrations working, but it doesn't stop a service being used as a confused deputy for another account. Use `aws:SourceAccount` or `aws:SourceOrgID` in resource policies for that.
- **Your own stolen credentials aren't blocked.** Credentials taken from a principal in your organization carry your organization ID, so the identity perimeter lets them through. Network-based conditions (`aws:SourceIp`, `aws:SourceVpc`) address that, but they aren't part of this repo.
- **Calls made without AWS credentials are denied.** Anonymous requests, SAML and OIDC sign-in calls, and certificate-based sign-in carry no organization ID, so a deny on those actions blocks them. That's why `RCPFullOrgRestrict` covers only `sts:AssumeRole` and `sts:SetContext` in STS, and why a few services are left out of the default list.
- **The bypass tag only works where the service exposes resource tags.** The appendix shows, per service, how many of the restricted actions honor `BypassRCP`. Where it doesn't work, the deny still applies.
- **Each service costs space.** Each one adds about 15 characters to a policy capped at 5,120. The default list uses about 1,100.

## Summary

| Rating | Services |
|---|---|
| High (11) | S3, KMS, Secrets Manager, SQS, STS, DynamoDB, ECR, EventBridge, CodeArtifact, CloudSearch, OpenSearch Serverless |
| Medium (11) | CloudWatch Logs, CodeBuild, CloudFront, Comprehend, Cloud Map, WAF, AppStream 2.0, WorkSpaces, Resource Groups, X-Ray, CloudTrail Data |
| Left out of the default list (5) | Cognito identity pools, Cognito user pools, IAM Roles Anywhere, AWS Sign-In, ECR Public |
| Low (28) | Everything else with resource-level actions |
| None (7) | Comprehend Medical, Inspector Scan, Auto Scaling plans, Compute Optimizer, Cost Optimization Hub, Pricing Calculator, Support |

## High risk

These services let a resource policy or share grant another account, or everyone, direct access. The first five are also covered by the Control Tower controls in this repo.

| Service | How outsiders can be let in | Risk without the restriction | What can break when restricted |
|---|---|---|---|
| Amazon S3 (`s3`) | Bucket and access point policies, ACLs, S3 Access Grants (shareable through RAM, including outside the organization) | Outsiders or the public read, overwrite or delete data. This is the most common cause of cloud data exposure. Also covered by CT.S3.PV.4. | Public buckets and websites; partners reading or writing your buckets; replication into your buckets from accounts outside the organization. Use the bypass tag or an exemption for the ones that need it. |
| AWS KMS (`kms`) | Key policies and grants | Outsiders encrypt or decrypt with your key. A key protects everything encrypted with it, so this exposes all of that data. Also covered by CT.KMS.PV.7. | Sharing encrypted snapshots, AMIs or S3 objects with accounts outside the organization, because they need your key to read them. |
| AWS Secrets Manager (`secretsmanager`) | Secret resource policies | Outsiders read credentials and use them to reach databases and other systems. Also covered by CT.SECRETSMANAGER.PV.1. | Vendors or partners that read secrets directly from your accounts. |
| Amazon SQS (`sqs`) | Queue policies | Outsiders read or delete messages, or inject messages into the workflows that consume the queue. Also covered by CT.SQS.PV.1. | Vendors and partner accounts that send to your queues. Deliveries from AWS services such as SNS, S3 event notifications and EventBridge come from service principals and keep working. |
| AWS STS (`sts`) | Role trust policies | Outsiders assume a role in your account and act as it, which reaches every service, including the ones rated Low here. Also covered by CT.STS.PV.1. | Vendor integrations that assume roles from their own accounts. SAML, OIDC and IAM Identity Center sign-in keep working, because only `AssumeRole` and `SetContext` are covered. |
| Amazon DynamoDB (`dynamodb`) | Resource-based policies on tables, indexes and streams | Outsiders read or change table data or read the stream. | Access granted to accounts outside the organization through table or stream policies. |
| Amazon ECR (`ecr`) | Repository and registry policies | Outsiders pull private images, which can contain code or embedded secrets, or push images into repositories you deploy from. | Customers or partners pulling your images. Test cross-account replication and pull-through cache with accounts outside the organization before enabling. |
| Amazon EventBridge (`events`) | Event bus policies; event buses are shareable through RAM, including outside the organization | Outsiders put events on your buses and trigger your rules and automation. | Event routing from accounts outside the organization. How RCPs treat SaaS partner event sources isn't confirmed, so test them before enabling. |
| AWS CodeArtifact (`codeartifact`) | Domain and repository permissions policies | Outsiders read private packages, or publish package versions your builds then install. | Package consumers outside the organization. |
| Amazon CloudSearch (`cloudsearch`) | Domain access policies, which can name accounts or IP ranges | Outsiders search or upload documents. | Search clients outside the organization. Requests allowed by IP range rather than an AWS identity carry no organization ID, so test them before enabling. |
| Amazon OpenSearch Serverless (`aoss`) | Data access policies on collections | Principals named in a data access policy read or write collection data. | Principals outside the organization in data access policies. Dashboards users who sign in through SAML aren't AWS principals; test that access before enabling. |

## Medium risk

These services can share configuration, images or metadata with other accounts, or let other accounts send data in.

| Service | How outsiders can be let in | Risk without the restriction | What can break when restricted |
|---|---|---|---|
| Amazon CloudWatch Logs (`logs`) | Resource policies and cross-account log destinations | Outsiders send data into your log destinations, polluting or flooding logs you rely on for audits. | Central logging that receives logs from accounts outside the organization. |
| AWS CodeBuild (`codebuild`) | Resource policies; projects and report groups are shareable through RAM, including outside the organization | Outsiders see build projects, build output and reports, which can include secrets printed in logs. | Projects and report groups shared outside the organization. |
| Amazon CloudFront (`cloudfront`) | Resource policies; VPC origins are shareable through RAM, including outside the organization | Outsiders point their own distributions at your private VPC origins. | VPC origins shared outside the organization. Viewer traffic isn't affected, because viewers don't call CloudFront APIs. |
| Amazon Comprehend (`comprehend`) | Resource policies on custom models | Outsiders copy your custom models. | Models shared with accounts outside the organization. |
| AWS Cloud Map (`servicediscovery`) | Resource policies; namespaces are shareable through RAM within the organization only | If a resource policy grants it, outsiders discover internal endpoints or register instances that redirect your traffic. | Access granted outside the organization through resource policies. |
| AWS WAF (`wafv2`) | Permission policies on rule groups | Outsiders use or inspect your rule groups, which shows what you protect against. | Rule groups shared outside the organization. |
| Amazon AppStream 2.0 (`appstream`) | Image permissions | Outsiders launch fleets from your images and any software, licenses or data in them. | Images shared outside the organization. |
| Amazon WorkSpaces (`workspaces`) | Image and connection alias permissions | Outsiders use your images or connection aliases. | Images or aliases shared outside the organization. |
| AWS Resource Groups (`resource-groups`) | Groups are shareable through RAM, including outside the organization | Outsiders see group membership or use shared groups, for example in License Manager. | Groups shared outside the organization. |
| AWS X-Ray (`xray`) | Resource policies | Outsiders send trace data into your account, adding noise and cost. | Trace data sent from outside the organization. |
| AWS CloudTrail Data (`cloudtrail-data`) | CloudTrail Lake channels, whose resource policy lets integration partners send events | Outsiders inject events into your CloudTrail Lake event data store. | CloudTrail Lake integrations with partners outside your organization. **This service is in the default list**, so remove it if you use those integrations. |

## Left out of the default list

These support RCPs, but `full_org_restrict_services` leaves them out by default. Their callers often have no AWS organization identity, so restricting them could break sign-in. Which of their calls RCPs evaluate isn't confirmed. Add them only after testing on a sandbox account.

| Service | Risk without the restriction | Why it's left out |
|---|---|---|
| Amazon Cognito identity pools (`cognito-identity`) | Low: no resource policies; outsiders can only call management APIs through roles in your account. | App users get AWS credentials through calls such as `GetId` and `GetCredentialsForIdentity`, which carry no AWS identity. |
| Amazon Cognito user pools (`cognito-idp`) | Low: no resource policies. | Sign-up and sign-in calls come from app users, not AWS principals. |
| IAM Roles Anywhere (`rolesanywhere`) | Low: no resource policies. | Workloads get sessions by authenticating with an X.509 certificate, not AWS credentials. |
| AWS Sign-In (`signin`) | Low to medium: has resource permission statements for its OAuth clients. | Console and CLI sign-in would be at risk. |
| Amazon ECR Public (`ecr-public`) | Low: public repositories are meant to be pulled by anyone, and pushing still needs permission in your account. | Restricting it would block public pulls. |

## Low risk

No resource policy or sharing feature turned up for these, so outsiders can only get in by assuming a role in your account, which the STS controls already block. Covering them protects you if AWS adds sharing later.

| Service | Notes |
|---|---|
| Amazon Aurora DSQL (`dsql`) | |
| Amazon Cloud Directory (`clouddirectory`) | The bypass tag doesn't work here. |
| Network Synthetic Monitor (`networkmonitor`) | |
| Amazon Data Firehose (`firehose`) | Cross-account delivery goes out from your stream; nothing grants outsiders access to it. |
| DynamoDB Accelerator (`dax`) | The bypass tag doesn't work here. |
| Amazon EC2 Auto Scaling (`autoscaling`) | |
| Amazon GameLift Servers (`gamelift`) | |
| Amazon Kendra (`kendra`) | |
| Amazon Kinesis Video Streams (`kinesisvideo`) | Viewers usually get credentials from your own Cognito identity pools, which are roles in your account and keep working. |
| Amazon MemoryDB (`memorydb`) | |
| Amazon Personalize (`personalize`) | |
| Amazon Polly (`polly`) | The bypass tag doesn't work here. |
| Amazon SWF (`swf`) | |
| Amazon Textract (`textract`) | |
| Amazon Timestream for InfluxDB (`timestream-influxdb`) | |
| Amazon Transcribe (`transcribe`) | |
| Amazon Translate (`translate`) | |
| AWS AppConfig (`appconfig`) | |
| AWS Budgets (`budgets`) | |
| AWS CodeCommit (`codecommit`) | Cross-account access goes through roles. |
| AWS CodePipeline (`codepipeline`) | Cross-account pipelines use roles in the other account. |
| AWS Firewall Manager (`fms`) | The administrator account is inside the organization. |
| AWS Fault Injection Service (`fis`) | |
| AWS Health (`health`) | The bypass tag doesn't work here. |
| Amazon OpenSearch Service (`opensearch`) | This prefix only covers OpenSearch applications and data sources. Domains use the `es` prefix, which doesn't support RCPs, so domain access policies aren't covered by any RCP. The bypass tag doesn't work here. |
| AWS Private CA Connector for AD (`pca-connector-ad`) | |
| AWS Transfer Family (`transfer`) | End users connect with SFTP, FTPS or AS2 credentials, not AWS ones, and the service acts through roles you give it. |
| AWS User Notifications (`notifications`) | |

## No effect

These services support RCPs but have no actions that authorize a specific resource, so an RCP doesn't restrict anything in them. They're in the default list and harmless there; removing them saves about 15 characters each.

Amazon Comprehend Medical (`comprehendmedical`), Amazon Inspector Scan (`inspector-scan`), AWS Auto Scaling plans (`autoscaling-plans`), AWS Compute Optimizer (`compute-optimizer`), AWS Cost Optimization Hub (`cost-optimization-hub`), AWS Pricing Calculator (`pricing`), AWS Support (`support`).

## Appendix: restricted actions and bypass tag support

Generated from the AWS service reference data on 2026-10-01. **Actions RCPs apply to** counts the actions with a resource type, out of all the service's actions. **Bypass tag works on** counts how many of those expose `aws:ResourceTag`, which the `BypassRCP` tag needs. For S3, the bucket also needs ABAC turned on.

| Service | Prefix | Actions RCPs apply to | Bypass tag works on |
|---|---|---|---|
| Amazon AppStream 2.0 | `appstream` | 59 of 89 | All |
| Amazon Aurora DSQL | `dsql` | 28 of 30 | All |
| Amazon Cloud Directory | `clouddirectory` | 60 of 66 | None |
| Amazon CloudFront | `cloudfront` | 101 of 173 | 67 of 101 |
| Amazon CloudSearch | `cloudsearch` | 32 of 32 | None |
| Amazon CloudWatch Logs | `logs` | 76 of 133 | All |
| Amazon Cognito identity pools | `cognito-identity` | 16 of 26 | All |
| Amazon Cognito user pools | `cognito-idp` | 98 of 129 | 97 of 98 |
| Amazon Comprehend | `comprehend` | 56 of 85 | All |
| Amazon Comprehend Medical | `comprehendmedical` | 0 of 25 | n/a |
| Amazon Data Firehose | `firehose` | 11 of 12 | All |
| Amazon DynamoDB | `dynamodb` | 66 of 79 | 60 of 66 |
| Amazon EC2 Auto Scaling | `autoscaling` | 44 of 68 | 42 of 44 |
| Amazon ECR | `ecr` | 35 of 60 | All |
| Amazon ECR Public | `ecr-public` | 22 of 23 | 19 of 22 |
| Amazon EventBridge | `events` | 59 of 74 | 33 of 59 |
| Amazon GameLift Servers | `gamelift` | 68 of 120 | All |
| Amazon Inspector Scan | `inspector-scan` | 0 of 1 | n/a |
| Amazon Kendra | `kendra` | 64 of 66 | All |
| Amazon Kinesis Video Streams | `kinesisvideo` | 43 of 46 | All |
| Amazon MemoryDB | `memorydb` | 40 of 47 | 38 of 40 |
| Amazon OpenSearch Serverless | `aoss` | 7 of 49 | 6 of 7 |
| Amazon OpenSearch Service (applications, data sources) | `opensearch` | 6 of 11 | None |
| Amazon Personalize | `personalize` | 63 of 83 | 51 of 63 |
| Amazon Polly | `polly` | 6 of 10 | None |
| Amazon S3 | `s3` | 165 of 180 | 147 of 165 |
| Amazon SQS | `sqs` | 19 of 20 | All |
| Amazon SWF | `swf` | 49 of 51 | All |
| Amazon Textract | `textract` | 9 of 25 | All |
| Amazon Timestream for InfluxDB | `timestream-influxdb` | 19 of 24 | All |
| Amazon Transcribe | `transcribe` | 22 of 51 | All |
| Amazon Translate | `translate` | 13 of 19 | All |
| Amazon WorkSpaces | `workspaces` | 72 of 103 | All |
| AWS AppConfig | `appconfig` | 47 of 58 | All |
| AWS Auto Scaling plans | `autoscaling-plans` | 0 of 6 | n/a |
| AWS Budgets | `budgets` | 12 of 13 | All |
| AWS Cloud Map | `servicediscovery` | 24 of 33 | All |
| AWS CloudTrail Data | `cloudtrail-data` | 1 of 1 | All |
| AWS CodeArtifact | `codeartifact` | 46 of 51 | 32 of 46 |
| AWS CodeBuild | `codebuild` | 50 of 67 | 42 of 50 |
| AWS CodeCommit | `codecommit` | 82 of 91 | All |
| AWS CodePipeline | `codepipeline` | 31 of 44 | All |
| AWS Compute Optimizer | `compute-optimizer` | 0 of 28 | n/a |
| AWS Cost Optimization Hub | `cost-optimization-hub` | 0 of 8 | n/a |
| AWS Fault Injection Service | `fis` | 24 of 29 | 22 of 24 |
| AWS Firewall Manager | `fms` | 22 of 42 | All |
| AWS Health | `health` | 2 of 14 | None |
| AWS KMS | `kms` | 45 of 56 | All |
| AWS Pricing Calculator | `pricing` | 0 of 5 | n/a |
| AWS Private CA Connector for AD | `pca-connector-ad` | 20 of 25 | All |
| AWS Resource Groups | `resource-groups` | 23 of 29 | All |
| AWS Secrets Manager | `secretsmanager` | 20 of 23 | All |
| AWS Sign-In | `signin` | 7 of 16 | None |
| AWS STS | `sts` | 8 of 16 | 6 of 8 |
| AWS Support | `support` | 0 of 39 | n/a |
| AWS Transfer Family | `transfer` | 57 of 71 | All |
| AWS User Notifications | `notifications` | 26 of 44 | 12 of 26 |
| AWS WAF | `wafv2` | 38 of 63 | 35 of 38 |
| AWS X-Ray | `xray` | 10 of 43 | All |
| DynamoDB Accelerator (DAX) | `dax` | 19 of 30 | None |
| IAM Roles Anywhere | `rolesanywhere` | 22 of 30 | All |
| Network Synthetic Monitor | `networkmonitor` | 10 of 12 | All |
