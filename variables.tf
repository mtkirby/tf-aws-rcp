variable "aws_region" {
  description = "Region for the AWS provider. AWS Organizations is global; this only selects the API endpoint."
  type        = string
  default     = "us-east-1"
}

variable "target_ids" {
  description = "Organization root (r-...), OU (ou-...) or account IDs to attach the RCPs to. RCPs never apply to the management account."
  type        = list(string)

  validation {
    condition = length(var.target_ids) > 0 && alltrue([
      for id in var.target_ids : can(regex("^(r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|[0-9]{12})$", id))
    ])
    error_message = "Provide at least one target ID, and ensure each is an organization root ID (r-...), an OU ID (ou-...-...) or a 12-digit account ID."
  }
}

variable "enabled_controls" {
  description = "Control Tower RCP control IDs to include. Remove IDs to stage a rollout."
  type        = set(string)
  default = [
    "CT.KMS.PV.7",
    "CT.S3.PV.2",
    "CT.S3.PV.3",
    "CT.S3.PV.4",
    "CT.S3.PV.5",
    "CT.S3.PV.6",
    "CT.SECRETSMANAGER.PV.1",
    "CT.SQS.PV.1",
    "CT.STS.PV.1",
  ]

  validation {
    condition = alltrue([
      for id in var.enabled_controls : contains([
        "CT.KMS.PV.7", "CT.S3.PV.2", "CT.S3.PV.3", "CT.S3.PV.4", "CT.S3.PV.5", "CT.S3.PV.6",
        "CT.SECRETSMANAGER.PV.1", "CT.SQS.PV.1", "CT.STS.PV.1",
      ], id)
    ])
    error_message = "enabled_controls contains an unsupported control ID."
  }
}

variable "enable_rcp_full_org_restrict" {
  description = "Create and attach RCPFullOrgRestrict, which denies every action on every RCP-supported service to principals outside the organization (AWS services excepted). Off by default; see the README before enabling."
  type        = bool
  default     = false
}

variable "full_org_restrict_services" {
  description = "Service prefixes that RCPFullOrgRestrict denies to principals outside the organization, each rendered as \"<prefix>:*\". STS is always included, limited to sts:AssumeRole and sts:SetContext, so it must not be listed here. The default is the AWS list of RCP-supported services as of 2026-10-01, minus cognito-identity, cognito-idp, rolesanywhere, signin and ecr-public (see the README)."
  type        = list(string)
  default = [
    "aoss", "appconfig", "appstream", "autoscaling", "autoscaling-plans", "budgets", "clouddirectory",
    "cloudfront", "cloudsearch", "cloudtrail-data", "codeartifact", "codebuild", "codecommit",
    "codepipeline", "comprehend", "comprehendmedical", "compute-optimizer", "cost-optimization-hub",
    "dax", "dsql", "dynamodb", "ecr", "events", "firehose", "fis", "fms", "gamelift", "health",
    "inspector-scan", "kendra", "kinesisvideo", "kms", "logs", "memorydb", "networkmonitor",
    "notifications", "opensearch", "pca-connector-ad", "personalize", "polly", "pricing",
    "resource-groups", "s3", "secretsmanager", "servicediscovery", "sqs", "support", "swf",
    "textract", "timestream-influxdb", "transcribe", "transfer", "translate", "wafv2", "workspaces",
    "xray",
  ]

  validation {
    condition     = length(var.full_org_restrict_services) > 0 && alltrue([for svc in var.full_org_restrict_services : can(regex("^[a-z0-9-]+$", svc))])
    error_message = "List at least one service, each as a lowercase service prefix such as \"s3\" or \"dynamodb\" (no \"*\" or \":\")."
  }

  validation {
    condition     = !contains(var.full_org_restrict_services, "sts")
    error_message = "Don't list \"sts\": sts:* would deny SAML and OIDC federation. RCPFullOrgRestrict always covers sts:AssumeRole and sts:SetContext."
  }
}

variable "enable_rcp_bypass_tag" {
  description = "Let resources tagged BypassRCP = True skip every RCP statement in this repo. Works only where the service exposes aws:ResourceTag for the request; S3 buckets also need ABAC enabled. Elsewhere the RCPs still apply."
  type        = bool
  default     = false
}

variable "additional_trusted_organization_ids" {
  description = "Organization IDs, besides this one, whose principals may access resources under the identity-perimeter controls (the OrganizationIds parameter)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.additional_trusted_organization_ids : can(regex("^o-[a-z0-9]{10,32}$", id))])
    error_message = "Organization IDs must match o-xxxxxxxxxx."
  }
}

variable "exempted_principal_arns" {
  description = "Per-control ExemptedPrincipalArns, keyed by control ID or \"RCPFullOrgRestrict\". Wildcards are allowed (ArnNotLike), e.g. arn:aws:iam::*:role/BreakGlass."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for id in keys(var.exempted_principal_arns) : contains([
        "CT.KMS.PV.7", "CT.S3.PV.2", "CT.S3.PV.3", "CT.S3.PV.4", "CT.S3.PV.5", "CT.S3.PV.6",
        "CT.SECRETSMANAGER.PV.1", "CT.SQS.PV.1", "CT.STS.PV.1", "RCPFullOrgRestrict",
      ], id)
    ])
    error_message = "exempted_principal_arns keys must be supported control IDs or \"RCPFullOrgRestrict\"."
  }
}

variable "s3_sse_kms_exempted_resource_arns" {
  description = "ExemptedResourceArns for CT.S3.PV.6: S3 bucket/object ARNs that may receive uploads without SSE-KMS (rendered as NotResource)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.s3_sse_kms_exempted_resource_arns : startswith(arn, "arn:")])
    error_message = "Exempted resource ARNs must be full ARNs, e.g. arn:aws:s3:::my-bucket/*."
  }
}

variable "policy_name_prefix" {
  description = "Prefix for the RCP names."
  type        = string
  default     = "ct-rcp"
}

variable "tags" {
  description = "Tags applied to the RCPs."
  type        = map(string)
  default     = {}
}
