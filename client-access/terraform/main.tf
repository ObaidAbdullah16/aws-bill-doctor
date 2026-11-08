# Same read-only audit role as the CloudFormation template, for clients who use Terraform.
# Copy the whole aws-bill-doctor folder (this file reads the JSON policies in ../../policies/).
# enable_security_check = true adds the security baseline check (service S8) to the cost audit (S1).
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "auditor_account_id" {
  description = "AWS account ID of the auditor (given to you with this module)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.auditor_account_id))
    error_message = "auditor_account_id must be a 12-digit AWS account ID."
  }
}

variable "external_id" {
  description = "Shared secret given to you by the auditor (prevents the confused-deputy problem)."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "external_id must be at least 16 characters."
  }
}

variable "allow_cost_explorer" {
  description = "Allow reading the spend-by-service summary from Cost Explorer."
  type        = bool
  default     = false
}

variable "enable_security_check" {
  description = "Also allow the security baseline check: AWS-managed SecurityAudit + ViewOnlyAccess and a few extra reads."
  type        = bool
  default     = false
}

data "aws_partition" "current" {}

locals {
  policy          = jsondecode(file("${path.module}/../../policies/billdoctor-readonly.json"))
  security_policy = jsondecode(file("${path.module}/../../policies/security-check-readonly.json"))
  deny_data       = [for s in local.security_policy.Statement : s if s.Sid == "DenyReadingData"]
  security_extras = [for s in local.security_policy.Statement : s if s.Sid == "SecurityCheckExtraReads"]

  # The Cost Explorer statement is only included when the client opts in (same as the CloudFormation template).
  statements = [
    for s in local.policy.Statement : s
    if var.allow_cost_explorer || s.Sid != "OptionalCostExplorer"
  ]
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.auditor_account_id}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "billdoctor" {
  name                 = "BillDoctorReadOnly"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = { Purpose = var.enable_security_check ? "cost-and-security-audit" : "cost-audit", DeleteAfter = "audit-complete" }
}

resource "aws_iam_role_policy" "readonly" {
  name   = "billdoctor-readonly"
  role   = aws_iam_role.billdoctor.id
  policy = jsonencode({ Version = local.policy.Version, Statement = local.statements })
}

# Always attached: the role can never read data, whatever else is attached to it.
resource "aws_iam_role_policy" "never_read_data" {
  name   = "never-read-data"
  role   = aws_iam_role.billdoctor.id
  policy = jsonencode({ Version = local.security_policy.Version, Statement = local.deny_data })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  for_each = var.enable_security_check ? toset(["SecurityAudit", "job-function/ViewOnlyAccess"]) : toset([])

  role       = aws_iam_role.billdoctor.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.value}"
}

resource "aws_iam_role_policy" "security_extras" {
  count = var.enable_security_check ? 1 : 0

  name   = "security-check-extra-reads"
  role   = aws_iam_role.billdoctor.id
  policy = jsonencode({ Version = local.security_policy.Version, Statement = local.security_extras })
}

output "role_arn" {
  description = "Send this ARN to the auditor."
  value       = aws_iam_role.billdoctor.arn
}
