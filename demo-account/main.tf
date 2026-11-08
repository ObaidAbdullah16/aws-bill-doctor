# DELIBERATELY MISCONFIGURED demo account for the security baseline check (service S8).
#
# Run it ONLY in an empty sandbox account (see README.md). The provider refuses any other
# account ID. Everything here is cheap, contains no real data and fake secrets only, and is
# destroyed right after the scan by run-demo.sh (about $0.05 per run).
#
# Each resource is wrong on purpose; the comment says which control it trips.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70"
    }
  }
}

variable "sandbox_account_id" {
  description = "12-digit ID of the EMPTY sandbox account. Terraform refuses to touch any other account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "sandbox_account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "Region for the demo resources."
  type        = string
  default     = "ap-southeast-2"
}

variable "include_rds" {
  description = "Also create a small unencrypted RDS instance (adds about $0.02/hour and 10 minutes)."
  type        = bool
  default     = false
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.sandbox_account_id] # hard stop: never runs in your main account

  default_tags {
    tags = {
      Purpose     = "security-check-demo"
      Synthetic   = "true"
      DeleteAfter = "the-scan"
    }
  }
}

data "aws_partition" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_caller_identity" "current" {}

locals {
  name = "acme-demo-${substr(data.aws_caller_identity.current.account_id, 8, 4)}"
  fake = "demo-only-not-a-real-secret" # every "secret" below is this string
}

# ---------------------------------------------------------------- identity (ID-04, ID-05, ID-06, SP-03)
# A legacy admin user with no credentials at all: AdministratorAccess attached directly to a user.
resource "aws_iam_user" "legacy_admin" {
  name = "${local.name}-legacy-admin"
}

resource "aws_iam_user_policy_attachment" "legacy_admin" {
  user       = aws_iam_user.legacy_admin.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

# A "CI" user with an access key - but the key is useless: an inline policy denies everything.
resource "aws_iam_user" "ci" {
  name = "${local.name}-ci-deploy"
}

resource "aws_iam_user_policy" "ci_deny_all" {
  name = "deny-everything"
  user = aws_iam_user.ci.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

# ---------------------------------------------------------------- logging (LD-01..LD-04)
# No CloudTrail trail, no GuardDuty, no AWS Config: a new account has none of them.
resource "aws_cloudwatch_log_group" "api" {
  name              = "/${local.name}/api"
  retention_in_days = 7 # LD-04: gone before anyone investigates
}

# ---------------------------------------------------------------- data (DA-01, DA-02, DA-04)
resource "aws_s3_account_public_access_block" "off" {
  block_public_acls       = false # DA-01: the account-wide safety switch is off
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "uploads" {
  bucket        = "acme-demo-${data.aws_caller_identity.current.account_id}-uploads"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "uploads_public" {
  bucket     = aws_s3_bucket.uploads.id
  depends_on = [aws_s3_bucket_public_access_block.uploads, aws_s3_account_public_access_block.off]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadOfAnEmptyPrefix" # DA-02: the bucket is empty; the policy is the finding
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.uploads.arn}/public/*"
    }]
  })
}

resource "aws_db_instance" "db" {
  count                   = var.include_rds ? 1 : 0
  identifier              = "${local.name}-db"
  engine                  = "postgres"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  username                = "acme"
  password                = "${local.fake}-1A"
  storage_encrypted       = false # DA-04
  backup_retention_period = 0     # DA-04
  deletion_protection     = false # DA-04
  publicly_accessible     = false
  skip_final_snapshot     = true
}

# ---------------------------------------------------------------- network and compute (NC-01, NC-03, NC-04, SP-01)
resource "aws_security_group" "legacy" {
  name        = "${local.name}-legacy-admin"
  description = "Deliberately open demo group"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "NC-01: SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "NC-01: Postgres from anywhere (nothing listens on it)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "legacy_api" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.legacy.id]
  associate_public_ip_address = true # NC-04

  metadata_options {
    http_tokens   = "optional" # NC-03: IMDSv1 still allowed
    http_endpoint = "enabled"
  }

  # SP-01: a "password" in user data (fake). The instance does nothing else.
  user_data = "#!/bin/bash\nexport DB_PASSWORD='${local.fake}'\n"

  tags = { Name = "${local.name}-legacy-api" }
}

# ---------------------------------------------------------------- secrets and pipelines (SP-01, SP-02, SP-04)
resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_lambda_function" "mailer" {
  function_name    = "${local.name}-invoice-mailer"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "app.handler"
  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")

  environment {
    variables = {
      SMTP_PASSWORD = "Demo-Only-Smtp-Passw0rd-NotReal" # SP-01
    }
  }
}

resource "aws_secretsmanager_secret" "db" {
  name                    = "${local.name}/db"
  recovery_window_in_days = 0 # deleted immediately on destroy
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = local.fake # SP-02: never rotated
}

resource "aws_ecr_repository" "api" {
  name                 = "${local.name}/api"
  image_tag_mutability = "MUTABLE" # SP-04
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false # SP-04
  }
}

output "created" {
  description = "What the scan should find."
  value = {
    users          = [aws_iam_user.legacy_admin.name, aws_iam_user.ci.name]
    public_bucket  = aws_s3_bucket.uploads.bucket
    instance       = aws_instance.legacy_api.id
    security_group = aws_security_group.legacy.id
    lambda         = aws_lambda_function.mailer.function_name
    rds            = var.include_rds ? aws_db_instance.db[0].identifier : "not created"
  }
}
