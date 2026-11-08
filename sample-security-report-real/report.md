# AWS security baseline check - account Demo sandbox (deliberately misconfigured)

> **SYNTHETIC DEMO DATA.** DEMO ACCOUNT - a real AWS sandbox deliberately misconfigured with Terraform (demo-account/ in this repo), fake secrets only, destroyed right after the scan.

- Regions: ap-southeast-2
- Scanned: 2026-11-08 17:20 UTC
- **Score: 12/100 (grade F)** - coverage 82%
- Controls: 16 failing, 2 passing, 3 not applicable, 0 to review, 4 not evaluated

## Top risks

| Severity | Control | Finding | First step |
|---|---|---|---|
| critical | **NC-01** No SSH, RDP or database port is open to the whole internet | Security group acme-demo-1107-legacy-admin (sg-0f589326b0d3de0db) has SSH port 22 open to the Internet. (+1 more) | `aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0` |
| critical | **SP-01** No secrets in Lambda variables, EC2 user data or launch templates | Potential secret found in Lambda function acme-demo-1107-invoice-mailer variables -> Generic Password in variable SMTP_PASSWORD, SMTP Credentials in variable SMTP_PASSWORD. (+1 more) | `Move each value to Secrets Manager or SSM Parameter Store (SecureString), read it at runtime, then rotate it - it must be treated as exposed.` |
| critical | **DA-01** S3 Block Public Access is on for the whole account | Block Public Access is not configured for the account 453348321107. | `module.security_baseline: s3_account_public_access_block = true` |
| critical | **DA-02** No bucket is public | S3 Bucket acme-demo-453348321107-uploads has public access due to bucket policy. | `aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` |
| critical | **LD-01** CloudTrail records every region, with tamper-evident, private logs | No CloudTrail trails enabled with logging were found. | `module.security_baseline: cloudtrail = true   # multi-region trail, log-file validation, private encrypted bucket` |

## All controls

| Status | ID | Control | Severity | Result |
|---|---|---|---|---|
| Not evaluated | ID-01 | Root user is protected (MFA on, no access keys) | critical | not evaluated (the scanner returned no result - see Method) |
| Pass | ID-02 | Every console user has MFA | high | 2 items checked, all passing |
| Pass | ID-03 | Access keys are rotated and unused keys removed | high | 8 items checked, all passing |
| Fail | ID-04 | People get permissions through groups, roles or SSO - not attached to users | medium | 2 failing items |
| Fail | ID-05 | Full administrator rights are limited to a break-glass role | high | 1 failing item, 11 passing |
| Fail | ID-06 | Password policy requires long, non-reused passwords | low | 2 failing items |
| Not evaluated | ID-07 | IAM Access Analyzer watches for external access | medium | not evaluated (the scanner returned no result - see Method) |
| Fail | LD-01 | CloudTrail records every region, with tamper-evident, private logs | critical | 1 failing item |
| Not evaluated | LD-02 | GuardDuty threat detection is on | high | not evaluated (the scanner returned no result - see Method) |
| Fail | LD-03 | AWS Config records configuration changes | medium | 1 failing item |
| Fail | LD-04 | Log groups keep logs for at least a year | medium | 1 failing item |
| Fail | LD-05 | Spend alerts would catch abuse within a day | medium | 1 failing item |
| Fail | DA-01 | S3 Block Public Access is on for the whole account | critical | 1 failing item |
| Fail | DA-02 | No bucket is public | critical | 1 failing item, 3 passing |
| Fail | DA-03 | Data is encrypted by default (S3 and EBS) | medium | 1 failing item, 1 passing |
| No resources | DA-04 | Databases are encrypted, private, backed up and protected from deletion | high | no matching resources in the scanned regions |
| No resources | DA-05 | No snapshot is public | critical | no matching resources in the scanned regions |
| Fail | NC-01 | No SSH, RDP or database port is open to the whole internet | critical | 2 failing items, 3 passing |
| No resources | NC-02 | Default security groups allow no traffic | low | no matching resources in the scanned regions |
| Fail | NC-03 | Instances require IMDSv2 | high | 2 failing items |
| Fail | NC-04 | Only intended instances have public IP addresses | medium | 1 failing item |
| Fail | SP-01 | No secrets in Lambda variables, EC2 user data or launch templates | critical | 2 failing items |
| Fail | SP-02 | Secrets Manager secrets rotate automatically | medium | 1 failing item |
| Not evaluated | SP-03 | CI/CD logs in with short-lived OIDC credentials, not stored keys | high | not evaluated (the scanner returned no result - see Method) |
| Fail | SP-04 | Container images are scanned on push and tags are immutable | low | 3 failing items |

## Checks that could not run

- native:ci_oidc in global: AccessDenied: User: arn:aws:sts::453348321107:assumed-role/AccountFullAccessRole/643884c8-9031-70eb-357b-85ffbc64df15 is not authorized to perform: iam:ListOpenIDConnectProviders on resource: arn:aws:iam::453348321107:oidc-provider/* with an explicit deny in a service control policy: arn:aws:organiz

## Method

Read-only role (SecurityAudit + ViewOnlyAccess, explicit deny on data reads); engine Prowler 5.47.0; every finding reviewed by a person. Findings reflect the configuration at scan time; this is not a penetration test or a guarantee.
