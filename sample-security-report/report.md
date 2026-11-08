# AWS security baseline check - account Acme Retail (synthetic demo)

> **SYNTHETIC DEMO DATA.** real Prowler checks run against a simulated AWS account (moto) seeded with a fictional company's typical mistakes. No customer data.

- Regions: ap-south-1
- Scanned: 2026-11-02 11:39 UTC
- **Score: 31/100 (grade F)** - coverage 83%
- Controls: 15 failing, 6 passing, 1 not applicable, 0 to review, 3 not evaluated

## Top risks

| Severity | Control | Finding | First step |
|---|---|---|---|
| critical | **DA-02** No bucket is public | S3 Bucket acme-demo-uploads has public access due to bucket policy. | `aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` |
| critical | **NC-01** No SSH, RDP or database port is open to the whole internet | Security group api (sg-1c5d8088dba90bc1a) has SSH port 22 open to the Internet. | `aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0` |
| critical | **SP-01** No secrets in Lambda variables, EC2 user data or launch templates | Potential secret found in Lambda function acme-invoice-mailer variables -> SMTP Credentials in variable SMTP_PASSWORD, Generic Password in variable SMTP_PASSWORD. | `Move each value to Secrets Manager or SSM Parameter Store (SecureString), read it at runtime, then rotate it - it must be treated as exposed.` |
| high | **ID-02** Every console user has MFA | User priya.sharma has Console Password enabled but MFA disabled. | `aws iam list-virtual-mfa-devices  # find users without a device, then enable MFA for each, or move people to IAM Identity Center` |
| high | **ID-05** Full administrator rights are limited to a break-glass role | AWS policy AdministratorAccess is attached and allows '*:*' administrative privileges. | `aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` |

## All controls

| Status | ID | Control | Severity | Result |
|---|---|---|---|---|
| Not evaluated | ID-01 | Root user is protected (MFA on, no access keys) | critical | not evaluated (the scanner returned no result - see Method) |
| Fail | ID-02 | Every console user has MFA | high | 1 failing item, 1 passing |
| Pass | ID-03 | Access keys are rotated and unused keys removed | high | 6 items checked, all passing |
| Fail | ID-04 | People get permissions through groups, roles or SSO - not attached to users | medium | 1 failing item, 1 passing |
| Fail | ID-05 | Full administrator rights are limited to a break-glass role | high | 1 failing item, 1 passing |
| Pass | ID-06 | Password policy requires long, non-reused passwords | low | 2 items checked, all passing |
| Not evaluated | ID-07 | IAM Access Analyzer watches for external access | medium | not evaluated (the scanner returned no result - see Method) |
| Pass | LD-01 | CloudTrail records every region, with tamper-evident, private logs | critical | 3 items checked, all passing |
| Fail | LD-02 | GuardDuty threat detection is on | high | 1 failing item |
| Fail | LD-03 | AWS Config records configuration changes | medium | 1 failing item |
| Fail | LD-04 | Log groups keep logs for at least a year | medium | 1 failing item, 1 passing |
| Pass | LD-05 | Spend alerts would catch abuse within a day | medium | 1 item checked, all passing |
| Not evaluated | DA-01 | S3 Block Public Access is on for the whole account | critical | not evaluated (the scanner returned no result - see Method) |
| Fail | DA-02 | No bucket is public | critical | 1 failing item, 11 passing |
| Fail | DA-03 | Data is encrypted by default (S3 and EBS) | medium | 1 failing item, 3 passing |
| Pass | DA-04 | Databases are encrypted, private, backed up and protected from deletion | high | 4 items checked, all passing |
| Pass | DA-05 | No snapshot is public | critical | 4 items checked, all passing |
| Fail | NC-01 | No SSH, RDP or database port is open to the whole internet | critical | 1 failing item, 4 passing |
| No resources | NC-02 | Default security groups allow no traffic | low | no matching resources in the scanned regions |
| Fail | NC-03 | Instances require IMDSv2 | high | 1 failing item |
| Fail | NC-04 | Only intended instances have public IP addresses | medium | 1 failing item |
| Fail | SP-01 | No secrets in Lambda variables, EC2 user data or launch templates | critical | 1 failing item, 1 passing |
| Fail | SP-02 | Secrets Manager secrets rotate automatically | medium | 1 failing item |
| Fail | SP-03 | CI/CD logs in with short-lived OIDC credentials, not stored keys | high | 1 failing item |
| Fail | SP-04 | Container images are scanned on push and tags are immutable | low | 3 failing items |

## Method

Read-only role (SecurityAudit + ViewOnlyAccess, explicit deny on data reads); engine Prowler 5.47.0; every finding reviewed by a person. Findings reflect the configuration at scan time; this is not a penetration test or a guarantee.
- Note: Not evaluated in the simulator (ID-01, ID-07, DA-01): it has no root user, IAM Access Analyzer or account-level S3 settings. A scan of a real account evaluates them.
