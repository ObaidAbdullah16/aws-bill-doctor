# AWS security baseline check - account Acme Retail (synthetic demo)

> **SYNTHETIC DEMO DATA.** real Prowler checks run against a simulated AWS account (moto) seeded with a fictional company's typical mistakes. No customer data.

- Regions: ap-south-1
- Scanned: 2026-11-02 11:39 UTC
- **Score: 97/100 (grade A)** - coverage 83%
- Controls: 1 failing, 20 passing, 1 not applicable, 0 to review, 3 not evaluated

## Top risks

| Severity | Control | Finding | First step |
|---|---|---|---|
| medium | **LD-03** AWS Config records configuration changes | AWS Config recorder 123456789012 is disabled. | `module.security_baseline: config_recorder = true` |

## All controls

| Status | ID | Control | Severity | Result |
|---|---|---|---|---|
| Not evaluated | ID-01 | Root user is protected (MFA on, no access keys) | critical | not evaluated (the scanner returned no result - see Method) |
| Pass | ID-02 | Every console user has MFA | high | 1 item checked, all passing |
| Pass | ID-03 | Access keys are rotated and unused keys removed | high | 3 items checked, all passing |
| Pass | ID-04 | People get permissions through groups, roles or SSO - not attached to users | medium | 1 item checked, all passing |
| Pass | ID-05 | Full administrator rights are limited to a break-glass role | high | 1 item checked, all passing |
| Pass | ID-06 | Password policy requires long, non-reused passwords | low | 2 items checked, all passing |
| Not evaluated | ID-07 | IAM Access Analyzer watches for external access | medium | not evaluated (the scanner returned no result - see Method) |
| Pass | LD-01 | CloudTrail records every region, with tamper-evident, private logs | critical | 3 items checked, all passing |
| Pass | LD-02 | GuardDuty threat detection is on | high | 1 item checked, all passing |
| Fail | LD-03 | AWS Config records configuration changes | medium | 1 failing item |
| Pass | LD-04 | Log groups keep logs for at least a year | medium | 3 items checked, all passing |
| Pass | LD-05 | Spend alerts would catch abuse within a day | medium | 1 item checked, all passing |
| Not evaluated | DA-01 | S3 Block Public Access is on for the whole account | critical | not evaluated (the scanner returned no result - see Method) |
| Pass | DA-02 | No bucket is public | critical | 12 items checked, all passing |
| Pass | DA-03 | Data is encrypted by default (S3 and EBS) | medium | 4 items checked, all passing |
| Pass | DA-04 | Databases are encrypted, private, backed up and protected from deletion | high | 4 items checked, all passing |
| Pass | DA-05 | No snapshot is public | critical | 4 items checked, all passing |
| Pass | NC-01 | No SSH, RDP or database port is open to the whole internet | critical | 5 items checked, all passing |
| No resources | NC-02 | Default security groups allow no traffic | low | no matching resources in the scanned regions |
| Pass | NC-03 | Instances require IMDSv2 | high | 1 item checked, all passing |
| Pass | NC-04 | Only intended instances have public IP addresses | medium | 1 item checked, all passing |
| Pass | SP-01 | No secrets in Lambda variables, EC2 user data or launch templates | critical | 2 items checked, all passing |
| Pass | SP-02 | Secrets Manager secrets rotate automatically | medium | 1 item checked, all passing |
| Pass | SP-03 | CI/CD logs in with short-lived OIDC credentials, not stored keys | high | 1 item checked, all passing |
| Pass | SP-04 | Container images are scanned on push and tags are immutable | low | 3 items checked, all passing |

## Method

Read-only role (SecurityAudit + ViewOnlyAccess, explicit deny on data reads); engine Prowler 5.47.0; every finding reviewed by a person. Findings reflect the configuration at scan time; this is not a penetration test or a guarantee.
- Note: Not evaluated in the simulator (ID-01, ID-07, DA-01): it has no root user, IAM Access Analyzer or account-level S3 settings. A scan of a real account evaluates them.
- Note: Retest after the fix pack. AWS Config (LD-03) is still off: this fictional client chose to add it next quarter.
