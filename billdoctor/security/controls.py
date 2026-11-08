"""The 25 controls of the AWS Security Baseline Check (service S8).

Each control groups one or more Prowler checks (https://github.com/prowler-cloud/prowler, Apache-2.0)
or, where Prowler has no check, a small native check from `extras.py`. The selection follows the
CIS AWS Foundations Benchmark and the basic mistakes behind most cloud breaches: who can get in,
whether you would notice, whether data is exposed, what is open to the internet, and where secrets live.

Severity is ours, not Prowler's: it ranks how a small company is usually hurt, and drives the score.
"""
from __future__ import annotations

from dataclasses import dataclass, field

GROUPS = {
    "ID": "Identity and access",
    "LD": "Logging and detection",
    "DA": "Data protection",
    "NC": "Network and compute",
    "SP": "Secrets and pipelines",
}

SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}

# India's DPDP Rules (notified 13 Nov 2025): technical safeguard areas a reviewer can inspect.
DPDP_AREAS = {
    "encryption": "Encryption, masking and secrets",
    "access": "Access control",
    "logging": "Logging and monitoring (logs kept at least one year)",
    "continuity": "Backups and continuity",
    "breach": "Breach detection and 72-hour response",
}


@dataclass(frozen=True)
class Fix:
    terraform: str = ""   # input of aws-foundation/modules/security-baseline, or another module
    cli: str = ""         # AWS CLI command(s) to review and run - never run by this tool
    console: str = ""     # console steps when there is no safe API


@dataclass(frozen=True)
class Control:
    id: str
    group: str
    title: str
    severity: str
    why: str
    prowler: tuple[str, ...] = ()
    native: str = ""            # name of a check in extras.py
    scope: str = "account"      # "account": no result means not evaluated; "resource": no result means no such resources
    fix: Fix = field(default_factory=Fix)
    dpdp: tuple[str, ...] = ()

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    @property
    def group_name(self) -> str:
        return GROUPS[self.group]


CONTROLS: tuple[Control, ...] = (
    # ------------------------------------------------------------------ identity
    Control(
        "ID-01", "ID", "Root user is protected (MFA on, no access keys)", "critical",
        "The root user can do everything, including closing the account. A stolen root password or key is a total loss.",
        ("iam_root_mfa_enabled", "iam_no_root_access_key"),
        fix=Fix(console="Sign in as root > Security credentials > assign an MFA device (passkey or hardware key); delete any root access keys. "
                        "In AWS Organizations, turn on centralized root access management for member accounts."),
        dpdp=("access",),
    ),
    Control(
        "ID-02", "ID", "Every console user has MFA", "high",
        "Passwords get phished and reused. MFA stops most account takeovers.",
        ("iam_user_mfa_enabled_console_access",), scope="resource",
        fix=Fix(cli="aws iam list-virtual-mfa-devices  # find users without a device, then enable MFA for each, or move people to IAM Identity Center",
                console="IAM > Users > (user) > Security credentials > Assign MFA device."),
        dpdp=("access",),
    ),
    Control(
        "ID-03", "ID", "Access keys are rotated and unused keys removed", "high",
        "Long-lived keys leak through laptops, CI logs and git history. Datadog found active keys over a year old at 59% of IAM users.",
        ("iam_rotate_access_key_90_days", "iam_user_accesskey_unused", "iam_user_console_access_unused"), scope="resource",
        fix=Fix(cli="aws iam update-access-key --user-name <user> --access-key-id <key> --status Inactive   # then delete once nothing breaks\n"
                    "aws iam delete-access-key --user-name <user> --access-key-id <key>"),
        dpdp=("access",),
    ),
    Control(
        "ID-04", "ID", "People get permissions through groups, roles or SSO - not attached to users", "medium",
        "Permissions attached user by user drift and are never reviewed. Groups, roles and IAM Identity Center keep access auditable.",
        ("iam_policy_attached_only_to_group_or_roles",), scope="resource",
        fix=Fix(cli="aws iam detach-user-policy --user-name <user> --policy-arn <arn>   # after adding the user to a group with the same rights",
                console="Prefer IAM Identity Center: one login per person, permission sets per job, no long-lived keys."),
        dpdp=("access",),
    ),
    Control(
        "ID-05", "ID", "Full administrator rights are limited to a break-glass role", "high",
        "Every identity with AdministratorAccess is a way to lose the whole account. Most teams need two or three, not ten.",
        ("iam_aws_attached_policy_no_administrative_privileges", "iam_customer_attached_policy_no_administrative_privileges",
         "iam_inline_policy_no_administrative_privileges"), scope="resource",
        fix=Fix(cli="aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                console="Replace AdministratorAccess with job-based policies (PowerUserAccess, ReadOnlyAccess, or service-scoped). "
                        "Keep one MFA-protected break-glass role."),
        dpdp=("access",),
    ),
    Control(
        "ID-06", "ID", "Password policy requires long, non-reused passwords", "low",
        "Only matters for IAM users with console access, but auditors and customer questionnaires ask for it.",
        ("iam_password_policy_minimum_length_14", "iam_password_policy_reuse_24"),
        fix=Fix(terraform="module.security_baseline: iam_password_policy = true",
                cli="aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 "
                    "--require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"),
        dpdp=("access",),
    ),
    Control(
        "ID-07", "ID", "IAM Access Analyzer watches for external access", "medium",
        "It flags buckets, roles and keys shared with other accounts or the public - for free.",
        ("accessanalyzer_enabled",),
        fix=Fix(terraform="module.security_baseline: access_analyzer = true",
                cli="aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT"),
        dpdp=("access",),
    ),
    # ------------------------------------------------------------------ logging and detection
    Control(
        "LD-01", "LD", "CloudTrail records every region, with tamper-evident, private logs", "critical",
        "Without CloudTrail there is no record of who did what - no investigation, and no basis for a breach report.",
        ("cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "cloudtrail_logs_s3_bucket_is_not_publicly_accessible"),
        fix=Fix(terraform="module.security_baseline: cloudtrail = true   # multi-region trail, log-file validation, private encrypted bucket",
                cli="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation\n"
                    "aws cloudtrail start-logging --name org-trail"),
        dpdp=("logging", "breach"),
    ),
    Control(
        "LD-02", "LD", "GuardDuty threat detection is on", "high",
        "GuardDuty spots stolen credentials, crypto-mining and unusual API calls. Costs a few dollars a month for small accounts.",
        ("guardduty_is_enabled",),
        fix=Fix(terraform="module.security_baseline: guardduty = true",
                cli="aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES"),
        dpdp=("breach",),
    ),
    Control(
        "LD-03", "LD", "AWS Config records configuration changes", "medium",
        "Config keeps a history of how each resource was configured - the evidence auditors and investigators ask for.",
        ("config_recorder_all_regions_enabled",),
        fix=Fix(terraform="module.security_baseline: config_recorder = true",
                console="AWS Config > Get started > record all resources > deliver to the CloudTrail logs bucket."),
        dpdp=("logging",),
    ),
    Control(
        "LD-04", "LD", "Log groups keep logs for at least a year", "medium",
        "Logs kept for days or weeks are gone when an incident is found months later. One year is the minimum many customers - "
        "and India's DPDP Rules - expect for security logs. ('Never expire' passes here; the cost check LOGS-001 flags its price.)",
        ("cloudwatch_log_group_retention_policy_specific_days_enabled",), scope="resource",
        fix=Fix(cli="bash aws-foundation/fix-pack/scripts/set-log-retention.sh --days 365   # dry run first; add --apply to change"),
        dpdp=("logging",),
    ),
    Control(
        "LD-05", "LD", "Spend alerts would catch abuse within a day", "medium",
        "A stolen key used for crypto-mining shows up first on the bill. Budgets with email alerts are free.",
        native="spend_alerts",
        fix=Fix(terraform="module.security_baseline: monthly_budget_usd = <amount>, alert_emails = [...]  (or aws-bill-doctor/terraform/budget-guard)"),
        dpdp=("breach",),
    ),
    # ------------------------------------------------------------------ data
    Control(
        "DA-01", "DA", "S3 Block Public Access is on for the whole account", "critical",
        "One account-wide switch stops any bucket from being made public by mistake - the cause of many data leaks.",
        ("s3_account_level_public_access_blocks",),
        fix=Fix(terraform="module.security_baseline: s3_account_public_access_block = true",
                cli="aws s3control put-public-access-block --account-id <account> --public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"),
        dpdp=("access", "encryption"),
    ),
    Control(
        "DA-02", "DA", "No bucket is public", "critical",
        "Public buckets are found by automated scanners within hours.",
        ("s3_bucket_public_access", "s3_bucket_policy_public_write_access", "s3_bucket_public_list_acl", "s3_bucket_public_write_acl"),
        scope="resource",
        fix=Fix(cli="aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n"
                    "# if the bucket serves a website, put CloudFront with origin access control in front instead"),
        dpdp=("access",),
    ),
    Control(
        "DA-03", "DA", "Data is encrypted by default (S3 and EBS)", "medium",
        "Default encryption is free and protects disks, snapshots and buckets that get copied or shared by mistake.",
        ("s3_bucket_default_encryption", "ec2_ebs_default_encryption"),
        fix=Fix(terraform="module.security_baseline: ebs_encryption_by_default = true",
                cli="aws ec2 enable-ebs-encryption-by-default --region <region>"),
        dpdp=("encryption",),
    ),
    Control(
        "DA-04", "DA", "Databases are encrypted, private, backed up and protected from deletion", "high",
        "An RDS instance reachable from the internet, without backups, is one mistake away from a data leak or permanent loss.",
        ("rds_instance_storage_encrypted", "rds_instance_no_public_access", "rds_instance_backup_enabled", "rds_instance_deletion_protection"),
        scope="resource",
        fix=Fix(cli="aws rds modify-db-instance --db-instance-identifier <db> --backup-retention-period 7 --deletion-protection "
                    "--no-publicly-accessible --apply-immediately\n"
                    "# encryption at rest needs a new instance: snapshot -> copy with --kms-key-id -> restore -> switch over"),
        dpdp=("encryption", "access", "continuity"),
    ),
    Control(
        "DA-05", "DA", "No snapshot is public", "critical",
        "A public EBS or RDS snapshot hands a full copy of the disk or database to anyone.",
        ("ec2_ebs_public_snapshot", "rds_snapshots_public_access"), scope="resource",
        fix=Fix(terraform="module.security_baseline: ebs_snapshot_block_public_access = true",
                cli="aws ec2 modify-snapshot-attribute --snapshot-id <snap> --attribute createVolumePermission --operation-type remove --group-names all\n"
                    "aws rds modify-db-snapshot-attribute --db-snapshot-identifier <snap> --attribute-name restore --values-to-remove all"),
        dpdp=("access",),
    ),
    # ------------------------------------------------------------------ network and compute
    Control(
        "NC-01", "NC", "No SSH, RDP or database port is open to the whole internet", "critical",
        "Open admin and database ports are scanned constantly; one weak password or unpatched service is enough.",
        ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
         "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
         "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"), scope="resource",
        fix=Fix(cli="aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0\n"
                    "# use SSM Session Manager (no open port) or a VPN/allow-list instead"),
        dpdp=("access",),
    ),
    Control(
        "NC-02", "NC", "Default security groups allow no traffic", "low",
        "Resources launched without a chosen group land in the default one; it should block everything.",
        ("ec2_securitygroup_default_restrict_traffic",), scope="resource",
        fix=Fix(terraform="module.security_baseline: default_security_group_vpc_ids = [\"vpc-...\"]   # check nothing uses the group first"),
        dpdp=("access",),
    ),
    Control(
        "NC-03", "NC", "Instances require IMDSv2", "high",
        "IMDSv1 lets an SSRF bug in a web app read the instance's cloud credentials (the Capital One breach). "
        "Datadog found IMDSv2 enforced on only 49% of instances.",
        ("ec2_instance_imdsv2_enabled", "ec2_instance_account_imdsv2_enabled"), scope="resource",
        fix=Fix(terraform="module.security_baseline: ec2_imdsv2_default = true   # new instances",
                cli="bash aws-foundation/fix-pack/scripts/require-imdsv2.sh --regions <region>   # dry run lists instances; --apply after testing one\n"
                    "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 2"),
        dpdp=("access",),
    ),
    Control(
        "NC-04", "NC", "Only intended instances have public IP addresses", "medium",
        "Every public instance is attack surface (and costs $3.65 a month per IPv4 address). Most belong behind a load balancer.",
        ("ec2_instance_public_ip",), scope="resource",
        fix=Fix(console="Move workloads to private subnets behind a load balancer; reach them with SSM Session Manager. "
                        "Keep a public IP only where it is intended, and note it in the report."),
        dpdp=("access",),
    ),
    # ------------------------------------------------------------------ secrets and pipelines
    Control(
        "SP-01", "SP", "No secrets in Lambda variables, EC2 user data or launch templates", "critical",
        "Anyone with read-only access - including auditors and many SaaS tools - can read these fields.",
        ("awslambda_function_no_secrets_in_variables", "ec2_instance_secrets_user_data", "ec2_launch_template_no_secrets"),
        scope="resource",
        fix=Fix(console="Move each value to Secrets Manager or SSM Parameter Store (SecureString), read it at runtime, "
                        "then rotate it - it must be treated as exposed."),
        dpdp=("encryption",),
    ),
    Control(
        "SP-02", "SP", "Secrets Manager secrets rotate automatically", "medium",
        "A secret that never changes stays valid after every leak.",
        ("secretsmanager_automatic_rotation_enabled",), scope="resource",
        fix=Fix(cli="aws secretsmanager rotate-secret --secret-id <id> --rotation-lambda-arn <arn> --rotation-rules AutomaticallyAfterDays=90"),
        dpdp=("encryption",),
    ),
    Control(
        "SP-03", "SP", "CI/CD logs in with short-lived OIDC credentials, not stored keys", "high",
        "Keys stored in CI were stolen in the tj-actions, Trivy and Checkmarx incidents. OIDC tokens expire in minutes.",
        native="ci_oidc",
        fix=Fix(terraform="gha-hardening-kit/terraform/github-oidc-role (service S2)",
                console="Create an OIDC role trusted only by your repository's main branch or a protected environment, "
                        "switch the workflow to role-to-assume, then delete the old access key."),
        dpdp=("access",),
    ),
    Control(
        "SP-04", "SP", "Container images are scanned on push and tags are immutable", "low",
        "Scanning catches known vulnerabilities before deployment; immutable tags stop a pushed image being silently replaced.",
        ("ecr_registry_scan_images_on_push_enabled", "ecr_repositories_scan_images_on_push_enabled", "ecr_repositories_tag_immutability"),
        scope="resource",
        fix=Fix(terraform="module.security_baseline: ecr_scan_on_push = true",
                cli="aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE"),
    ),
)

BY_ID: dict[str, Control] = {c.id: c for c in CONTROLS}


def prowler_checks() -> list[str]:
    """Every Prowler check the baseline needs, in a stable order."""
    seen: list[str] = []
    for c in CONTROLS:
        for p in c.prowler:
            if p not in seen:
                seen.append(p)
    return seen


def control_for_check() -> dict[str, str]:
    """Prowler check ID -> control ID."""
    return {p: c.id for c in CONTROLS for p in c.prowler}
