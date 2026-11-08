"""RDS, CloudWatch Logs and S3 checks."""
from __future__ import annotations

from collections.abc import Iterable

from botocore.exceptions import ClientError

from ..models import HOURS_PER_MONTH, Finding, ScanContext, check

GB = 1024 ** 3


@check("RDS-001", "Idle RDS databases", "RDS",
       "A database with zero connections for two weeks is usually a forgotten test or migration copy.")
def idle_rds(ctx: ScanContext) -> Iterable[Finding]:
    for db in ctx.paginate("rds", "describe_db_instances", "DBInstances"):
        if db.get("DBInstanceStatus") != "available":
            continue
        dbid, cls = db["DBInstanceIdentifier"], db["DBInstanceClass"]
        conns = ctx.metric("AWS/RDS", "DatabaseConnections", {"DBInstanceIdentifier": dbid}, "Maximum")
        if len(conns) < 3 or max(conns) > 0:
            continue
        hourly = ctx.money("rds_hour", cls)
        storage = ctx.money("ebs_gb_month", "gp2")  # RDS gp2/gp3 storage is priced close to EBS gp2
        cost = None
        if hourly is not None:
            cost = hourly * HOURS_PER_MONTH * (2 if db.get("MultiAZ") else 1)
            if storage is not None:
                cost += db.get("AllocatedStorage", 0) * storage
            cost = round(cost, 2)
        yield Finding(
            check_id="RDS-001", title="Database has had no connections", region=ctx.region,
            resource_type="rds-instance", resource_id=dbid,
            detail=f"{cls} {db.get('Engine')} {db.get('AllocatedStorage')} GiB{' Multi-AZ' if db.get('MultiAZ') else ''}: "
                   f"0 connections in {len(conns)} days",
            recommendation="Take a final snapshot and delete it (stopping only lasts 7 days before AWS restarts it).",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="high",
            fix_command=(f"aws rds delete-db-instance --region {ctx.region} --db-instance-identifier {dbid} "
                         f"--final-db-snapshot-identifier {dbid}-billdoctor-final"),
        )


@check("LOGS-001", "Log groups that never expire", "CloudWatch",
       "The default retention is 'never expire', so log storage grows forever.")
def log_retention(ctx: ScanContext) -> Iterable[Finding]:
    price = ctx.money("logs_gb_month")
    for g in ctx.paginate("logs", "describe_log_groups", "logGroups"):
        if g.get("retentionInDays"):
            continue
        stored = g.get("storedBytes", 0) / GB
        cost = round(stored * price, 2) if price is not None else None
        yield Finding(
            check_id="LOGS-001", title="Log group keeps data forever", region=ctx.region,
            resource_type="log-group", resource_id=g["logGroupName"],
            detail=f"{stored:.2f} GB stored, retention: never expire",
            recommendation="Set a retention period that matches your needs (e.g. 30 days for app logs, longer for audit logs). "
                           "Saving depends on how old the data is, so it is not estimated.",
            monthly_cost=cost, est_monthly_savings=None, fix_risk="low",
            fix_command=f"aws logs put-retention-policy --region {ctx.region} --log-group-name '{g['logGroupName']}' --retention-in-days 30",
        )


@check("S3-001", "S3 buckets without lifecycle rules", "S3",
       "Without lifecycle rules, incomplete multipart uploads and old object versions are kept (and billed) forever.")
def s3_lifecycle(ctx: ScanContext) -> Iterable[Finding]:
    s3 = ctx.client("s3")

    def skipped(bucket: str, what: str, e: ClientError) -> None:
        # A bucket policy can deny the auditor even when the IAM role allows the call: say so in the
        # report instead of silently treating the bucket as fine.
        code = e.response.get("Error", {}).get("Code", "ClientError")
        note = f"S3-001: could not read the {what} of bucket {bucket} ({code}); it was not checked"
        if note not in ctx.notes:
            ctx.notes.append(note)

    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except ClientError as e:
            skipped(name, "region", e)
            continue
        loc = {"EU": "eu-west-1"}.get(loc, loc)  # very old buckets report "EU"
        if loc != ctx.region:
            continue  # each bucket is reported once, in its own region
        try:
            rules = s3.get_bucket_lifecycle_configuration(Bucket=name).get("Rules", [])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchLifecycleConfiguration":
                skipped(name, "lifecycle rules", e)
                continue
            rules = []
        try:
            versioned = s3.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
        except ClientError as e:
            skipped(name, "versioning status", e)
            continue
        enabled = [r for r in rules if r.get("Status") == "Enabled"]
        aborts_mpu = any("AbortIncompleteMultipartUpload" in r for r in enabled)
        expires_versions = any("NoncurrentVersionExpiration" in r for r in enabled)
        problems = []
        if not aborts_mpu:
            problems.append("incomplete multipart uploads are never cleaned up")
        if versioned and not expires_versions:
            problems.append("versioning is on but old versions never expire")
        if not problems:
            continue
        yield Finding(
            check_id="S3-001", title="Bucket lifecycle gaps", region=ctx.region,
            resource_type="s3-bucket", resource_id=name, detail="; ".join(problems),
            recommendation="Add a lifecycle rule: abort incomplete multipart uploads after 7 days"
                           + (" and expire noncurrent versions after 30-90 days." if versioned else "."),
            monthly_cost=None, est_monthly_savings=None, fix_risk="low",
            fix_command=(f"aws s3api put-bucket-lifecycle-configuration --region {ctx.region} --bucket {name} --lifecycle-configuration "
                         "'{\"Rules\":[{\"ID\":\"billdoctor-hygiene\",\"Status\":\"Enabled\",\"Filter\":{},"
                         "\"AbortIncompleteMultipartUpload\":{\"DaysAfterInitiation\":7}"
                         + (",\"NoncurrentVersionExpiration\":{\"NoncurrentDays\":60}" if versioned else "")
                         + "}]}'  # WARNING: replaces existing rules - merge them first"),
        )
