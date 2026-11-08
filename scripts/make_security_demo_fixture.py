"""Rebuild billdoctor/data/security-demo.json: REAL Prowler checks run against a SIMULATED account.

The sample security report is generated from this fixture so CI and `billdoctor security demo` need
neither AWS nor Prowler. To rebuild it (developer machine only):

    pip install prowler "moto[server]"
    moto_server -p 5555 &                       # with MOTO_IAM_LOAD_MANAGED_POLICIES=true in its environment
    AWS_ENDPOINT_URL=http://127.0.0.1:5555 AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing \
        python scripts/make_security_demo_fixture.py

It seeds a deliberately misconfigured fictional company ("Acme Retail", the same fictional company as the cost demo) into the simulator, runs
Prowler with the curated check list, runs the two native checks, and keeps a trimmed copy of the results.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from billdoctor.security.controls import prowler_checks  # noqa: E402
from billdoctor.security.extras import ci_oidc, spend_alerts  # noqa: E402

R = "ap-south-1"
FAKE = "demo-only-not-a-real-secret"


def seed(fixed: bool = False) -> None:
    """A fictional small company. fixed=False: a typical state before the check (some things done right, the usual
    gaps). fixed=True: after the fix pack - except AWS Config, which this client chose not to pay for yet."""
    iam = boto3.client("iam")
    s3 = boto3.client("s3", region_name=R)
    ec2 = boto3.client("ec2", region_name=R)
    acct = boto3.client("sts").get_caller_identity()["Account"]
    # ---- identity
    iam.create_user(UserName="priya.sharma")
    iam.create_login_profile(UserName="priya.sharma", Password="Demo-Only-Password-1!")
    iam.create_group(GroupName="developers")
    iam.attach_group_policy(GroupName="developers", PolicyArn="arn:aws:iam::aws:policy/PowerUserAccess")
    iam.add_user_to_group(GroupName="developers", UserName="priya.sharma")
    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24, RequireSymbols=True,
                                       RequireNumbers=True, RequireUppercaseCharacters=True, RequireLowercaseCharacters=True)
    if fixed:
        mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="priya.sharma")["VirtualMFADevice"]["SerialNumber"]
        iam.enable_mfa_device(UserName="priya.sharma", SerialNumber=mfa, AuthenticationCode1="123456", AuthenticationCode2="654321")
        iam.create_open_id_connect_provider(Url="https://token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"],
                                            ThumbprintList=["ffffffffffffffffffffffffffffffffffffffff"])
    else:
        iam.create_user(UserName="ci-deploy")
        iam.create_access_key(UserName="ci-deploy")
        iam.attach_user_policy(UserName="ci-deploy", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    # ---- logging and detection
    s3.create_bucket(Bucket="acme-demo-trail", CreateBucketConfiguration={"LocationConstraint": R})
    s3.put_public_access_block(Bucket="acme-demo-trail", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket="acme-demo-trail", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    ct = boto3.client("cloudtrail", region_name=R)
    ct.create_trail(Name="acme-trail", S3BucketName="acme-demo-trail", IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="acme-trail")
    logs = boto3.client("logs", region_name=R)
    logs.create_log_group(logGroupName="/acme/api")
    logs.put_retention_policy(logGroupName="/acme/api", retentionInDays=365 if fixed else 7)
    logs.create_log_group(logGroupName="/acme/worker")
    logs.put_retention_policy(logGroupName="/acme/worker", retentionInDays=365)
    if fixed:
        boto3.client("guardduty", region_name=R).create_detector(Enable=True)
    boto3.client("budgets", region_name="us-east-1").create_budget(
        AccountId=acct,
        Budget={"BudgetName": "monthly", "BudgetLimit": {"Amount": "300", "Unit": "USD"}, "TimeUnit": "MONTHLY", "BudgetType": "COST"},
        NotificationsWithSubscribers=[{"Notification": {"NotificationType": "ACTUAL", "ComparisonOperator": "GREATER_THAN", "Threshold": 80},
                                       "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "finance@example.com"}]}])
    # ---- data: buckets encrypted (as every new bucket is since 2023); uploads public before the fix
    for name in ("acme-demo-uploads", "acme-demo-invoices"):
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": R})
        s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    if not fixed:
        s3.put_bucket_policy(Bucket="acme-demo-uploads", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-demo-uploads/*"}]}))
    if fixed:
        ec2.enable_ebs_encryption_by_default()
    rds = boto3.client("rds", region_name=R)
    rds.create_db_instance(DBInstanceIdentifier="acme-prod-db", Engine="postgres", DBInstanceClass="db.t4g.micro",
                           MasterUsername="acme", MasterUserPassword=FAKE, AllocatedStorage=20, PubliclyAccessible=False,
                           StorageEncrypted=True, BackupRetentionPeriod=7, DeletionProtection=True)
    vol = ec2.create_volume(AvailabilityZone=R + "a", Size=8, Encrypted=fixed)["VolumeId"]
    ec2.create_snapshot(VolumeId=vol, Description="old db backup")
    # ---- network and compute
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    subnet = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
    sg = ec2.create_security_group(GroupName="api", Description="acme api", VpcId=vpc)["GroupId"]
    rules = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}]
    if not fixed:
        rules.append({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=rules)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
                      NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": not fixed}],
                      MetadataOptions={"HttpTokens": "required" if fixed else "optional", "HttpEndpoint": "enabled"},
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "acme-api"}]}])
    # ---- secrets and pipelines
    role = iam.create_role(RoleName="acme-lambda", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "def handler(e, c):\n    return 1\n")
    env = {"SECRET_NAME": "acme/prod/smtp", "REGION": R} if fixed else {"SMTP_PASSWORD": "Demo-Only-Smtp-Passw0rd-NotReal", "REGION": R}
    lam = boto3.client("lambda", region_name=R)
    fn = lam.create_function(FunctionName="acme-invoice-mailer", Runtime="python3.12", Role=role, Handler="app.handler",
                             Code={"ZipFile": buf.getvalue()}, Environment={"Variables": env})["FunctionArn"]
    sm = boto3.client("secretsmanager", region_name=R)
    sm.create_secret(Name="acme/prod/db", SecretString=FAKE)
    if fixed:
        sm.rotate_secret(SecretId="acme/prod/db", RotationLambdaARN=fn, RotationRules={"AutomaticallyAfterDays": 90})
    ecr = boto3.client("ecr", region_name=R)
    ecr.create_repository(repositoryName="acme/api", imageTagMutability="IMMUTABLE" if fixed else "MUTABLE",
                          imageScanningConfiguration={"scanOnPush": fixed})
    if fixed:
        ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[
            {"scanFrequency": "SCAN_ON_PUSH", "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}]}])


def trim(item: dict) -> dict:
    """Keep what the report reads; keep only CIS mappings."""
    un = item.get("unmapped", {})
    un["compliance"] = {k: v for k, v in (un.get("compliance") or {}).items() if k.startswith("CIS-")}
    for k in ("depends_on", "related_to", "additional_urls", "categories", "notes", "related_url"):
        un.pop(k, None)
    for k in ("risk_details", "remediation", "type_uid", "type_name", "activity_name", "activity_id", "category_name",
              "category_uid", "class_name", "class_uid", "time"):
        item.pop(k, None)
    fi = item.get("finding_info", {})
    fi.pop("desc", None)
    fi.pop("types", None)
    for r in item.get("resources", []):
        for k in ("data", "labels", "group", "cloud_partition"):
            r.pop(k, None)
    item.get("cloud", {}).pop("org", None)
    return item


def scan() -> tuple[list[dict], list[dict]]:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["prowler", "aws", "--no-banner", "--no-color", "--filter-region", R, "--checks", *prowler_checks(),
               "--output-formats", "json-ocsf", "--output-directory", tmp, "--output-filename", "demo"]
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL)
        items = json.loads((Path(tmp) / "demo.ocsf.json").read_text())
    kept, passes = [], {}
    for it in items:
        cid = it["metadata"]["event_code"]
        if it["status_code"] == "PASS":
            passes[cid] = passes.get(cid, 0) + 1
            if passes[cid] > 3:      # the simulator ships hundreds of public AMI snapshots; three passes are enough
                continue
        kept.append(trim(it))
    session = boto3.Session(region_name=R)
    acct = session.client("sts").get_caller_identity()["Account"]
    native = [r.__dict__ for r in spend_alerts(session, acct) + ci_oidc(session, acct)]
    return kept, native


def reset() -> None:
    import urllib.request
    urllib.request.urlopen(urllib.request.Request(os.environ["AWS_ENDPOINT_URL"].rstrip("/") + "/moto-api/reset", method="POST"))


def main() -> int:
    if not os.environ.get("AWS_ENDPOINT_URL"):
        print("Refusing to run without AWS_ENDPOINT_URL (this script must only ever talk to the simulator).", file=sys.stderr)
        return 2
    for fixed, name in ((False, "security-demo.json"), (True, "security-demo-after.json")):
        reset()
        seed(fixed=fixed)
        kept, native = scan()
        out = {"note": "Real Prowler checks run against a SIMULATED account (moto). Fictional company; no customer data.",
               "account_label": "Acme Retail (synthetic demo)", "regions": [R], "stage": "after fixes" if fixed else "before",
               "prowler": kept, "native": native}
        dest = ROOT / "billdoctor" / "data" / name
        dest.write_text(json.dumps(out, indent=1, default=str) + "\n", encoding="utf-8")
        print(f"wrote {dest} ({len(kept)} prowler results, {len(native)} native)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
