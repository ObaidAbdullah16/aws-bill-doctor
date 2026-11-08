"""Synthetic demo account.

`billdoctor demo` starts an in-memory fake of AWS (moto), creates a small company's
account with typical waste, and runs the *real* checks against it. The resulting
report is what clients see, with a SYNTHETIC banner on every page. Nothing touches AWS.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

import boto3

ACCOUNT = "123456789012"
PRIMARY, SECONDARY = "ap-south-1", "us-east-1"


def _tags(name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}]


def _cpu(cw: Any, iid: str, avg: float, peak: float, now: dt.datetime, days: int = 14) -> None:
    data = []
    for d in range(1, days + 1):
        ts = now - dt.timedelta(days=d, hours=1)
        data.append({"MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                     "Timestamp": ts, "Value": avg})
        data.append({"MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                     "Timestamp": ts + dt.timedelta(minutes=5), "Value": peak if d % 3 == 0 else avg})
    for i in range(0, len(data), 20):
        cw.put_metric_data(Namespace="AWS/EC2", MetricData=data[i:i + 20])


def _daily(cw: Any, ns: str, metric: str, dim: tuple[str, str], value: float, now: dt.datetime, days: int = 14) -> None:
    data = [{"MetricName": metric, "Dimensions": [{"Name": dim[0], "Value": dim[1]}],
             "Timestamp": now - dt.timedelta(days=d, hours=2), "Value": value} for d in range(1, days + 1)]
    cw.put_metric_data(Namespace=ns, MetricData=data)


def _backdate(notes: list[str], fn: Any, what: str) -> None:
    """moto has no API for 'this happened 200 days ago'; adjust its in-memory objects."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001 - demo only; keep working on other moto versions
        notes.append(f"could not backdate {what} in the simulator ({e.__class__.__name__})")


def seed(now: dt.datetime) -> list[str]:
    """Create the synthetic account. Must run inside moto's mock_aws()."""
    notes: list[str] = []
    from moto.ec2.models import ec2_backends  # imported lazily: moto is an optional extra
    from moto.logs.models import logs_backends

    ec2 = boto3.client("ec2", region_name=PRIMARY)
    cw = boto3.client("cloudwatch", region_name=PRIMARY)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    subnets = ec2.describe_subnets()["Subnets"]
    vpc_id = subnets[0]["VpcId"]

    def run(name: str, itype: str, gb: int, vtype: str = "gp2") -> str:
        r = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType=itype, SubnetId=subnets[0]["SubnetId"],
                              TagSpecifications=_tags(name),
                              BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": gb, "VolumeType": vtype}}])
        return r["Instances"][0]["InstanceId"]

    web = run("web-1", "t3.medium", 50, "gp3")
    legacy = run("legacy-reporting", "t2.large", 100)
    staging = run("staging-api", "m4.large", 80, "gp3")
    agent = run("old-build-agent", "t3.large", 120)
    _cpu(cw, web, 34, 71, now)
    _cpu(cw, legacy, 1.8, 7.5, now)
    _cpu(cw, staging, 12, 48, now)
    ec2.stop_instances(InstanceIds=[agent])
    be = ec2_backends[ACCOUNT][PRIMARY]
    stopped_at = (now - dt.timedelta(days=75)).strftime("%Y-%m-%d %H:%M:%S")
    _backdate(notes, lambda: setattr(be.get_instance(agent), "_reason", f"User initiated ({stopped_at} GMT)"), "stopped instance")

    for size, vtype, name in [(200, "gp2", "old-jenkins-data"), (500, "gp3", "migration-temp"), (100, "io1", "perf-test")]:
        kw = {"Iops": 3000} if vtype == "io1" else {}
        ec2.create_volume(AvailabilityZone=f"{PRIMARY}a", Size=size, VolumeType=vtype,
                          TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}], **kw)

    src = ec2.create_volume(AvailabilityZone=f"{PRIMARY}a", Size=200, VolumeType="gp3")["VolumeId"]
    for age, desc in [(410, "pre-migration backup 2025"), (220, "manual backup before upgrade"), (12, "weekly backup")]:
        sid = ec2.create_snapshot(VolumeId=src, Description=desc)["SnapshotId"]
        _backdate(notes, lambda sid=sid, age=age: setattr(be.snapshots[sid], "start_time", now - dt.timedelta(days=age)), "snapshot")
    ec2.delete_volume(VolumeId=src)
    # An old snapshot that backs an AMI must NOT be reported (it is still in use).
    image = ec2.register_image(Name="golden-image", RootDeviceName="/dev/xvda")["ImageId"]
    for bdm in ec2.describe_images(ImageIds=[image])["Images"][0].get("BlockDeviceMappings", []):
        ami_snap = bdm.get("Ebs", {}).get("SnapshotId")
        if ami_snap:
            _backdate(notes, lambda s=ami_snap: setattr(be.snapshots[s], "start_time", now - dt.timedelta(days=300)), "AMI snapshot")

    used = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=used["AllocationId"], InstanceId=web)
    ec2.allocate_address(Domain="vpc")

    nat_eip = ec2.allocate_address(Domain="vpc")
    nat = ec2.create_nat_gateway(SubnetId=subnets[0]["SubnetId"], AllocationId=nat_eip["AllocationId"])["NatGateway"]["NatGatewayId"]
    for metric, mb_per_day in [("BytesOutToDestination", 10), ("BytesInFromDestination", 30)]:
        _daily(cw, "AWS/NATGateway", metric, ("NatGatewayId", nat), mb_per_day * 1024 * 1024, now)

    elb = boto3.client("elbv2", region_name=PRIMARY)
    two = [s["SubnetId"] for s in subnets[:2]]
    for lb_name, register in [("app-alb", True), ("old-promo-alb", False)]:
        lb = elb.create_load_balancer(Name=lb_name, Subnets=two, Type="application")["LoadBalancers"][0]
        tg = elb.create_target_group(Name=f"{lb_name}-tg", Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")["TargetGroups"][0]
        elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                            DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
        if register:
            elb.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": web}])

    rds = boto3.client("rds", region_name=PRIMARY)
    for dbid, cls, conns in [("app-db", "db.t4g.micro", 14), ("analytics-copy", "db.t3.medium", 0)]:
        rds.create_db_instance(DBInstanceIdentifier=dbid, DBInstanceClass=cls, Engine="postgres", AllocatedStorage=100,
                               MasterUsername="demo", MasterUserPassword="demo-password-123")
        _daily(cw, "AWS/RDS", "DatabaseConnections", ("DBInstanceIdentifier", dbid), conns, now)

    logs = boto3.client("logs", region_name=PRIMARY)
    lbe = logs_backends[ACCOUNT][PRIMARY]
    for group, gb, retention in [("/ecs/web", 48, None), ("/aws/lambda/old-report-fn", 12, None), ("/app/audit", 30, 365)]:
        logs.create_log_group(logGroupName=group)
        if retention:
            logs.put_retention_policy(logGroupName=group, retentionInDays=retention)
        logs.create_log_stream(logGroupName=group, logStreamName="s")
        logs.put_log_events(logGroupName=group, logStreamName="s",
                            logEvents=[{"timestamp": int(now.timestamp() * 1000), "message": "demo"}])
        _backdate(notes, lambda group=group, gb=gb: setattr(lbe.groups[group].streams["s"], "stored_bytes", gb * 1024 ** 3), "log size")

    s3 = boto3.client("s3", region_name=PRIMARY)
    for bucket, versioned, lifecycle in [("acme-uploads-demo", True, False), ("acme-exports-demo", False, False), ("acme-site-demo", False, True)]:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": PRIMARY})
        if versioned:
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        if lifecycle:
            s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [
                {"ID": "mpu", "Status": "Enabled", "Filter": {}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]})

    ec2b = boto3.client("ec2", region_name=SECONDARY)
    ec2b.create_volume(AvailabilityZone=f"{SECONDARY}a", Size=1000, VolumeType="gp2",
                       TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": "forgotten-ml-dataset"}]}])
    ec2b.allocate_address(Domain="vpc")
    return notes


def run_demo(out_dir: str) -> tuple[Any, list[str]]:
    from moto import mock_aws

    from .report import write_all
    from .scanner import run_scan

    now = dt.datetime.now(dt.timezone.utc)
    with mock_aws():
        session = boto3.Session(region_name=PRIMARY)
        notes = seed(now)
        result = run_scan(session, [PRIMARY, SECONDARY], account_label="Acme Retail (synthetic demo)", now=now, synthetic=True)
        result.notes.extend(notes)
        files = write_all(result, out_dir)
    return result, [str(f) for f in files]
