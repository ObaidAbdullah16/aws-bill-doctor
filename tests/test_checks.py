import datetime as dt

from moto.ec2.models import ec2_backends

from billdoctor.checks import data, ebs, ec2, network

ACCOUNT = "123456789012"
REGION = "ap-south-1"


def ids(findings):
    return [f.resource_id for f in findings]


def test_unattached_volume_cost(aws, ctx):
    c = aws.client("ec2")
    v = c.create_volume(AvailabilityZone=f"{REGION}a", Size=100, VolumeType="gp2")["VolumeId"]
    out = list(ebs.unattached_volumes(ctx))
    assert ids(out) == [v]
    assert out[0].est_monthly_savings == round(100 * 0.114, 2)
    cmd = out[0].fix_command
    # The volume is deleted only after the snapshot has completed.
    assert cmd.index("create-snapshot") < cmd.index("wait snapshot-completed") < cmd.index("delete-volume")


def test_volume_cost_includes_provisioned_performance(ctx):
    # ap-south-1 storage prices; IOPS/throughput prices fall back to us-east-1 (and say so)
    assert ctx.volume_cost({"VolumeType": "gp2", "Size": 100, "Iops": 300}) == round(100 * 0.114, 2)
    assert ctx.volume_cost({"VolumeType": "io1", "Size": 100, "Iops": 3000}) == round(100 * 0.131 + 3000 * 0.065, 2)
    io2 = ctx.volume_cost({"VolumeType": "io2", "Size": 10, "Iops": 80000})  # io2 falls back to us-east-1 storage too
    assert io2 == round(10 * 0.125 + (32000 + 0.7 * 32000 + 0.49 * 16000) * 0.065, 2)
    gp3 = ctx.volume_cost({"VolumeType": "gp3", "Size": 100, "Iops": 6000, "Throughput": 250})
    assert gp3 == round(100 * 0.0912 + 3000 * 0.005 + 125 * 0.04, 2)
    assert ctx.volume_cost({"VolumeType": "gp3", "Size": 100, "Iops": 3000, "Throughput": 125}) == round(100 * 0.0912, 2)
    assert any("ebs_iops_month" in n for n in ctx.notes)


def test_gp2_to_gp3_skips_unattached_and_stopped(aws, ctx):
    c = aws.client("ec2")
    ami = c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    bdm = [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 50, "VolumeType": "gp2"}}]
    running = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", BlockDeviceMappings=bdm)["Instances"][0]["InstanceId"]
    stopped = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", BlockDeviceMappings=bdm)["Instances"][0]["InstanceId"]
    c.stop_instances(InstanceIds=[stopped])
    c.create_volume(AvailabilityZone=f"{REGION}a", Size=10, VolumeType="gp2")  # unattached: EBS-001's job
    out = list(ebs.gp2_to_gp3(ctx))
    assert len(out) == 1 and running in out[0].detail
    assert out[0].est_monthly_savings == round(50 * (0.114 - 0.0912), 2)
    assert "--iops" not in out[0].fix_command


def test_gp2_to_gp3_matches_iops_of_big_volumes(aws, ctx):
    c = aws.client("ec2")
    ami = c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    bdm = [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 2000, "VolumeType": "gp2"}}]
    c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", BlockDeviceMappings=bdm)
    out = list(ebs.gp2_to_gp3(ctx))
    # 2,000 GiB gp2 = 6,000 IOPS; gp3 needs 3,000 extra IOPS (us-east-1 price as fallback)
    assert out[0].est_monthly_savings == round(2000 * (0.114 - 0.0912) - 3000 * 0.005, 2)
    assert out[0].fix_command.endswith("--volume-type gp3 --iops 6000")


def test_old_snapshots_respect_age_and_ami(aws, ctx, now):
    c = aws.client("ec2")
    be = ec2_backends[ACCOUNT][REGION]
    v = c.create_volume(AvailabilityZone=f"{REGION}a", Size=20)["VolumeId"]
    old = c.create_snapshot(VolumeId=v)["SnapshotId"]
    new = c.create_snapshot(VolumeId=v)["SnapshotId"]
    be.snapshots[old].start_time = now - dt.timedelta(days=200)
    image = c.register_image(Name="x", RootDeviceName="/dev/xvda")["ImageId"]
    ami_snap = c.describe_images(ImageIds=[image])["Images"][0]["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"]
    be.snapshots[ami_snap].start_time = now - dt.timedelta(days=300)
    out = ids(ebs.old_snapshots(ctx))
    assert old in out and new not in out and ami_snap not in out


def test_idle_eip(aws, ctx):
    c = aws.client("ec2")
    free = c.allocate_address(Domain="vpc")["AllocationId"]
    out = list(ec2.idle_eips(ctx))
    assert ids(out) == [free] and out[0].est_monthly_savings == 3.65


def test_stopped_instance_threshold(aws, ctx, now):
    c = aws.client("ec2")
    ami = c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iid = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    c.stop_instances(InstanceIds=[iid])
    assert list(ec2.stopped_instances(ctx)) == []  # stopped just now
    be = ec2_backends[ACCOUNT][REGION]
    be.get_instance(iid)._reason = f"User initiated ({(now - dt.timedelta(days=45)):%Y-%m-%d %H:%M:%S} GMT)"
    out = list(ec2.stopped_instances(ctx))
    assert ids(out) == [iid] and "45 days" in out[0].detail
    cmd = out[0].fix_command  # terminate only once the AMI backup is available
    assert cmd.index("create-image") < cmd.index("wait image-available") < cmd.index("terminate-instances")


def _cpu(aws, iid, value, now, days=10):
    cw = aws.client("cloudwatch")
    cw.put_metric_data(Namespace="AWS/EC2", MetricData=[
        {"MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": iid}],
         "Timestamp": now - dt.timedelta(days=d, hours=1), "Value": value} for d in range(1, days + 1)])


def test_idle_and_previous_generation(aws, ctx, now):
    c = aws.client("ec2")
    ami = c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    idle = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t2.micro")["Instances"][0]["InstanceId"]
    busy = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    nodata = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    _cpu(aws, idle, 1.0, now)
    _cpu(aws, busy, 40.0, now)
    assert ids(ec2.idle_instances(ctx)) == [idle]
    prev = list(ec2.previous_generation(ctx))
    assert ids(prev) == [idle] and "t3.micro" in prev[0].detail
    assert prev[0].est_monthly_savings == round((0.0124 - 0.0112) * 730, 2)
    cmd = prev[0].fix_command  # the type can only be changed once the instance is fully stopped
    assert cmd.index("stop-instances") < cmd.index("wait instance-stopped") < cmd.index("modify-instance-attribute")
    assert nodata not in ids(prev)


def test_idle_load_balancer(aws, ctx):
    c = aws.client("ec2")
    subnets = [s["SubnetId"] for s in c.describe_subnets()["Subnets"][:2]]
    vpc = c.describe_subnets()["Subnets"][0]["VpcId"]
    elb = aws.client("elbv2")
    lb = elb.create_load_balancer(Name="empty", Subnets=subnets, Type="application")["LoadBalancers"][0]
    elb.create_target_group(Name="empty-tg", Protocol="HTTP", Port=80, VpcId=vpc)
    out = list(network.idle_load_balancers(ctx))
    assert ids(out) == ["empty"]
    assert out[0].est_monthly_savings == round(0.0225 * 730, 2)  # us-east-1 fallback price
    assert any("alb_hour" in n for n in ctx.notes)
    assert lb["LoadBalancerArn"] in out[0].fix_command


def test_idle_nat_gateway(aws, ctx, now):
    c = aws.client("ec2")
    sub = c.describe_subnets()["Subnets"][0]["SubnetId"]
    idle, downloads = (
        c.create_nat_gateway(SubnetId=sub, AllocationId=c.allocate_address(Domain="vpc")["AllocationId"])["NatGateway"]["NatGatewayId"]
        for _ in range(2)
    )
    # A NAT used for downloads sends little out but brings a lot in: it is busy, not idle.
    aws.client("cloudwatch").put_metric_data(Namespace="AWS/NATGateway", MetricData=[
        {"MetricName": metric, "Dimensions": [{"Name": "NatGatewayId", "Value": downloads}],
         "Timestamp": now - dt.timedelta(days=d, hours=1), "Value": value}
        for d in range(1, 8)
        for metric, value in [("BytesOutToDestination", 20 * 1024 ** 2), ("BytesInFromDestination", 3 * 1024 ** 3)]])
    out = list(network.idle_nat_gateways(ctx))
    assert ids(out) == [idle] and out[0].est_monthly_savings == round(0.056 * 730, 2)


def test_idle_rds(aws, ctx, now):
    rds = aws.client("rds")
    for dbid, conns in [("used", 5), ("idle", 0)]:
        rds.create_db_instance(DBInstanceIdentifier=dbid, DBInstanceClass="db.t4g.micro", Engine="postgres",
                               AllocatedStorage=20, MasterUsername="u", MasterUserPassword="password123")
        aws.client("cloudwatch").put_metric_data(Namespace="AWS/RDS", MetricData=[
            {"MetricName": "DatabaseConnections", "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": dbid}],
             "Timestamp": now - dt.timedelta(days=d, hours=1), "Value": conns} for d in range(1, 8)])
    out = list(data.idle_rds(ctx))
    assert ids(out) == ["idle"]
    assert out[0].est_monthly_savings == round(0.021 * 730 + 20 * 0.114, 2)


def test_log_retention_and_s3(aws, ctx):
    logs = aws.client("logs")
    logs.create_log_group(logGroupName="/forever")
    logs.create_log_group(logGroupName="/kept")
    logs.put_retention_policy(logGroupName="/kept", retentionInDays=30)
    assert ids(data.log_retention(ctx)) == ["/forever"]

    s3 = aws.client("s3")
    for b in ("plain-bucket-x", "clean-bucket-x"):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_bucket_lifecycle_configuration(Bucket="clean-bucket-x", LifecycleConfiguration={"Rules": [
        {"ID": "a", "Status": "Enabled", "Filter": {}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]})
    assert ids(data.s3_lifecycle(ctx)) == ["plain-bucket-x"]


def test_s3_denied_bucket_is_reported_not_hidden(aws, ctx):
    from botocore.exceptions import ClientError

    s3 = aws.client("s3")
    for b in ("open-bucket-x", "locked-bucket-x"):
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": REGION})
    client = ctx.client("s3")
    real = client.get_bucket_lifecycle_configuration

    def lifecycle(Bucket):  # noqa: N803 - boto3 parameter name
        if Bucket == "locked-bucket-x":  # e.g. a bucket policy that denies the auditor
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketLifecycleConfiguration")
        return real(Bucket=Bucket)

    client.get_bucket_lifecycle_configuration = lifecycle
    assert ids(data.s3_lifecycle(ctx)) == ["open-bucket-x"]
    assert any("locked-bucket-x" in n and "AccessDenied" in n for n in ctx.notes)
