"""Load balancer and NAT gateway checks."""
from __future__ import annotations

from collections.abc import Iterable

from botocore.exceptions import ClientError

from ..models import HOURS_PER_MONTH, Finding, ScanContext, check

GB = 1024 ** 3


@check("ELB-001", "Load balancers with no targets", "ELB",
       "A load balancer is billed by the hour even when nothing is registered behind it.")
def idle_load_balancers(ctx: ScanContext) -> Iterable[Finding]:
    elbv2 = ctx.client("elbv2")
    for lb in ctx.paginate("elbv2", "describe_load_balancers", "LoadBalancers"):
        arn, kind = lb["LoadBalancerArn"], lb.get("Type", "application")
        try:
            tgs = elbv2.describe_target_groups(LoadBalancerArn=arn).get("TargetGroups", [])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "TargetGroupNotFound":
                raise
            tgs = []  # no target group attached at all
        targets = 0
        for tg in tgs:
            targets += len(elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", []))
        if targets:
            continue
        hourly = ctx.money("nlb_hour" if kind == "network" else "alb_hour")
        cost = round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
        yield Finding(
            check_id="ELB-001", title="Load balancer has no targets", region=ctx.region,
            resource_type=f"{kind}-load-balancer", resource_id=lb["LoadBalancerName"],
            detail=f"{kind} load balancer with {len(tgs)} target group(s) and 0 registered targets",
            recommendation="Delete it if the service is gone. First check DNS records pointing at it, and its listener rules: "
                           "a load balancer without targets can still serve redirects or fixed responses.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="medium",
            fix_command=f"aws elbv2 delete-load-balancer --region {ctx.region} --load-balancer-arn {arn}",
        )
    # Classic load balancers
    try:
        classic = ctx.client("elb").describe_load_balancers().get("LoadBalancerDescriptions", [])
    except ClientError as e:  # don't lose the ALB/NLB results above; say what was skipped
        ctx.notes.append(f"ELB-001: could not list Classic Load Balancers in {ctx.region} "
                         f"({e.response.get('Error', {}).get('Code', 'ClientError')}); they were not checked")
        classic = []
    for lb in classic:
        if lb.get("Instances"):
            continue
        hourly = ctx.money("clb_hour")
        cost = round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
        yield Finding(
            check_id="ELB-001", title="Classic load balancer has no instances", region=ctx.region,
            resource_type="classic-load-balancer", resource_id=lb["LoadBalancerName"],
            detail="Classic ELB with 0 registered instances",
            recommendation="Delete it, or migrate live services to an Application Load Balancer.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="medium",
            fix_command=f"aws elb delete-load-balancer --region {ctx.region} --load-balancer-name {lb['LoadBalancerName']}",
        )


@check("NAT-001", "Idle NAT gateways", "VPC",
       "A NAT gateway costs ~$33-41/month before any data. Many dev VPCs keep one for traffic that never comes.")
def idle_nat_gateways(ctx: ScanContext) -> Iterable[Finding]:
    nats = ctx.paginate("ec2", "describe_nat_gateways", "NatGateways",
                        Filters=[{"Name": "state", "Values": ["available"]}])
    for n in nats:
        nid = n["NatGatewayId"]
        # Count both directions: a NAT used mostly for downloads (packages, images) sends only
        # small requests out, so outbound bytes alone would make a busy gateway look idle.
        moved = sum(
            sum(ctx.metric("AWS/NATGateway", metric, {"NatGatewayId": nid}, "Sum"))
            for metric in ("BytesOutToDestination", "BytesInFromDestination")
        )
        if moved >= 1 * GB:
            continue
        hourly = ctx.money("nat_hour")
        cost = round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
        yield Finding(
            check_id="NAT-001", title="NAT gateway barely used", region=ctx.region,
            resource_type="nat-gateway", resource_id=nid,
            detail=f"moved {moved / GB:.2f} GB (in + out) in {ctx.lookback_days} days (VPC {n.get('VpcId')})",
            recommendation="Delete it if private subnets do not need the internet; use VPC endpoints for S3/DynamoDB/ECR, "
                           "or public subnets with tight security groups for small dev setups.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="high",
            fix_command=f"aws ec2 delete-nat-gateway --region {ctx.region} --nat-gateway-id {nid}",
        )
