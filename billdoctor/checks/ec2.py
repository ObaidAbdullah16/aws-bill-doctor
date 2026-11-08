"""EC2 instance and public IP checks."""
from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable

from ..models import HOURS_PER_MONTH, Finding, ScanContext, check
from ..pricing import UPGRADE_PATH

STOP_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:GMT|UTC)\)")


def _instances(ctx: ScanContext, state: str) -> list[dict]:
    res = ctx.paginate("ec2", "describe_instances", "Reservations",
                       Filters=[{"Name": "instance-state-name", "Values": [state]}])
    return [i for r in res for i in r.get("Instances", [])]


def _name(inst: dict) -> str:
    for t in inst.get("Tags", []) or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


@check("EC2-001", "Unassociated Elastic IPs", "EC2",
       "Since February 2024 every public IPv4 address costs $0.005/hour; an Elastic IP attached to nothing is pure waste.")
def idle_eips(ctx: ScanContext) -> Iterable[Finding]:
    hourly = ctx.money("public_ipv4_hour")
    for a in ctx.client("ec2").describe_addresses().get("Addresses", []):
        if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
            continue
        cost = round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
        alloc = a.get("AllocationId", a.get("PublicIp"))
        yield Finding(
            check_id="EC2-001", title="Elastic IP not associated", region=ctx.region,
            resource_type="elastic-ip", resource_id=alloc, detail=f"{a.get('PublicIp')} is not attached to anything",
            recommendation="Release it unless an allow-list somewhere depends on this exact IP.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="medium",
            fix_command=f"aws ec2 release-address --region {ctx.region} --allocation-id {alloc}",
        )


@check("EC2-002", "Long-stopped instances still paying for disks", "EC2",
       "A stopped instance costs nothing for compute, but its EBS volumes are billed in full.")
def stopped_instances(ctx: ScanContext) -> Iterable[Finding]:
    ec2 = ctx.client("ec2")
    for inst in _instances(ctx, "stopped"):
        m = STOP_RE.search(inst.get("StateTransitionReason", "") or "")
        stopped_days = None
        if m:
            when = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
            stopped_days = (ctx.now - when).days
            if stopped_days < ctx.stopped_days:
                continue
        vol_ids = [b["Ebs"]["VolumeId"] for b in inst.get("BlockDeviceMappings", []) if "Ebs" in b]
        cost = 0.0
        known = True
        if vol_ids:
            for v in ec2.describe_volumes(VolumeIds=vol_ids).get("Volumes", []):
                p = ctx.volume_cost(v)
                if p is None:
                    known = False
                else:
                    cost += p
        cost_val = round(cost, 2) if known else None
        since = f"{stopped_days} days" if stopped_days is not None else "an unknown time"
        name = _name(inst)
        yield Finding(
            check_id="EC2-002", title="Instance stopped for a long time", region=ctx.region,
            resource_type="ec2-instance", resource_id=inst["InstanceId"],
            detail=f"{inst['InstanceType']}{' (' + name + ')' if name else ''} stopped for {since}, {len(vol_ids)} volume(s) attached",
            recommendation="If it is not coming back: create an AMI (keeps a restorable copy), then terminate the instance. "
                           "Volumes with 'delete on termination' turned off survive the termination; delete them too "
                           "(the AMI holds a copy) or they show up as unattached volumes next time.",
            monthly_cost=cost_val, est_monthly_savings=cost_val, fix_risk="high",
            # Terminate only after the AMI (and its snapshots) is available.
            fix_command=(f"IMG=$(aws ec2 create-image --region {ctx.region} --instance-id {inst['InstanceId']} "
                         f"--name billdoctor-{inst['InstanceId']} --query ImageId --output text) && "
                         f"aws ec2 wait image-available --region {ctx.region} --image-ids \"$IMG\" && "
                         f"aws ec2 terminate-instances --region {ctx.region} --instance-ids {inst['InstanceId']}"),
        )


@check("EC2-003", "Idle running instances", "EC2",
       "Instances averaging under 5% CPU (and never above 20%) for two weeks are usually forgotten or oversized.")
def idle_instances(ctx: ScanContext) -> Iterable[Finding]:
    for inst in _instances(ctx, "running"):
        iid, itype = inst["InstanceId"], inst["InstanceType"]
        avgs = ctx.metric("AWS/EC2", "CPUUtilization", {"InstanceId": iid}, "Average")
        maxes = ctx.metric("AWS/EC2", "CPUUtilization", {"InstanceId": iid}, "Maximum")
        if len(avgs) < 3:   # not enough data to judge
            continue
        avg, peak = sum(avgs) / len(avgs), max(maxes or [0])
        if avg >= 5 or peak >= 20:
            continue
        hourly = ctx.money("ec2_hour", itype)
        cost = round(hourly * HOURS_PER_MONTH, 2) if hourly is not None else None
        name = _name(inst)
        yield Finding(
            check_id="EC2-003", title="Instance looks idle", region=ctx.region,
            resource_type="ec2-instance", resource_id=iid,
            detail=f"{itype}{' (' + name + ')' if name else ''}: average CPU {avg:.1f}%, peak {peak:.1f}% over {len(avgs)} days",
            recommendation="Confirm with the owner. Then stop it, schedule it (office hours only), or downsize. "
                           "Saving shown assumes it can be stopped.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="high",
            fix_command=f"aws ec2 stop-instances --region {ctx.region} --instance-ids {iid}",
        )


@check("EC2-004", "Previous-generation instance types", "EC2",
       "Older families (t2, m4, c4, r4...) cost more for less performance than their current replacements.")
def previous_generation(ctx: ScanContext) -> Iterable[Finding]:
    for inst in _instances(ctx, "running"):
        itype = inst["InstanceType"]
        family, _, size = itype.partition(".")
        new_family = UPGRADE_PATH.get(family)
        if not new_family:
            continue
        new_type = f"{new_family}.{size}"
        old_p, new_p = ctx.money("ec2_hour", itype), ctx.money("ec2_hour", new_type)
        cost = round(old_p * HOURS_PER_MONTH, 2) if old_p is not None else None
        saving = round((old_p - new_p) * HOURS_PER_MONTH, 2) if old_p is not None and new_p is not None else None
        yield Finding(
            check_id="EC2-004", title="Previous-generation instance type", region=ctx.region,
            resource_type="ec2-instance", resource_id=inst["InstanceId"],
            detail=f"{itype} -> {new_type}",
            recommendation=f"Change the instance type to {new_type} during a maintenance window (stop, change type, start). "
                           + ("" if new_p is not None else f"Check that {new_type} exists in {ctx.region} first (not every size has a "
                              "current-generation twin). ")
                           + "Newer types run on Nitro: very old AMIs need the ENA and NVMe drivers (current images have them). "
                             "A stop/start changes the public IP unless it is an Elastic IP. "
                             "Graviton (t4g/m7g) is cheaper still if the software runs on ARM.",
            monthly_cost=cost, est_monthly_savings=saving, fix_risk="medium",
            fix_command=(f"aws ec2 stop-instances --region {ctx.region} --instance-ids {inst['InstanceId']} && "
                         f"aws ec2 wait instance-stopped --region {ctx.region} --instance-ids {inst['InstanceId']} && "
                         f"aws ec2 modify-instance-attribute --region {ctx.region} --instance-id {inst['InstanceId']} "
                         f"--instance-type Value={new_type} && "
                         f"aws ec2 start-instances --region {ctx.region} --instance-ids {inst['InstanceId']}"),
        )
