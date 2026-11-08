"""EBS volume and snapshot checks."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from ..models import Finding, ScanContext, check


def _name(tags: list[dict] | None) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


@check("EBS-001", "Unattached EBS volumes", "EC2",
       "Volumes in the 'available' state are billed every month but serve nothing - often left behind by deleted instances.")
def unattached_volumes(ctx: ScanContext) -> Iterable[Finding]:
    vols = ctx.paginate("ec2", "describe_volumes", "Volumes", Filters=[{"Name": "status", "Values": ["available"]}])
    for v in vols:
        cost = ctx.volume_cost(v)  # storage + provisioned IOPS/throughput
        name = _name(v.get("Tags"))
        yield Finding(
            check_id="EBS-001", title="Unattached EBS volume", region=ctx.region,
            resource_type="ebs-volume", resource_id=v["VolumeId"],
            detail=(f"{v['Size']} GiB {v['VolumeType']}"
                    f"{', ' + format(v['Iops'], ',') + ' provisioned IOPS' if v['VolumeType'] in ('io1', 'io2') and v.get('Iops') else ''}"
                    f"{' (' + name + ')' if name else ''}, not attached to any instance"),
            recommendation="Confirm with the owner, snapshot it (cheap insurance), then delete the volume. The command waits for "
                           "the snapshot to finish (up to 10 minutes); if the wait times out, delete the volume once the snapshot "
                           "shows 'completed'. Delete the snapshot too after a month or two if nobody needs it.",
            monthly_cost=cost, est_monthly_savings=cost, fix_risk="medium",
            # Delete only after the snapshot has completed: if it fails or the wait times out, nothing is deleted.
            fix_command=(f"SNAP=$(aws ec2 create-snapshot --region {ctx.region} --volume-id {v['VolumeId']} "
                         f"--description 'billdoctor: backup before delete' --query SnapshotId --output text) && "
                         f"aws ec2 wait snapshot-completed --region {ctx.region} --snapshot-ids \"$SNAP\" && "
                         f"aws ec2 delete-volume --region {ctx.region} --volume-id {v['VolumeId']}"),
        )


@check("EBS-002", "gp2 volumes that should be gp3", "EC2",
       "gp3 is about 20% cheaper than gp2 per GiB and has a 3,000 IOPS baseline regardless of size. The change is online.")
def gp2_to_gp3(ctx: ScanContext) -> Iterable[Finding]:
    vols = ctx.paginate("ec2", "describe_volumes", "Volumes", Filters=[{"Name": "volume-type", "Values": ["gp2"]}])
    # Unattached volumes are covered by EBS-001 (delete), and volumes of long-stopped
    # instances by EC2-002 (terminate); counting them here too would double the savings.
    stopped = {
        i["InstanceId"]
        for r in ctx.paginate("ec2", "describe_instances", "Reservations",
                              Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])
        for i in r.get("Instances", [])
    }
    gp2, gp3 = ctx.money("ebs_gb_month", "gp2"), ctx.money("ebs_gb_month", "gp3")
    gp3_iops = ctx.money("ebs_iops_month", "gp3")
    for v in vols:
        attached_to = [a.get("InstanceId") for a in v.get("Attachments", [])]
        if v.get("State") == "available" or any(i in stopped for i in attached_to):
            continue
        size = v["Size"]
        # gp2 gives 3 IOPS per GiB (100 minimum, 16,000 maximum); gp3 includes 3,000. Bigger
        # volumes need IOPS bought on gp3 to stay as fast, which reduces the saving.
        gp2_iops = min(max(3 * size, 100), 16000)
        extra_iops = max(gp2_iops - 3000, 0)
        cost = round(size * gp2, 2) if gp2 is not None else None
        saving = None
        if gp2 is not None and gp3 is not None and gp3_iops is not None:
            saving = round(size * (gp2 - gp3) - extra_iops * gp3_iops, 2)
            if saving <= 0:
                continue  # not cheaper once performance is matched
        note = ""
        if extra_iops:
            note += f" The command sets --iops {gp2_iops} to match this volume's gp2 performance (included in the saving)."
        if size > 170:
            note += (" gp2 volumes over 170 GiB can reach 250 MiB/s and gp3 includes 125 MiB/s; "
                     "add --throughput 250 (a small extra cost) if the workload reads or writes a lot.")
        yield Finding(
            check_id="EBS-002", title="gp2 volume can move to gp3", region=ctx.region,
            resource_type="ebs-volume", resource_id=v["VolumeId"],
            detail=f"{size} GiB gp2 attached to {', '.join(i for i in attached_to if i) or 'an instance'}",
            recommendation="Modify the volume to gp3 (no downtime)." + note,
            monthly_cost=cost, est_monthly_savings=saving, fix_risk="low",
            fix_command=(f"aws ec2 modify-volume --region {ctx.region} --volume-id {v['VolumeId']} --volume-type gp3"
                         + (f" --iops {gp2_iops}" if extra_iops else "")),
        )


@check("EBS-003", "Old EBS snapshots", "EC2",
       "Snapshots older than the retention you need, and not used by an AMI, keep costing storage forever.")
def old_snapshots(ctx: ScanContext) -> Iterable[Finding]:
    snaps = ctx.paginate("ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"])
    images = ctx.client("ec2").describe_images(Owners=["self"]).get("Images", [])
    in_use = {
        bdm["Ebs"]["SnapshotId"]
        for img in images
        for bdm in img.get("BlockDeviceMappings", [])
        if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
    }
    cutoff = ctx.now - dt.timedelta(days=ctx.snapshot_age_days)
    price = ctx.money("snapshot_gb_month")
    for s in snaps:
        start = s["StartTime"]
        if start.tzinfo is None:
            start = start.replace(tzinfo=dt.timezone.utc)
        if start > cutoff or s["SnapshotId"] in in_use:
            continue
        age = (ctx.now - start).days
        # Snapshots are incremental, so the volume size is an upper bound of what this one stores.
        upper = round(s.get("VolumeSize", 0) * price, 2) if price is not None else None
        yield Finding(
            check_id="EBS-003", title="Old snapshot not used by any AMI", region=ctx.region,
            resource_type="ebs-snapshot", resource_id=s["SnapshotId"],
            detail=f"{age} days old, from a {s.get('VolumeSize', '?')} GiB volume. {s.get('Description', '')[:80]}".strip(),
            recommendation="Keep only what your retention policy needs (e.g. 30-90 days) - set up Amazon Data Lifecycle Manager "
                           "instead of manual snapshots. Saving shown is an upper bound (snapshots are incremental).",
            monthly_cost=upper, est_monthly_savings=upper, fix_risk="medium",
            fix_command=f"aws ec2 delete-snapshot --region {ctx.region} --snapshot-id {s['SnapshotId']}",
        )
