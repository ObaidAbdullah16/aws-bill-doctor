# AWS Bill Doctor report - account Acme Retail (synthetic demo)

> **SYNTHETIC DEMO DATA.** Generated against a simulated AWS account; no real customer data.

- Regions: ap-south-1, us-east-1
- Scanned: 2026-11-02 11:39 UTC
- **Estimated savings: $616.37/month ($7,396.44/year)**
- Findings: 20 (high 4, medium 7, low 5, info 4)

## Top findings

| Priority | Check | Resource | Region | Saving / month | Detail |
|---|---|---|---|---|---|
| high | EBS-001 | `vol-61b83803386704d04` | ap-south-1 | $208.10 | 100 GiB io1, 3,000 provisioned IOPS (perf-test), not attached to any instance |
| high | EBS-001 | `vol-d5ad5396436612ce5` | us-east-1 | $100.00 | 1000 GiB gp2 (forgotten-ml-dataset), not attached to any instance |
| high | EC2-003 | `i-1222cd8a252d8edc1` | ap-south-1 | $72.42 | t2.large (legacy-reporting): average CPU 2.7%, peak 7.5% over 13 days |
| high | RDS-001 | `analytics-copy` | ap-south-1 | $63.96 | db.t3.medium postgres 100 GiB: 0 connections in 13 days |
| medium | EBS-001 | `vol-8f632793cccc4eedc` | ap-south-1 | $45.60 | 500 GiB gp3 (migration-temp), not attached to any instance |
| medium | NAT-001 | `nat-95a718f3d35a4e2d8` | ap-south-1 | $40.88 | moved 0.51 GB (in + out) in 14 days (VPC vpc-0527c2ef9d79f9cd3) |
| medium | EBS-001 | `vol-021fe5f4debe2e734` | ap-south-1 | $22.80 | 200 GiB gp2 (old-jenkins-data), not attached to any instance |
| medium | ELB-001 | `old-promo-alb` | ap-south-1 | $16.43 | application load balancer with 1 target group(s) and 0 registered targets |
| medium | EC2-002 | `i-8891acb15ab0eabd4` | ap-south-1 | $13.68 | t3.large (old-build-agent) stopped for 75 days, 1 volume(s) attached |
| medium | EBS-003 | `snap-623da09cda0b9887a` | ap-south-1 | $10.00 | 410 days old, from a 200 GiB volume. pre-migration backup 2025 |
| medium | EBS-003 | `snap-d93c9fe1018b66a97` | ap-south-1 | $10.00 | 220 days old, from a 200 GiB volume. manual backup before upgrade |
| low | EC2-004 | `i-1222cd8a252d8edc1` | ap-south-1 | $7.01 | t2.large -> t3.large |
| low | EC2-001 | `eipalloc-0076a7c9852db02a4` | ap-south-1 | $3.65 | 127.184.176.136 is not attached to anything |
| low | EC2-001 | `eipalloc-689a9541a3f86cde3` | us-east-1 | $3.65 | 127.43.70.107 is not attached to anything |
| low | EC2-004 | `i-a6d48966bc3c7556b` | ap-south-1 | $2.92 | m4.large -> m6i.large |

## Quick wins (low-risk fixes)

- **EBS-002** `vol-7128ec531f6695580`: Modify the volume to gp3 (no downtime).  
  `aws ec2 modify-volume --region ap-south-1 --volume-id vol-7128ec531f6695580 --volume-type gp3`

## Method

Read-only API calls; prices are approximate on-demand list prices (2026-10). Savings are estimates - confirm with the resource owner and snapshot before deleting anything.
- Note: ap-south-1: no local price for ebs_iops_month/io1; used us-east-1 as an approximation
- Note: ap-south-1: no local price for ebs_iops_month/gp3; used us-east-1 as an approximation
- Note: ap-south-1: no local price for ec2_hour/m4.large; used us-east-1 as an approximation
- Note: ap-south-1: no local price for ec2_hour/m6i.large; used us-east-1 as an approximation
- Note: ap-south-1: no local price for alb_hour; used us-east-1 as an approximation
- Note: ap-south-1: no local price for logs_gb_month; used us-east-1 as an approximation
- Note: ap-south-1: no local price for rds_hour/db.t3.medium; used us-east-1 as an approximation
