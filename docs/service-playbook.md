# Service S1 - AWS Bill Doctor (cost & waste audit)

**Promise:** "I find AWS waste with read-only access. You get a ranked savings list in 3 days."
**Founding price:** $149-$299 (India: Rs 9k-20k). Savings guarantee only for accounts spending $1,000+/month.

## Day 0 - free 15-minute call

Ask: monthly bill, main services, who owns which environment, anything they must not touch.
Send the client: `client-access/cloudformation-readonly-role.yaml`, your AWS account ID and a random
external ID (`openssl rand -hex 16`). Explain in one line: *"It can list resources and read metrics;
it cannot read your data or change anything, and you delete it when we're done."*

## Day 1 - access and scan

```bash
# client created the stack and sent you the RoleArn
billdoctor scan \
  --role-arn arn:aws:iam::<client>:role/BillDoctorReadOnly --external-id <id> \
  --regions all --label "Client name" --cost-explorer --out audits/client-2026-11
```

- `--regions all` scans every enabled region (forgotten resources hide in regions nobody uses).
- `--cost-explorer` adds the spend-by-service table (one Cost Explorer API call: $0.01 on the client's bill; ask first).

## Day 2 - review (the part that makes it worth paying for)

1. Open `report.html`. For every **high** item, check tags, CloudTrail "last used", and ask the owner.
2. Remove false positives (e.g. a NAT gateway that is idle because it is a DR standby). Note them.
3. Add 3-5 "quick fixes" the client approves; for low-risk ones (gp2 -> gp3, log retention, lifecycle
   rules) offer to do them during a screen share **with their hands on the keyboard**.
4. Print the HTML to PDF (browser print, A4) for the deliverable.

## Day 3 - deliver

- PDF report + `findings.csv` (for their spreadsheet) + a 10-minute walkthrough call.
- Install the budget guard: `terraform/budget-guard` (monthly budget with 80/100% and forecast alerts).
- Ask the client to delete the CloudFormation stack (removes your access). Confirm it is gone.

## Day 30 - follow-up (testimonial moment)

Re-run the scan (they re-create the role, or send a Cost Explorer screenshot). Show before/after
spend. Ask for a testimonial and a referral.

## What never to do

- Never ask for access keys or console passwords. Role + external ID only.
- Never run a delete command yourself. Every `fix_command` is a suggestion for the owner.
- Never promise exact savings; the report says "estimate" for a reason.
