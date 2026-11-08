# Service S8 - AWS Security Baseline Check

**Promise:** "A read-only review of the 25 AWS settings behind most cloud breaches. You get a scored report,
every fix as code, and a retest - in one week."

| Package | Includes | Founding (first 3) | Standard | India |
|---|---|---|---|---|
| Snapshot | One account, up to two regions: scan, human review, scored report, top 5 risks, a fix for every finding | $149 | $300-450 | ₹9-15k |
| Standard | Snapshot + fix pack (Terraform/CLI) + 45-minute walkthrough + retest | $299 | $600-900 | ₹15-30k |
| AWS Health Check | S1 cost audit + S8 Standard, one role, one combined report | $399 | $750-1,200 | ₹25-45k |
| DPDP technical check (India) | Standard, DPDP wording and safeguard view, 72-hour breach runbook | - | - | ₹15-40k |
| Questionnaire pack (add-on) | Answers and evidence for the cloud section of a customer's security questionnaire | +$75 | +$150-250 | +₹5k |

## Before anything: paperwork (Day 0)

1. Free 15-minute call. Ask: how many accounts and regions, who owns them, what must not be touched,
   whether a customer or auditor is asking (that decides the deadline and the questionnaire add-on).
2. Send the **statement of work** and the **authorisation letter** (`docs/templates/`). Do not accept a role ARN
   until the signed letter is back: it names the account IDs, regions, read-only activities, dates and
   data-retention period, and is signed by someone with authority (founder or CTO).
3. Send `client-access/cloudformation-readonly-role.yaml` with `EnableSecurityCheck=true`, your AWS account ID
   and a fresh external ID (`openssl rand -hex 16`). One line for the client:
   *"It can read configuration, never data, cannot change anything, and you delete it when we are done.
   Your own CloudTrail records every call I make."*

## Day 1 - scan

```bash
pipx install prowler                     # once; Prowler is a separate tool (Apache-2.0)
billdoctor security scan \
  --role-arn arn:aws:iam::<client>:role/BillDoctorReadOnly --external-id <id> \
  --regions all --label "Client name" --out audits/<client>/security
# Health Check bundle instead (cost + security, one summary page):
billdoctor health-check --role-arn ... --external-id <id> --regions all --label "Client name" --out audits/<client>
# Indian startup, DPDP wording:  add --dpdp
```

Raw Prowler output is deleted after conversion unless you pass `--keep-raw`. The report keeps finding
messages only: Lambda variable values and user data are never copied into it.

## Day 2 - review (what they pay for)

1. Open `report.html`. For every critical and high control, confirm the evidence by hand.
2. Remove false positives and record intended exceptions (a public website bucket behind CloudFront is not
   a leak; a bastion with SSH limited to an office IP is a decision). Note them in the walkthrough deck,
   never by editing the JSON.
3. Rank the top five for *this* company: a startup with customer data in RDS cares about DA-04 before ID-06.
4. Prepare the fix pack: `aws-foundation/modules/security-baseline` inputs for what they want fixed, plus
   CLI or console steps from the report for one-off items. If they have Terraform, open a pull request
   against their repository instead.

## Day 3 - deliver

- PDF (browser print of `report.html`) + `findings.csv` + the fix pack + a 45-minute walkthrough.
- They apply the fixes. You never need write access; offer a screen share with **their hands on the keyboard**.

## Day 7-14 - retest

```bash
billdoctor security scan --role-arn ... --external-id <id> --regions all --label "Client name" \
  --previous audits/<client>/security/findings.json --out audits/<client>/security-retest
```

The retest report shows the score change and every control fixed, still open or new. Then:

1. The client deletes the CloudFormation stack. Confirm it is gone.
2. Delete the scan files after the agreed retention (30 days by default) and send the deletion confirmation
   (`docs/templates/data-deletion-confirmation.md`).
3. Ask for a testimonial and offer the **security care plan** ($50-200/month: monthly re-scan, new-finding alerts,
   one-page report).

## Rules that never bend

- Written authorisation before any non-public check. Read-only role with an external ID only; never root
  passwords, personal logins or access keys.
- Never use a credential you find. Report its location and type; the owner rotates it.
- Never read data. The role has an explicit deny on S3 objects, database rows, secret values and log events.
- No exploitation, no load tests, no "let me just try" on a finding. A baseline check is not a penetration test,
  and the report says so.
- Findings are confidential: encrypted disk, no screenshots of secrets, deleted after the retention period,
  never reused in public case studies without written, anonymised permission.
- DPDP variant: say "technical readiness", never "compliant". Consent, notices and contracts are legal work.
