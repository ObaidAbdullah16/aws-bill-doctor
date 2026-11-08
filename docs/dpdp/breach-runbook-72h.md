# Personal data breach runbook: the first 72 hours

**Company:** {Company} · **Version:** {date} · **Owner:** {name, role} · **Review:** every 6 months and after every incident

> Template for the technical side of a breach response. It is not legal advice: the wording and timing of
> notices to the Data Protection Board and to affected people must be confirmed with your lawyer.

## 0. Who decides (fill in before you need it)

| Role | Name | Phone (24/7) | Backup |
|---|---|---|---|
| Incident lead (decides) | | | |
| Technical lead (AWS, logs) | | | |
| Legal / DPDP contact | | | |
| Communications | | | |

Where people report suspicions: {email / Slack channel}. Anyone may raise an alarm; nobody is blamed for a false one.

## Hour 0-4: confirm and contain

- [ ] Start a timeline document: what was seen, by whom, when (UTC and IST).
- [ ] Classify: personal data involved? which systems, roughly how many people? Assume yes until shown otherwise.
- [ ] Contain without destroying evidence: deactivate (do not delete) leaked keys, isolate instances with a
      quarantine security group, snapshot affected volumes before changing them.
- [ ] Rotate credentials that may be exposed: IAM keys, database passwords, CI/CD secrets, third-party API keys.
- [ ] Preserve evidence: CloudTrail logs (bucket with log-file validation), VPC flow logs, application logs,
      GuardDuty findings. Note the S3 paths.

## Hour 4-24: understand

- [ ] From CloudTrail: which identity, which API calls, from which IPs, since when.
- [ ] Which data stores were reachable by that identity; were objects read, copied or shared?
- [ ] Is the attacker still active? Check new IAM users, roles, access keys, regions, instances.
- [ ] Inform the incident lead and legal contact in writing with a one-page summary.

## Hour 24-72: notify and report (with legal review)

- [ ] Intimation to the Data Protection Board without delay, and the detailed report within 72 hours
      (or the period the Board allows): nature, extent, timing, location, likely impact, measures taken,
      findings about the cause, and who to contact.
- [ ] Intimation to each affected Data Principal without delay, in plain language: what happened, likely
      consequences, what you are doing, what they should do, and a contact person.
- [ ] Notify customers or partners your contracts require you to notify.

## After: learn

- [ ] Root cause and fixes, tracked to closure. Retest with the security baseline check.
- [ ] Keep the timeline, evidence and notices for at least one year.
- [ ] Update this runbook and the contacts.

## Evidence locations (fill in)

| Evidence | Where | Retention |
|---|---|---|
| CloudTrail | s3://{bucket}/AWSLogs/ | {365} days |
| GuardDuty findings | {region} console / EventBridge rule | 90 days in GuardDuty, longer if exported |
| Application logs | {log groups} | {365} days |
| Database backups | {RDS automated backups / AWS Backup vault} | {days} |
