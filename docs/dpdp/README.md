# DPDP technical safeguards check (India variant of service S8)

India's Digital Personal Data Protection Rules, 2025 were notified on 13 November 2025. Most duties,
including reasonable security safeguards and breach intimation, apply 18 months later - around
**13 May 2027**. Failing to take reasonable security safeguards can attract a penalty of up to ₹250 crore,
and a detailed breach report is due to the Data Protection Board within 72 hours of becoming aware of a breach.

This check covers only what can be inspected in an AWS account. It is **technical readiness, not legal
advice and not a compliance certificate.**

```bash
billdoctor security scan --role-arn <arn> --external-id <id> --regions all --label "Client" --dpdp --out audits/client/dpdp
```

## What is checked, and how it maps

| Safeguard area | What the Rules expect (summary) | Controls |
|---|---|---|
| Encryption, masking and secrets | Personal data protected by encryption, obfuscation, masking or tokens | DA-01, DA-03, DA-04, SP-01, SP-02 |
| Access control | Access limited to those who need it, with strong authentication | ID-01 to ID-07, DA-02, DA-05, NC-01 to NC-04, SP-03 |
| Logging and monitoring | Visibility of access through logs, monitoring and review; logs kept at least one year | LD-01, LD-03, LD-04 |
| Backups and continuity | Processing can continue if confidentiality, integrity or availability is compromised | DA-04, plus a tested restore (manual; service S4) |
| Breach detection and response | Detect a breach, inform affected people and the Board, detailed report within 72 hours | LD-01, LD-02, LD-05, plus the runbook (manual) |

## What is outside this check (say so in writing)

- Consent and notices, children's data, Data Principal rights, retention of personal data itself.
- Contracts with Data Processors and cross-border transfer rules.
- Application code, databases' contents and endpoints outside AWS.
- Whether the company is a Significant Data Fiduciary, and anything requiring legal interpretation.

Recommend a lawyer for these. Deliver [`breach-runbook-72h.md`](breach-runbook-72h.md) with the report,
filled in with the client during the walkthrough.
