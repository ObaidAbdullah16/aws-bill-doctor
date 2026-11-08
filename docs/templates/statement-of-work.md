# Statement of work: {AWS Security Baseline Check - Standard}

*Template. Editable Word version in the private delivery kit.*

**Client:** {company} · **Provider:** Obaid Abdullah · **Date:** {date} · **Reference:** {S8-2026-001}

## Objective

An independent, read-only review of {one AWS account, two regions} against 25 baseline security controls,
with fixes delivered as code and a retest.

## Deliverables

1. Scored report (HTML and PDF) with the top five risks in plain language and evidence for each finding.
2. `findings.csv` for the Client's tracker.
3. Fix pack: Terraform inputs for the security-baseline module and CLI or console steps for one-off items
   {or: a pull request against the Client's infrastructure repository}.
4. A 45-minute walkthrough call.
5. A retest scan within {14} days of the walkthrough, with an updated report showing fixed and open items.
{6. DPDP view and a 72-hour breach runbook template (India variant).}
{7. Answers for the cloud section of the customer's security questionnaire (add-on).}

## Out of scope

Penetration testing, incident response, changes to the Client's systems by the Provider, application code
review, compliance certification and legal advice.

## Timeline

| Day | Activity |
|---|---|
| 0 | Signed SOW and authorisation letter; Client creates the read-only role |
| 1 | Scan |
| 2 | Human review of every finding |
| 3 | Report, fix pack and walkthrough |
| 7-14 | Retest; Client deletes the role; scan files deleted after {30} days |

## Price and payment

{$299 / ₹15,000} fixed price. 50% on signature, 50% on delivery of the report. The retest is included if it
happens within 30 days. Payment by {bank transfer / Wise / Razorpay invoice}.
{Founding-client price, in exchange for an honest testimonial and permission to describe the work anonymously.}

## Client responsibilities

Create and later delete the read-only role; name a contact who can answer questions within one working day;
apply fixes the Client chooses to apply.

## Acceptance

The work is complete when the report and fix pack are delivered and the walkthrough has taken place, or
{5} working days after delivery if the Client does not schedule the walkthrough.

Signed: ______________ (Client) · ______________ (Provider)
