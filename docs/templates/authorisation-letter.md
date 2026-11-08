# Authorisation for a read-only security and cost review

*Template. An editable Word version is in the private delivery kit. Not legal advice: have your own
lawyer review it before first use, and adapt it to the client's jurisdiction.*

**Date:** {date}

**From (the Client):** {legal company name}, {registered address} ("the Client")
**To (the Reviewer):** Obaid Abdullah, {address}, {email} ("the Reviewer")

## 1. Authorisation

The Client authorises the Reviewer to perform the read-only review described below on the systems listed in
section 2, during the period in section 4. The Client confirms that it owns or is entitled to authorise
access to these systems.

## 2. Systems in scope

| System | Identifier | Regions / notes |
|---|---|---|
| AWS account | {123456789012} | {ap-south-1, us-east-1 / all enabled regions} |
| GitHub repositories (if S2 is included) | {org/repo} | {read access or pull requests only} |
| Domains (if the email add-on is included) | {example.com} | public DNS only |

Anything not listed is out of scope, including production data, other accounts, employees' devices and
third-party services.

## 3. Activities

**Permitted:** assuming the read-only role `BillDoctorReadOnly` created by the Client (with an external ID);
read-only API calls that list and describe configuration (AWS-managed SecurityAudit and ViewOnlyAccess
policies and the extra read permissions in the template); reading public DNS records; static review of
configuration or code the Client provides.

**Not permitted:** any change to the systems; reading stored data (S3 objects, database rows, secret values,
log contents - the role denies these explicitly); exploitation of any finding; load or denial-of-service
testing; social engineering; scanning hosts or applications from the internet; using any credential found.

## 4. Period and contacts

Access from {start date} to {end date}. The Client deletes the role at the end of the period.

| | Client | Reviewer |
|---|---|---|
| Primary contact | {name, role, phone, email} | Obaid Abdullah, {phone}, {email} |
| Emergency contact | {name, phone} | |

The Reviewer stops immediately if the Client asks, and reports at once any sign of an active compromise.

## 5. Data handling

Scan results are configuration metadata. They are stored only on the Reviewer's encrypted device, shared only
with the contacts above, and deleted {30} days after delivery of the final report, confirmed in writing.
Credentials found during the review are reported by location and type only and are never used or copied.

## 6. Confidentiality

The Reviewer keeps the findings confidential and will not describe the engagement publicly except with the
Client's written permission and in anonymised form.

## 7. Limits

The review reflects the configuration at the time of the scan. It is not a penetration test, not a
guarantee against breaches, and not legal advice or a certificate of compliance. The Reviewer's total
liability is limited to the fees paid for this engagement.

## 8. Signatures

Signed for the Client by a person authorised to grant access to the systems above:

Name: {name} · Title: {founder / CTO / director} · Signature: ______________ · Date: ______

Reviewer: Obaid Abdullah · Signature: ______________ · Date: ______
