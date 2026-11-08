# Deliberately misconfigured demo account

Terraform for a **real** AWS sandbox that contains the usual mistakes, so the security baseline check has
something true to find. It produces `sample-security-report-real/`, the proof that sits next to the
simulator-based `sample-security-report/`.

> **Run it only in an empty sandbox account.** The provider is locked to the account ID you pass
> (`allowed_account_ids`) and `run-demo.sh` makes you type the ID again. Never use your main account:
> the demo turns off account-wide S3 Block Public Access.

| Resource | Wrong on purpose | Control |
|---|---|---|
| IAM user `*-legacy-admin` (no password, no keys) | AdministratorAccess attached to a user | ID-04, ID-05 |
| IAM user `*-ci-deploy` with an access key | Long-lived CI key (the key is useless: an inline policy denies everything) | SP-03 |
| No password policy, no CloudTrail, GuardDuty or Config | A new account has none of them | ID-06, LD-01, LD-02, LD-03 |
| Log group with 7-day retention | Logs gone before anyone investigates | LD-04 |
| Account-level S3 Block Public Access off; empty bucket with a public-read policy | Public bucket | DA-01, DA-02 |
| Security group with SSH and Postgres open to 0.0.0.0/0, on a t3.micro | Open admin ports | NC-01 |
| The instance allows IMDSv1, has a public IP and a fake password in user data | IMDSv1, public instance, secret in user data | NC-03, NC-04, SP-01 |
| Lambda with a fake `SMTP_PASSWORD` variable | Secret in a variable | SP-01 |
| Secrets Manager secret without rotation | Never rotated | SP-02 |
| ECR repository with mutable tags and no scan on push | Unscanned images | SP-04 |
| Optional (`-var include_rds=true`): unencrypted RDS without backups | Database risks | DA-04 |

Every "secret" is the string `demo-only-not-a-real-secret` or similar. Cost: about **$0.05 per run**
(t3.micro and a public IPv4 address for ~15 minutes, a secret for a few minutes).

## Run it

```bash
bash demo-account/run-demo.sh               # up + wait + scan + down in one go (~15 minutes, ~$0.05)

# or step by step, to look around in the console between the steps:
bash demo-account/up.sh                     # build the insecure sandbox (asks you to type its account ID)
bash demo-account/scan.sh                   # scan it -> sample-security-report-real/
bash demo-account/down.sh                   # ALWAYS finish with this (deletes everything)
bash demo-account/status.sh                 # is anything still up?
```

The scripts use the AWS CLI profile in `SANDBOX_PROFILE` (`../_setup/config.env`, default `sandbox`); pass
another one as the first argument. They refuse to run if that profile points at your main account, and you
must type the account ID before anything insecure is created. `run-demo.sh` **always destroys** the resources
afterwards, even if the scan fails. Check the account is empty after:

```bash
AWS_PROFILE=sandbox terraform -chdir=demo-account state list    # prints nothing when clean
```

billdoctor is installed into the repository's `.venv` the first time if it is missing; Prowler comes from
`_setup/install-tools-wsl.sh`. Creating the sandbox account itself (AWS Organizations, IAM Identity Center
profile) is covered in Project Hosting Guides / 08 - AWS Bill Doctor and Security Check.
