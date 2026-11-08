"""Native checks for the two baseline controls Prowler has no check for.

They use the same read-only session as the cost scan and return results in the same shape as
Prowler findings, so the rest of the pipeline treats them alike.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .ocsf import CheckResult

CI_NAME = re.compile(r"(^|[-_./])(ci|cd|cicd|github|gitlab|bitbucket|jenkins|circleci|deploy|deployer|pipeline|actions|build|terraform)([-_./]|$)", re.I)
CI_OIDC_HOSTS = ("token.actions.githubusercontent.com", "gitlab.com", "api.bitbucket.org", "oidc.circleci.com")


def _result(check: str, status: str, uid: str, rtype: str, message: str, region: str = "global") -> CheckResult:
    return CheckResult(check_id=f"native:{check}", status=status, region=region, resource_uid=uid,
                       resource_type=rtype, resource_name=uid.rsplit("/", 1)[-1], message=message)


def spend_alerts(session: Any, account_id: str) -> list[CheckResult]:
    budgets = session.client("budgets", region_name="us-east-1")
    alerting = []
    for b in budgets.describe_budgets(AccountId=account_id).get("Budgets", []):
        notes = budgets.describe_notifications_for_budget(AccountId=account_id, BudgetName=b["BudgetName"]).get("Notifications", [])
        if notes:
            alerting.append(b["BudgetName"])
    uid = f"arn:aws:budgets::{account_id}:budget"
    if alerting:
        return [_result("spend_alerts", "PASS", uid, "AwsBudget", f"{len(alerting)} budget(s) with alerts: {', '.join(alerting[:5])}")]
    return [_result("spend_alerts", "FAIL", uid, "AwsBudget", "No budget with an alert: abuse of a stolen key would only show up on the monthly bill")]


def ci_oidc(session: Any, account_id: str) -> list[CheckResult]:
    iam = session.client("iam")
    providers = [p["Arn"] for p in iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])]
    ci_providers = [a for a in providers if a.endswith(CI_OIDC_HOSTS)]
    out: list[CheckResult] = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page.get("Users", []):
            if not (CI_NAME.search(u["UserName"]) or CI_NAME.search(u.get("Path", ""))):
                continue
            keys = [k for k in iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []) if k.get("Status") == "Active"]
            for k in keys:
                out.append(_result("ci_oidc", "FAIL", u["Arn"], "AwsIamUser",
                                   f"IAM user '{u['UserName']}' looks like a CI/CD identity and has an active access key "
                                   f"(created {k['CreateDate']:%Y-%m-%d}); replace it with an OIDC role"))
    if out:
        return out
    uid = f"arn:aws:iam::{account_id}:oidc-provider"
    if ci_providers:
        return [_result("ci_oidc", "PASS", uid, "AwsIamOidcProvider",
                        f"CI/CD OIDC provider(s) present ({', '.join(a.rsplit('/', 1)[-1] for a in ci_providers)}) and no CI-looking user has an active key")]
    return [_result("ci_oidc", "MANUAL", uid, "AwsIamOidcProvider",
                    "No CI/CD OIDC provider and no CI-looking IAM user: confirm how pipelines deploy (keys may be held by another name)")]


NATIVE: dict[str, Callable[[Any, str], list[CheckResult]]] = {
    "spend_alerts": spend_alerts,
    "ci_oidc": ci_oidc,
}


def run_native(session: Any, account_id: str, names: list[str]) -> tuple[list[CheckResult], list[dict[str, str]]]:
    results: list[CheckResult] = []
    errors: list[dict[str, str]] = []
    for name in names:
        try:
            results.extend(NATIVE[name](session, account_id))
        except ClientError as e:
            err = e.response.get("Error", {})
            errors.append({"check": f"native:{name}", "region": "global", "error": f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}"[:300]})
        except BotoCoreError as e:
            errors.append({"check": f"native:{name}", "region": "global", "error": str(e)[:300]})
    return results, errors
