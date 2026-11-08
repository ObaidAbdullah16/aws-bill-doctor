provider "aws" {
  region = "us-east-1"
}

module "budget_guard" {
  source            = "../../budget-guard"
  monthly_limit_usd = 1200
  alert_emails      = ["finance@example.com", "cto@example.com"]
  service_limits_usd = {
    "Amazon Elastic Compute Cloud - Compute" = 500
    "Amazon Relational Database Service"     = 300
  }
}
