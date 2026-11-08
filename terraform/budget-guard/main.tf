# "Budget guard" delivered to clients at the end of a Bill Doctor audit:
# a monthly budget with actual + forecast alerts, optional per-service budgets,
# and (optionally) a Cost Anomaly Detection subscription.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "monthly_limit_usd" {
  description = "Expected monthly spend. Alerts fire at 80% and 100% actual, and 100% forecast."
  type        = number
}

variable "alert_emails" {
  type = list(string)
}

variable "service_limits_usd" {
  description = "Optional per-service budgets, e.g. { \"Amazon Elastic Compute Cloud - Compute\" = 200 }"
  type        = map(number)
  default     = {}
}

variable "enable_anomaly_subscription" {
  description = "Subscribe to an existing anomaly monitor (AWS creates a default one in most accounts)."
  type        = bool
  default     = false
}

variable "anomaly_monitor_arn" {
  type    = string
  default = ""
}

variable "anomaly_threshold_usd" {
  type    = number
  default = 20
}

resource "aws_budgets_budget" "total" {
  name         = "monthly-total"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [
      { t = 80, type = "ACTUAL" },
      { t = 100, type = "ACTUAL" },
      { t = 100, type = "FORECASTED" },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.t
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = var.alert_emails
    }
  }
}

resource "aws_budgets_budget" "service" {
  for_each = var.service_limits_usd

  name         = "monthly-${substr(replace(lower(each.key), "/[^a-z0-9]+/", "-"), 0, 40)}"
  budget_type  = "COST"
  limit_amount = tostring(each.value)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = [each.key]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.alert_emails
  }
}

resource "aws_ce_anomaly_subscription" "this" {
  count = var.enable_anomaly_subscription ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.anomaly_monitor_arn != ""
      error_message = "Set anomaly_monitor_arn (Billing console > Cost Anomaly Detection > Monitors) to enable the subscription."
    }
  }

  name             = "anomaly-alerts"
  frequency        = "DAILY"
  monitor_arn_list = [var.anomaly_monitor_arn]

  dynamic "subscriber" {
    for_each = var.alert_emails
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.anomaly_threshold_usd)]
    }
  }
}

output "budget_names" {
  value = concat([aws_budgets_budget.total.name], [for b in aws_budgets_budget.service : b.name])
}
