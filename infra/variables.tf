variable "region" {
  description = "AWS region for all project resources"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for every resource (must match the bootstrap stack)"
  type        = string
  default     = "vulnpipe"
}

variable "alert_email" {
  description = "Email address subscribed to critical vulnerability alerts. Empty = no subscription."
  type        = string
  default     = ""
}

variable "deploy_scan_target" {
  description = "Deploy the intentionally vulnerable EC2 instance Inspector scans. Set false to remove it."
  type        = bool
  default     = true
}

variable "target_ami_ssm_parameter" {
  description = "Public SSM parameter resolving to the scan target's AMI (Ubuntu 20.04: past standard support, known CVEs)"
  type        = string
  default     = "/aws/service/canonical/ubuntu/server/20.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

variable "target_instance_type" {
  description = "Instance type for the scan target"
  type        = string
  default     = "t3.micro"
}

variable "sla_days" {
  description = "Remediation SLA in days per priority"
  type        = map(number)
  default     = { P1 = 7, P2 = 30, P3 = 90, P4 = 180 }
}

variable "alert_priorities" {
  description = "Priorities that trigger an SNS alert"
  type        = list(string)
  default     = ["P1"]
}
