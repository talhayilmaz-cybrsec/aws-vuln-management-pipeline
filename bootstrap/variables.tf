variable "region" {
  description = "AWS region for all project resources"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for every resource; the deploy role may only manage IAM roles with this prefix"
  type        = string
  default     = "vulnpipe"
}

variable "github_owner" {
  description = "GitHub account that owns the repository"
  type        = string
  default     = "talhayilmaz-cybrsec"
}

variable "github_repo" {
  description = "Repository allowed to assume the deploy role"
  type        = string
  default     = "aws-vuln-management-pipeline"
}
