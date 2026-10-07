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

variable "github_owner_id" {
  description = "Immutable numeric ID of the GitHub account (appears in the OIDC subject claim)"
  type        = string
  default     = "338269886"
}

variable "github_repo_id" {
  description = "Immutable numeric ID of the repository (appears in the OIDC subject claim)"
  type        = string
  default     = "1409374658"
}
