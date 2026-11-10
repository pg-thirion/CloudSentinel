variable "aws_region" {
  description = "The AWS region to deploy CloudSentinel into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, staging, prod)."
  type        = string
  default     = "prod"
}

variable "app_name" {
  description = "Application name identifier."
  type        = string
  default     = "cloudsentinel"
}
