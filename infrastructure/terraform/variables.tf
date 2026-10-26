variable "aws_region" {
  description = "Target AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC network"
  type        = string
  default     = "10.0.0.0/16"
}

variable "db_password" {
  description = "PostgreSQL Master Password"
  type        = string
  sensitive   = true
  default     = "CyberSecAdminPass2026!"
}
