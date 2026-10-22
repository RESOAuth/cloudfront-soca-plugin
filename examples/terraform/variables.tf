variable "name" {
  type        = string
  description = "Unique deployment name used for Lambda, bucket prefix and CloudFront resources."
  default     = "cloudfront-soca-example"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,35}[a-z0-9]$", var.name))
    error_message = "Use 3 to 37 lowercase letters, digits or hyphens, starting and ending with a letter or digit."
  }
}

variable "zip_path" {
  type        = string
  description = "Absolute path to the private deployment ZIP. Build it before terraform plan."
}

variable "enabled" {
  type        = bool
  description = "Enable only after the ZIP contains this distribution's canonical HTTPS origin."
  default     = false
}

variable "domain_name" {
  type        = string
  description = "Optional canonical DNS name; otherwise use the assigned cloudfront.net hostname."
  default     = null
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate in us-east-1 covering domain_name."
  default     = null
}
