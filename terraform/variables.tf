variable "function_name" {
  type        = string
  description = "Unique Lambda function name."
  default     = "cloudfront-soca"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,64}$", var.function_name))
    error_message = "Use 1 to 64 letters, digits, underscores or hyphens."
  }
}

variable "zip_path" {
  type        = string
  description = "Path to the private deployment ZIP produced before terraform plan."

  validation {
    condition     = fileexists(var.zip_path)
    error_message = "Build the deployment ZIP before running Terraform."
  }
}

variable "timeout_seconds" {
  type        = number
  description = "Viewer-request timeout, including identity-provider requests."
  default     = 30

  validation {
    condition     = var.timeout_seconds >= 1 && var.timeout_seconds <= 30 && floor(var.timeout_seconds) == var.timeout_seconds
    error_message = "Use a whole number of seconds between 1 and 30."
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags for the function and execution role."
  default     = {}
}
