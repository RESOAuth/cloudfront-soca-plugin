output "origin" {
  description = "Canonical HTTPS origin to put in the generator configuration."
  value       = "https://${var.domain_name == null ? aws_cloudfront_distribution.content.domain_name : var.domain_name}"
}

output "distribution_domain" {
  description = "Assigned CloudFront hostname, also the DNS alias target for a custom domain."
  value       = aws_cloudfront_distribution.content.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.content.id
}

output "content_bucket" {
  description = "Private content bucket; upload only static website files, never deployment ZIPs."
  value       = aws_s3_bucket.content.id
}

output "version_arn" {
  value = module.soca.version_arn
}
