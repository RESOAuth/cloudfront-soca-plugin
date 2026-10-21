# Terraform module

Build the private deployment ZIP first. This module publishes a numbered Node.js 24 Lambda version in `us-east-1` and creates a logs-only execution role. It makes no distribution changes. It accepts the ZIP path, never individual keys or configuration values.

```hcl
provider "aws" {
  alias  = "edge"
  region = "us-east-1"
}

module "soca" {
  source        = "./terraform"
  providers     = { aws = aws.edge }
  function_name = "my-site-soca"
  zip_path      = "/private/deployment.zip"
}
```

Associate `module.soca.version_arn` with `viewer-request` and `include_body = false` on every relevant CloudFront behaviour. Allow POST so logout can reach the handler. The runtime permits only GET/HEAD for content. Cookies and query strings must not reach S3 or become content cache keys; the viewer handler sees them before cache-policy filtering. Keep the S3 bucket private using Origin Access Control.

`timeout_seconds` defaults to 30; `tags` defaults to an empty map. Session lifetime and authentication settings belong in the generated package. ZIP changes are detected using `filebase64sha256`, and every update publishes an immutable numbered version. Terraform state contains package paths and hashes rather than ZIP contents; keep the ZIP and state access restricted.

For a new site, use the [disabled-distribution bootstrap example](../examples/terraform/README.md). Deployment credentials need Lambda publishing, IAM role creation/passing, CloudFront association/replication and service-linked-role permissions; the function execution role itself only writes logs. Logs appear in the AWS Regions serving requests.

Before destroying a deployed function, remove its CloudFront associations, wait for distribution propagation and allow several hours for replica cleanup. Terraform retains earlier published versions during ordinary updates. See [AWS replica cleanup](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-edge-delete-replicas.html).
