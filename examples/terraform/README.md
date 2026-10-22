# Private S3 example

This example creates a private S3 REST origin, Origin Access Control and a CloudFront distribution with the SOCA viewer-request handler always attached. The distribution defaults to disabled. Nothing uploads content or creates public S3 access.

When using an allocated `cloudfront.net` hostname:

1. Generate a candidate ZIP using a placeholder HTTPS origin such as `https://example.invalid`, with `enabled=false` in the authentication configuration. Keep its keys for subsequent builds.
2. In this directory run `terraform init`, then `terraform apply -var='zip_path=/private/deployment.zip'`. Leave `enabled=false`. AWS allocates the distribution hostname while the distribution remains disabled.
3. Read `terraform output -raw origin`. Regenerate the ZIP for that exact origin using the same keys. Keep authentication `enabled=false` while checking public documents.
4. Apply the replacement ZIP and `-var='enabled=true'`. Wait until CloudFront finishes deployment. The handler now serves public metadata; protected content and login remain disabled.
5. Run the document check in the root README. Verify real allowed and denied logins on a separate staging distribution with authentication `enabled=true`, then build and deploy the enabled production package. Candidate-only tests and enforced activation evidence are not implemented. Verify that anonymous requests redirect, an approved login reaches content and disallowed identities are denied. Upload static files to `content_bucket` only; never put deployment ZIPs in that bucket.

For a custom domain, provide both `domain_name` and an ACM certificate ARN from `us-east-1` through `acm_certificate_arn`. The certificate must cover that domain. Configure DNS to point the domain at `distribution_domain`. Build for the custom origin before enabling; requests to the alternate CloudFront hostname are rejected by the handler's canonical-host check. DNS and certificate issuance are deliberately outside this example.

The example allows POST so logout can reach the handler; content accepts GET/HEAD only and the S3 policy grants CloudFront only `GetObject`. Cookies, query strings and viewer headers are excluded from the content cache key and forwarding to S3. All viewers therefore receive the same static object after their session is checked, including on cache hits. Do not use this cache configuration for personalised origin responses.

Attach the viewer handler to every additional behaviour you create. Changes to a generated ZIP publish a new numbered function version and update the association. CloudFront rollout takes time; old versions and policy may remain active during propagation. Disable the distribution before recovery changes that remove authentication.

To tear down, disable/remove the distribution and its associations first. Allow several hours for Lambda@Edge replicas to disappear, then remove the Lambda resources. An immediate `terraform destroy` may fail until AWS finishes replica cleanup. Bucket deletion requires that its content has been removed.
