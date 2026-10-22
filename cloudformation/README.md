# CloudFormation template

CloudFormation creates AWS resources from a YAML template. This template is the equivalent of the Terraform Lambda module: it publishes the function and execution role, then returns `VersionArn`. It can be deployed directly or used as an `AWS::CloudFormation::Stack` nested stack. It does not create or change a distribution.

1. Build the deployment ZIP using the generator.
2. Upload it to a private, versioned S3 bucket in `us-east-1`. Block public access and use server-side encryption. The ZIP contains private keys; restrict both artifact access and Lambda `GetFunction` permissions.
3. Calculate the base64 SHA-256 of the exact ZIP bytes, for example `openssl dgst -sha256 -binary deployment.zip | openssl base64 -A`.
4. Deploy `template.yaml` in `us-east-1` with `CAPABILITY_IAM`. Supply `ArtifactBucket`, `ArtifactKey`, `ArtifactVersion`, `CodeSha256` and a unique `FunctionName`.
5. Associate the output `VersionArn` with `viewer-request`, without a request body, on each relevant CloudFront behaviour. Keep the S3 origin private behind Origin Access Control and exclude cookies/query strings from the content cache policy and origin forwarding. Allow POST for logout.

For every package update, change both `ArtifactVersion` and `CodeSha256`. CloudFormation does not notice an overwritten object at an unchanged S3 reference. The hash forces replacement of the version resource and prevents publication if the uploaded code does not match. A timeout change also replaces the published version. The function remains Node.js 24, x86_64, 128 MB, with a default 30-second timeout and no custom environment variables. Keys and session settings stay inside the private ZIP rather than stack parameters.

Use the [Terraform example's bootstrap sequence](../examples/terraform/README.md) when the distribution hostname is not yet known. Keep the distribution disabled until a package for its canonical HTTPS origin is attached; public document checks and separate staging login tests then follow the main README.

Old version resources are retained on replacement because CloudFront replicas may still reference them. Retention also keeps their secret-bearing packages available to principals allowed to read Lambda code. Remove unused versions after confirming that no distribution uses them and waiting for replica cleanup. Before deleting the stack, remove all associations and wait several hours, then delete retained versions separately. See [AWS replica cleanup](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-edge-delete-replicas.html).
