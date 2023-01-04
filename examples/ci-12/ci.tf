terraform {
  required_version = "0.12.31"
}

provider "aws" {
  version = "~> 4.0"
  region  = "us-west-2"
}

# Note: Typically you would want to use a more human friendly URL for a website,
# probably something like "myapp.byu.edu".
data "aws_route53_zone" "zone" {
  name = "byu-oit-terraform-dev.amazon.byu.edu"
}

module "s3_site" {
  source         = "../../"
  site_url       = "teststatic.byu-oit-terraform-dev.amazon.byu.edu"
  hosted_zone_id = data.aws_route53_zone.zone.id
  s3_bucket_name = "terraform-module-dev-s3staticsite"
  tags = {
    "data-sensitivity" = "confidential"
    "env"              = "dev"
    "repo"             = "https://github.com/byu-oit/terraform-module"
  }
}

module "s3_site_with_cors" {
  source         = "../../"
  site_url       = "teststatic.byu-oit-terraform-dev.amazon.byu.edu"
  hosted_zone_id = data.aws_route53_zone.zone.id
  s3_bucket_name = "terraform-module-dev-s3staticsite"
  tags = {
    "data-sensitivity" = "confidential"
    "env"              = "dev"
    "repo"             = "https://github.com/byu-oit/terraform-module"
  }
  cors_rules = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT", "POST"]
      allowed_origins = ["https://s3-website-test.hashicorp.com"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    },
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT", "POST"]
      allowed_origins = ["https://example.com"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    }
  ]
}

output "site_bucket" {
  value = module.s3_site.site_bucket
}

output "cf_distribution" {
  value = module.s3_site.cf_distribution
}

output "dns_record" {
  value = module.s3_site.dns_record
}
