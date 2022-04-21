terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Note: Typically you would want to use a more human friendly URL for a website,
# probably something like "myapp.byu.edu".
data "aws_route53_zone" "myapp" {
  //name = "myapp.byu.edu"
  name = "myapp.byu-oit-terraform-dev.amazon.byu.edu"
}

data "aws_route53_zone" "myotherapp" {
  //name = "myotherapp..byu.edu"
  name = "myotherapp.byu-oit-terraform-dev.amazon.byu.edu"
}

module "s3_site" {
  source = "github.com/byu-oit/terraform-aws-s3staticsite?ref=v6.1.0"
  //source         = "../../"
  //site_url       = "myapp.byu.edu"
  site_url       = "myapp.byu-oit-terraform-dev.amazon.byu.edu"
  hosted_zone_id = data.aws_route53_zone.myapp.id
  s3_bucket_name = "myapp-byu-edu-s3staticsite"
  additional_domains = [
    {
      //domain         = "www.myapp.byu.edu"
      domain         = "www.myapp.byu-oit-terraform-dev.amazon.byu.edu"
      hosted_zone_id = data.aws_route53_zone.myapp.id
    },
    {
      //domain         = "myotherapp.byu.edu"
      domain         = "myotherapp.byu-oit-terraform-dev.amazon.byu.edu"
      hosted_zone_id = data.aws_route53_zone.myotherapp.id
    },
    {
      //domain         = "www.myotherapp.byu.edu"
      domain         = "www.myotherapp.byu-oit-terraform-dev.amazon.byu.edu"
      hosted_zone_id = data.aws_route53_zone.myotherapp.id
    }
  ]
  tags = {
    "data-sensitivity" = "confidential"
    "env"              = "dev"
    "repo"             = "https://github.com/byu-oit/terraform-module"
  }
}

output "bucket_name" {
  value = module.s3_site.site_bucket.bucket
}

output "url" {
  value = module.s3_site.dns_record.name
}
