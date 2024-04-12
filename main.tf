terraform {
  required_version = ">= 0.12.16"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.48.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

provider "aws" {
  alias  = "aws_n_va"
  region = "us-east-1"
}

resource "aws_acm_certificate" "cert" {
  provider          = aws.aws_n_va
  domain_name       = var.site_url
  validation_method = "DNS"
  tags              = var.tags

  subject_alternative_names = concat(
    [for subdomain in var.additional_subdomains : "${subdomain}.${var.site_url}"],
    [for domain in var.additional_domains : domain.domain]
  )
}

resource "aws_acm_certificate_validation" "cert" {
  provider                = aws.aws_n_va
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  provider = aws.aws_n_va
  name     = each.value.name
  type     = each.value.type
  zone_id  = lookup(var.additional_domains, each.key, var.hosted_zone_id)
  records  = [each.value.record]
  ttl      = 60
}

resource "random_string" "cf_key" {
  length  = 32
  special = false
}

# https://github.com/hashicorp/terraform-provider-aws/issues/30951#issuecomment-1523376909
resource "aws_s3_bucket_public_access_block" "logging_bucket_public_enabled" {
  bucket                  = aws_s3_bucket.logging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logging_bucket_ownership" {
  depends_on = [aws_s3_bucket_public_access_block.logging_bucket_public_enabled]
  bucket     = aws_s3_bucket.logging.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  depends_on  = [aws_s3_bucket_ownership_controls.logging_bucket_ownership]
  price_class = var.cloudfront_price_class
  origin {
    domain_name = aws_s3_bucket_website_configuration.website_config.website_endpoint
    origin_id   = aws_s3_bucket.website.bucket
    origin_path = var.origin_path

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    custom_header {
      name  = "Referer"
      value = random_string.cf_key.result
    }
  }

  comment             = "CDN for ${var.site_url}"
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = var.index_doc
  web_acl_id          = var.waf_acl_arn

  aliases = concat(
    [var.site_url],
    [for subdomain in var.additional_subdomains : "${subdomain}.${var.site_url}"],
    [for domain in var.additional_domains : domain.domain]
  )

  logging_config {
    bucket          = aws_s3_bucket.logging.bucket_domain_name
    include_cookies = var.log_cookies
  }

  default_cache_behavior {
    target_origin_id = aws_s3_bucket.website.bucket
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]

    forwarded_values {
      query_string = var.forward_query_strings
      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.cert.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2019"
  }

  wait_for_deployment = var.wait_for_deployment
  tags                = var.tags
}

resource "aws_route53_record" "custom_url_a" {
  name    = var.site_url
  type    = "A"
  zone_id = var.hosted_zone_id

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
  }
}

resource "aws_route53_record" "custom_url_4a" {
  name    = var.site_url
  type    = "AAAA"
  zone_id = var.hosted_zone_id

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
  }
}

resource "aws_route53_record" "subdomain_cname" {
  for_each = {
    for subdomain in var.additional_subdomains : subdomain => var.site_url
  }
  name    = each.key
  type    = "CNAME"
  zone_id = var.hosted_zone_id

  ttl     = 300
  records = [var.site_url]
}

resource "aws_route53_record" "additional_a" {
  for_each = {
    for domain in var.additional_domains : domain.domain => domain.hosted_zone_id
  }
  name    = each.key
  type    = "A"
  zone_id = each.value

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
  }
}

resource "aws_route53_record" "additional_4a" {
  for_each = {
    for domain in var.additional_domains : domain.domain => domain.hosted_zone_id
  }
  name    = each.key
  type    = "AAAA"
  zone_id = each.value

  alias {
    evaluate_target_health = false
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
  }
}

resource "aws_s3_bucket" "website" {
  bucket        = var.s3_bucket_name
  tags          = merge({ "divvy-ignore-s3-public" = "true" }, var.tags)
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_website_configuration" "website_config" {
  bucket = aws_s3_bucket.website.id
  index_document {
    suffix = var.index_doc
  }
  error_document {
    key = var.error_doc
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "website_lifecycle" {

  bucket = aws_s3_bucket.website.id
  rule {
    id     = "AutoAbortFailedMultipartUpload"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 10
    }

    expiration {
      days                         = 0
      expired_object_delete_marker = false
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.website.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_cors_configuration" "cors_config" {
  count  = length(var.cors_rules) > 1 ? 1 : 0
  bucket = aws_s3_bucket.website.id
  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = cors_rule.value["allowed_headers"]
      allowed_methods = cors_rule.value["allowed_methods"]
      allowed_origins = cors_rule.value["allowed_origins"]
      expose_headers  = cors_rule.value["expose_headers"]
      max_age_seconds = cors_rule.value["max_age_seconds"]
    }
  }
}

data "aws_iam_policy_document" "static_website" {
  statement {
    sid       = "1"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.website.arn}/*"]

    principals {
      identifiers = ["*"]
      type        = "AWS"
    }

    condition {
      test     = "StringLike"
      values   = [random_string.cf_key.result]
      variable = "aws:Referer"
    }
  }
}

# https://github.com/hashicorp/terraform-provider-aws/issues/30951#issuecomment-1523376909
resource "aws_s3_bucket_public_access_block" "website_bucket_public_enabled" {
  bucket                  = aws_s3_bucket.website.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "website_bucket_ownership" {
  depends_on = [aws_s3_bucket_public_access_block.website_bucket_public_enabled]
  bucket     = aws_s3_bucket.website.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "static_website_read" {
  depends_on = [aws_s3_bucket_ownership_controls.website_bucket_ownership]
  bucket     = aws_s3_bucket.website.id
  policy     = data.aws_iam_policy_document.static_website.json
}

resource "aws_s3_bucket" "logging" {
  bucket        = "${var.s3_bucket_name}-access-logs"
  tags          = var.tags
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_lifecycle_configuration" "logging_bucket_lifecycle" {
  bucket = aws_s3_bucket.logging.id
  rule {
    id     = "AutoAbortFailedMultipartUpload"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 10
    }

    expiration {
      days                         = 0
      expired_object_delete_marker = false
    }
  }
  rule {
    id     = "logs"
    status = "Enabled"
    transition {
      storage_class = "STANDARD_IA"
      days          = 120
    }
    expiration {
      days = 180
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "logging_encryption" {
  bucket = aws_s3_bucket.logging.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
