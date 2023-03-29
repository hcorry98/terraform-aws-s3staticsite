terraform {
  required_version = ">= 0.12.16"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.48.0"
    }
  }
}

provider "aws" {
  alias  = "aws_n_va"
  region = "us-east-1"
}

locals {
  # Make sure there is one leading slash to make a file name into a path
  error_doc_path = "/${replace(var.error_doc, "/^//", "")}"
}

resource "aws_acm_certificate" "cert" {
  provider                  = aws.aws_n_va
  domain_name               = var.site_url
  subject_alternative_names = [for domain in var.additional_domains : domain.domain]
  validation_method         = "DNS"
  tags                      = var.tags
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
  zone_id  = (each.key == var.site_url) ? var.hosted_zone_id : var.additional_domains[index(var.additional_domains.*.domain, each.key)].hosted_zone_id
  records  = [each.value.record]
  ttl      = 60
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = aws_s3_bucket.website.bucket
  description                       = "Lock down access to static site"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "cdn" {
  price_class = var.cloudfront_price_class
  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_id                = aws_s3_bucket.website.bucket
    origin_path              = var.origin_path
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  # The custom error responses make SPA frameworks like Vue work.
  # This is setup to be fairly similar to how the module previously
  # worked with the s3 static website "error_document" field

  custom_error_response {
    error_code         = 404
    response_code      = 404
    response_page_path = local.error_doc_path
  }

  custom_error_response {
    error_code         = 403
    response_code      = 403
    response_page_path = local.error_doc_path
  }

  comment             = "CDN for ${var.site_url}"
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = var.index_doc
  aliases             = concat([var.site_url], [for domain in var.additional_domains : domain.domain])
  web_acl_id          = var.waf_acl_arn

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
  tags          = var.tags
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket                  = aws_s3_bucket.website.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
    actions = ["s3:GetObject"]

    resources = ["${aws_s3_bucket.website.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cdn.arn]
    }
  }
}


resource "aws_s3_bucket_policy" "static_website_read" {
  bucket = aws_s3_bucket.website.id
  policy = data.aws_iam_policy_document.static_website.json
}

resource "aws_s3_bucket" "logging" {
  bucket        = "${var.s3_bucket_name}-access-logs"
  tags          = var.tags
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "block_public_access_logging" {
  bucket                  = aws_s3_bucket.logging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
