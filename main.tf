terraform {
  required_version = ">= 0.12.16"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.0"
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
}

resource "aws_acm_certificate_validation" "cert" {
  provider                = aws.aws_n_va
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_route53_record" "cert_validation" {
  for_each = aws_acm_certificate.cert.domain_validation_options
  provider = aws.aws_n_va
  name     = each.resource_record_name
  type     = each.resource_record_type
  zone_id  = var.hosted_zone_id
  records  = [each.resource_record_value]
  ttl      = 60
}

resource "random_string" "cf_key" {
  length  = 32
  special = false
}

resource "aws_cloudfront_distribution" "cdn" {
  price_class = var.cloudfront_price_class
  origin {
    domain_name = aws_s3_bucket.website.website_endpoint
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
  aliases             = [var.site_url]
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

resource "aws_s3_bucket" "website" {
  bucket        = var.s3_bucket_name
  tags          = var.tags
  force_destroy = var.force_destroy

  website {
    index_document = var.index_doc
    error_document = var.error_doc
  }

  lifecycle_rule {
    enabled                                = true
    abort_incomplete_multipart_upload_days = 10
    id                                     = "AutoAbortFailedMultipartUpload"

    expiration {
      days                         = 0
      expired_object_delete_marker = false
    }
  }

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

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
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

resource "aws_s3_bucket_policy" "static_website_read" {
  bucket = aws_s3_bucket.website.id
  policy = data.aws_iam_policy_document.static_website.json
}

resource "aws_s3_bucket" "logging" {
  bucket        = "${var.s3_bucket_name}-access-logs"
  tags          = var.tags
  force_destroy = var.force_destroy

  lifecycle_rule {
    id      = "logs"
    enabled = true

    transition {
      storage_class = "STANDARD_IA"
      days          = 120
    }

    expiration {
      days = 180
    }
  }

  lifecycle_rule {
    enabled                                = true
    abort_incomplete_multipart_upload_days = 10
    id                                     = "AutoAbortFailedMultipartUpload"

    expiration {
      days                         = 0
      expired_object_delete_marker = false
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
