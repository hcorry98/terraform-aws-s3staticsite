variable "index_doc" {
  type        = string
  default     = "index.html"
  description = "The index document of the site."
}

variable "error_doc" {
  type        = string
  default     = "index.html"
  description = "The error document (e.g. 404 page) of the site."
}

variable "origin_path" {
  type        = string
  default     = ""
  description = "The path to the file in the S3 bucket (no trailing slash)."
}

variable "site_url" {
  type        = string
  description = "The URL for the site."
}

variable "additional_domains" {
  type        = list(object({ domain = string, hosted_zone_id = string }))
  default     = []
  description = "Additional domains to route to this site, and the associated hosted zones for cert validation."
}

variable "wait_for_deployment" {
  type        = bool
  description = "Define if Terraform should wait for the distribution to deploy before completing."
  default     = true
}

variable "s3_bucket_name" {
  type        = string
  description = "Name of S3 bucket for website"
}

variable "tags" {
  type        = map(string)
  description = "A map of AWS Tags to attach to each resource created"
  default     = {}
}

variable "cloudfront_price_class" {
  type        = string
  description = "The price class for the cloudfront distribution"
  default     = "PriceClass_100"
}

variable "hosted_zone_id" {
  type        = string
  description = "hosted zone id"
}

variable "cors_rules" {
  type        = list(object({ allowed_headers = list(string), allowed_methods = list(string), allowed_origins = list(string), expose_headers = list(string), max_age_seconds = number }))
  default     = []
  description = "cors policy rules"
}

variable "forward_query_strings" {
  type        = bool
  default     = false
  description = "Forward query strings to the origin."
}

variable "log_cookies" {
  type        = bool
  default     = false
  description = "Include cookies in the CloudFront access logs."
}

variable "force_destroy" {
  type        = bool
  default     = false
  description = "Destroy site buckets even if they're not empty on a 'terraform destroy' command."
}

variable "waf_acl_arn" {
  type        = string
  default     = ""
  description = "The ARN of the WAF that should front the CloudFront distribution."
}
