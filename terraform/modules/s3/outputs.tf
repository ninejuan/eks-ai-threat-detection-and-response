output "runbooks_bucket_arn" {
  value = aws_s3_bucket.runbooks.arn
}

output "runbooks_bucket_id" {
  value = aws_s3_bucket.runbooks.id
}

output "forensics_bucket_arn" {
  value = aws_s3_bucket.forensics.arn
}

output "forensics_bucket_id" {
  value = aws_s3_bucket.forensics.id
}

output "logs_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

output "logs_bucket_id" {
  value = aws_s3_bucket.logs.id
}
