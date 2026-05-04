terraform {
  backend "s3" {
    bucket       = "atdr-tfstate"
    key          = "envs/demo/terraform.tfstate"
    region       = "ap-northeast-2"
    use_lockfile = true # S3 native lock (Terraform 1.10+, no DynamoDB needed)
  }
}
