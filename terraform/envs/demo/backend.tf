terraform {
  backend "s3" {
    bucket = "<your-bucket-name>"
    key    = "terraform-work-starter/envs/your-env/terraform.tfstate"
    region = "ap-northeast-2"
  }
}