# terraform-work-starter

This repository is a lightweight Terraform starter kit for infrastructure developers who need a quick and organized baseline project.

## Features

- opinionated directory structure that separates modules, environments, and shared state
- sample `main.tf` plus minimal supporting files so you can start building in minutes
- ready-to-use `.terraform-version` + backend settings you can adjust per team

## Requirements

- Terraform 1.5+ (or a version pinned in `.terraform-version`)
- Access to your chosen backend (local, S3, GCS, etc.)

## Usage

1. Install the required Terraform version.
2. Copy or adapt the starter files into your project.
3. Run `terraform init`, `terraform plan`, and `terraform apply` as usual.

## License

Available under the terms of the MIT License.
