#!/usr/bin/env bash
set -euo pipefail

PROJECT="atdr"
REGION="ap-northeast-2"
BUCKET_NAME="${PROJECT}-tfstate"

echo "=== ATDR Terraform Backend Bootstrap ==="
echo "Region: ${REGION}"
echo "Bucket: ${BUCKET_NAME}"
echo ""

if ! command -v aws &> /dev/null; then
  echo "ERROR: aws CLI not found. Install it first."
  exit 1
fi

if ! command -v terraform &> /dev/null; then
  echo "ERROR: terraform not found. Install >= 1.10.0."
  exit 1
fi

TF_VERSION=$(terraform version -json | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])")
TF_MAJOR=$(echo "$TF_VERSION" | cut -d. -f1)
TF_MINOR=$(echo "$TF_VERSION" | cut -d. -f2)
if [ "$TF_MAJOR" -lt 1 ] || { [ "$TF_MAJOR" -eq 1 ] && [ "$TF_MINOR" -lt 10 ]; }; then
  echo "ERROR: Terraform >= 1.10.0 required for S3 native locking. Found: ${TF_VERSION}"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || {
  echo "ERROR: AWS credentials not configured. Run 'aws configure' first."
  exit 1
}
echo "AWS Account: ${ACCOUNT_ID}"

if aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
  echo "Bucket '${BUCKET_NAME}' already exists. Skipping creation."
else
  echo "Creating S3 bucket '${BUCKET_NAME}'..."
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${REGION}" \
    --create-bucket-configuration LocationConstraint="${REGION}"

  aws s3api put-bucket-versioning \
    --bucket "${BUCKET_NAME}" \
    --versioning-configuration Status=Enabled

  aws s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

  aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration \
      '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'

  echo "Bucket created with versioning, encryption, and public access block."
fi

echo ""
echo "Initializing Terraform..."
cd "$(dirname "$0")/terraform/envs/demo"
terraform init

echo ""
echo "=== Bootstrap complete ==="
echo "Run 'cd terraform/envs/demo && terraform plan' to verify."
