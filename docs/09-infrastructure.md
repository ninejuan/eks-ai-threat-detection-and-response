# 09. 인프라 설계

## 인프라 개요

ATDR 프로젝트의 모든 AWS 리소스는 Terraform으로 관리한다. 콘솔에서 직접 클릭하는 방식은 재현성이 없고, 학교 크레딧 환경에서 실수로 리소스를 남기면 비용이 누적된다. IaC로 관리하면 `terraform destroy` 한 번으로 전체를 정리할 수 있다.

구조는 기능별 모듈로 분리했다. VPC, EKS, IAM, GuardDuty 등 각 관심사가 독립된 모듈 디렉터리에 담기고, `environments/dev/main.tf`에서 이 모듈들을 조합해 실제 환경을 구성한다. 모듈 경계가 명확하면 특정 컴포넌트만 교체하거나 비활성화하기 쉽다.

---

## Terraform 모듈 구조

```
terraform/
├── modules/
│   ├── vpc/           # VPC, 서브넷, NAT Gateway, IGW
│   ├── eks/           # EKS 클러스터, 노드 그룹, Access Entry
│   ├── iam/           # IAM 역할, 정책, Pod Identity
│   ├── guardduty/     # GuardDuty detector, Security Hub
│   ├── eventbridge/   # EventBridge 규칙, Lambda 타겟
│   ├── lambda/        # Lambda 함수 (Strands Agent)
│   ├── opensearch/    # OpenSearch Serverless (Knowledge Base)
│   ├── s3/            # S3 버킷 (런북, 포렌식, 로그)
│   ├── sns-sqs/       # SNS 토픽, SQS 큐, DLQ
│   ├── kms/           # KMS 키 (로그 암호화, 시크릿)
│   └── slack/         # API Gateway + Lambda (Slack Bot)
├── environments/
│   └── dev/
│       ├── main.tf
│       ├── variables.tf
│       └── terraform.tfvars
└── backend.tf
```

`backend.tf`는 S3 원격 상태 저장소와 DynamoDB 락 테이블을 정의한다. 팀 작업이 아니더라도 원격 백엔드를 쓰면 로컬 머신이 바뀌어도 상태가 유지된다.

---

## VPC 모듈

2개 AZ에 걸쳐 public/private 서브넷을 구성한다. EKS 노드와 Lambda는 private 서브넷에 배치하고, NAT Gateway를 통해 외부로 나간다. NAT Gateway는 AZ당 하나씩 두면 고가용성이 높아지지만 비용도 두 배다. 데모 환경이므로 단일 NAT Gateway로 절충한다.

VPC Flow Logs는 S3로 내보낸다. CloudWatch Logs보다 저렴하고, 나중에 Athena로 쿼리하기도 편하다.

```hcl
# modules/vpc/main.tf

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_subnet" "public" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name                     = "${var.project}-public-${count.index + 1}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name                              = "${var.project}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-igw"
  }
}

# 단일 NAT Gateway — 비용 절감
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project}-nat"
  }
}

# VPC Flow Logs → S3
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = var.flow_log_role_arn
  log_destination = "${var.log_bucket_arn}/vpc-flow-logs/"
  log_destination_type = "s3"
}
```

---

## EKS 모듈

EKS 1.35를 사용한다. Access Entry는 API 모드로 설정하고 `bootstrap_cluster_creator_admin_permissions`를 `false`로 둔다. 이렇게 하면 클러스터 생성자에게 자동으로 admin 권한이 부여되지 않아, 모든 접근 권한을 명시적으로 선언해야 한다.

네트워크 플러그인은 Cilium이다. `cluster_ip_family`를 `ipv4`로 설정하고, 기본 VPC CNI 대신 Cilium을 설치한다. 컨트롤 플레인 로깅은 5가지 항목을 모두 활성화한다. private endpoint만 열고 public endpoint는 닫는다.

```hcl
# modules/eks/main.tf

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = var.cluster_role_arn
  version  = "1.35"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    security_group_ids      = [aws_security_group.cluster.id]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  tags = {
    Name = var.cluster_name
  }
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-general"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids

  instance_types = ["t3.medium"]

  scaling_config {
    desired_size = 2
    min_size     = 1
    max_size     = 3
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    role = "general"
  }
}

resource "aws_eks_node_group" "compute" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-compute"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids

  instance_types = ["c5.large"]

  scaling_config {
    desired_size = 1
    min_size     = 0
    max_size     = 2
  }

  labels = {
    role = "compute"
  }
}

# Access Entry — 명시적 권한 부여
resource "aws_eks_access_entry" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = var.admin_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = var.admin_role_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}
```

---

## IAM 모듈

Pod Identity를 사용해 Kubernetes ServiceAccount와 IAM 역할을 연결한다. IRSA(IAM Roles for Service Accounts)보다 설정이 단순하고, OIDC 공급자를 별도로 관리할 필요가 없다.

Lambda 실행 역할은 필요한 서비스에만 접근 권한을 준다. GuardDuty 읽기, Bedrock 호출, SSM Parameter Store 읽기, SQS 메시지 처리 정도다. `*` 와일드카드는 쓰지 않는다.

```hcl
# modules/iam/main.tf

# Lambda 실행 역할
resource "aws_iam_role" "lambda_agent" {
  name = "${var.project}-lambda-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_agent" {
  name = "${var.project}-lambda-agent-policy"
  role = aws_iam_role.lambda_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ]
        Resource = "arn:aws:bedrock:${var.region}::foundation-model/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
        ]
        Resource = var.sqs_queue_arn
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
        ]
        Resource = "arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.project}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/*"
      },
    ]
  })
}

# Pod Identity — Falco ServiceAccount용
resource "aws_iam_role" "falco_pod" {
  name = "${var.project}-falco-pod"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "pods.eks.amazonaws.com"
      }
      Action = [
        "sts:AssumeRole",
        "sts:TagSession",
      ]
    }]
  })
}

resource "aws_eks_pod_identity_association" "falco" {
  cluster_name    = var.cluster_name
  namespace       = "falco"
  service_account = "falco"
  role_arn        = aws_iam_role.falco_pod.arn
}
```

---

## GuardDuty + Security Hub 모듈

GuardDuty detector를 생성하고 EKS Protection, Runtime Monitoring, Malware Protection을 활성화한다. Security Hub는 GuardDuty findings를 집계하는 용도로 쓴다.

EventBridge 규칙은 severity 7 이상(Critical/High) findings를 필터링해 Lambda로 전달한다. GuardDuty findings는 자동으로 EventBridge에 발행되므로 별도 설정 없이 규칙만 추가하면 된다.

```hcl
# modules/guardduty/main.tf

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name = "${var.project}-guardduty"
  }
}

resource "aws_guardduty_detector_feature" "eks_runtime" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_finding_aggregator" "main" {
  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.main]
}

# EventBridge — Critical/High findings → Lambda
resource "aws_cloudwatch_event_rule" "guardduty_critical" {
  name        = "${var.project}-guardduty-critical"
  description = "GuardDuty severity >= 7 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_critical.name
  target_id = "LambdaAgent"
  arn       = var.lambda_arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_critical.arn
}
```

---

## Lambda 모듈

Strands Agent를 실행하는 Lambda 함수다. Python 3.12 런타임을 쓰고, 메모리는 1024MB, 타임아웃은 300초로 설정한다. Bedrock 호출과 OpenSearch 쿼리가 포함되므로 기본값(128MB, 3초)으로는 부족하다.

VPC 내 private 서브넷에 배치해 OpenSearch Serverless와 내부 통신한다. 외부 인터넷 접근은 NAT Gateway를 통한다.

```hcl
# modules/lambda/main.tf

resource "aws_lambda_function" "agent" {
  function_name = "${var.project}-agent"
  role          = var.execution_role_arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  filename      = var.deployment_package_path
  timeout       = 300
  memory_size   = 1024

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      BEDROCK_MODEL_ID       = var.bedrock_model_id
      OPENSEARCH_ENDPOINT    = var.opensearch_endpoint
      KNOWLEDGE_BASE_ID      = var.knowledge_base_id
      SNS_TOPIC_ARN          = var.sns_topic_arn
      SLACK_WEBHOOK_PARAM    = "/${var.project}/slack/webhook-url"
      LOG_LEVEL              = "INFO"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "${var.project}-agent"
  }
}

resource "aws_security_group" "lambda" {
  name        = "${var.project}-lambda-sg"
  description = "Lambda agent security group"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound"
  }
}

# SQS → Lambda 트리거
resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn = var.sqs_queue_arn
  function_name    = aws_lambda_function.agent.arn
  batch_size       = 1
  enabled          = true
}
```

---

## OpenSearch Serverless 모듈

Bedrock Knowledge Base의 벡터 스토어로 OpenSearch Serverless를 쓴다. 서버리스라 클러스터를 직접 관리할 필요가 없고, 사용량 기반 과금이라 데모 환경에 적합하다.

보안 정책은 세 가지를 설정한다. encryption policy(KMS), network policy(VPC 또는 public), data access policy(Bedrock 서비스 역할 접근 허용)다.

```hcl
# modules/opensearch/main.tf

resource "aws_opensearchserverless_collection" "kb" {
  name        = "${var.project}-kb"
  type        = "VECTORSEARCH"
  description = "Knowledge Base for ATDR runbooks"

  depends_on = [
    aws_opensearchserverless_security_policy.encryption,
    aws_opensearchserverless_security_policy.network,
  ]

  tags = {
    Name = "${var.project}-kb"
  }
}

resource "aws_opensearchserverless_security_policy" "encryption" {
  name        = "${var.project}-kb-enc"
  type        = "encryption"
  description = "KMS encryption for KB collection"

  policy = jsonencode({
    Rules = [{
      ResourceType = "collection"
      Resource     = ["collection/${var.project}-kb"]
    }]
    AWSOwnedKey = true
  })
}

resource "aws_opensearchserverless_security_policy" "network" {
  name        = "${var.project}-kb-net"
  type        = "network"
  description = "Network access for KB collection"

  policy = jsonencode([{
    Rules = [
      {
        ResourceType = "collection"
        Resource     = ["collection/${var.project}-kb"]
      },
      {
        ResourceType = "dashboard"
        Resource     = ["collection/${var.project}-kb"]
      },
    ]
    AllowFromPublic = true
  }])
}

resource "aws_opensearchserverless_access_policy" "kb" {
  name        = "${var.project}-kb-access"
  type        = "data"
  description = "Bedrock KB data access"

  policy = jsonencode([{
    Rules = [
      {
        ResourceType = "index"
        Resource     = ["index/${var.project}-kb/*"]
        Permission   = ["aoss:*"]
      },
      {
        ResourceType = "collection"
        Resource     = ["collection/${var.project}-kb"]
        Permission   = ["aoss:*"]
      },
    ]
    Principal = [
      var.bedrock_kb_role_arn,
      var.lambda_role_arn,
    ]
  }])
}
```

---

## S3 모듈

세 가지 버킷을 만든다.

**런북 버킷**: Bedrock Knowledge Base가 읽는 Markdown 런북 파일을 저장한다. 버전 관리를 활성화해 런북 변경 이력을 추적한다.

**포렌식 버킷**: 사고 대응 중 수집한 증거를 저장한다. Object Lock(COMPLIANCE 모드)으로 삭제를 막고, KMS로 암호화한다.

**로그 버킷**: VPC Flow Logs, EKS 감사 로그, GuardDuty 내보내기를 받는다. 90일 후 Glacier로 전환해 비용을 줄인다.

```hcl
# modules/s3/main.tf

# 런북 버킷
resource "aws_s3_bucket" "runbooks" {
  bucket = "${var.project}-runbooks-${var.account_id}"

  tags = {
    Name    = "${var.project}-runbooks"
    Purpose = "knowledge-base"
  }
}

resource "aws_s3_bucket_versioning" "runbooks" {
  bucket = aws_s3_bucket.runbooks.id

  versioning_configuration {
    status = "Enabled"
  }
}

# 포렌식 버킷
resource "aws_s3_bucket" "forensics" {
  bucket = "${var.project}-forensics-${var.account_id}"

  object_lock_enabled = true

  tags = {
    Name    = "${var.project}-forensics"
    Purpose = "incident-evidence"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# 로그 버킷
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project}-logs-${var.account_id}"

  tags = {
    Name    = "${var.project}-logs"
    Purpose = "centralized-logging"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}
```

---

## SNS/SQS 모듈

Falcosidekick이 SNS 토픽으로 이벤트를 발행하고, SQS 큐가 이를 받아 Lambda로 전달한다. SNS → SQS 팬아웃 구조를 쓰면 나중에 구독자를 추가하기 쉽다.

DLQ(Dead Letter Queue)는 처리 실패한 메시지를 보관한다. Lambda가 3번 실패하면 메시지가 DLQ로 이동하고, CloudWatch 알람이 발생한다.

```hcl
# modules/sns-sqs/main.tf

resource "aws_sns_topic" "falco_events" {
  name              = "${var.project}-falco-events"
  kms_master_key_id = var.kms_key_id

  tags = {
    Name = "${var.project}-falco-events"
  }
}

resource "aws_sqs_queue" "agent_dlq" {
  name                      = "${var.project}-agent-dlq"
  message_retention_seconds = 1209600  # 14일
  kms_master_key_id         = var.kms_key_id

  tags = {
    Name = "${var.project}-agent-dlq"
  }
}

resource "aws_sqs_queue" "agent" {
  name                       = "${var.project}-agent"
  visibility_timeout_seconds = 360  # Lambda 타임아웃보다 길게
  message_retention_seconds  = 86400
  kms_master_key_id          = var.kms_key_id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.agent_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name = "${var.project}-agent"
  }
}

resource "aws_sns_topic_subscription" "sqs" {
  topic_arn = aws_sns_topic.falco_events.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.agent.arn
}

resource "aws_sqs_queue_policy" "agent" {
  queue_url = aws_sqs_queue.agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.agent.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_sns_topic.falco_events.arn
        }
      }
    }]
  })
}

# DLQ 알람
resource "aws_cloudwatch_metric_alarm" "dlq_not_empty" {
  alarm_name          = "${var.project}-dlq-not-empty"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DLQ에 메시지가 쌓이고 있음"

  dimensions = {
    QueueName = aws_sqs_queue.agent_dlq.name
  }
}
```

---

## 비용 추정

데모 환경 기준이다. 실제 사용 패턴에 따라 달라질 수 있다.

| 리소스 | 단가 | 월 예상 비용 |
|---|---|---|
| EKS 클러스터 | $0.10/hr | ~$72 |
| t3.medium 노드 x2 | $0.0416/hr x2 | ~$60 |
| c5.large 노드 x1 | $0.085/hr | ~$61 |
| NAT Gateway | $0.045/hr + 데이터 | ~$33 |
| GuardDuty | 프리티어 30일 이후 과금 | ~$10 |
| Bedrock (Claude) | 데모 시만 호출 | ~$5 |
| OpenSearch Serverless | OCU 최소 0.5 | ~$20 |
| S3, SNS, SQS, Lambda | 사용량 기반 | ~$5 |
| **합계** | | **~$266/월** |

비용을 줄이는 가장 효과적인 방법은 사용하지 않을 때 노드 그룹을 0으로 스케일 다운하는 것이다. EKS 클러스터 자체는 $0.10/hr이 계속 나가지만, 노드가 없으면 EC2 비용이 사라진다. `terraform apply`로 `desired_size = 0`을 적용하거나, Karpenter를 써서 워크로드가 없을 때 자동으로 노드를 제거할 수 있다.

GuardDuty는 첫 30일 프리티어가 끝나면 분석 데이터 양에 따라 과금된다. 데모 환경에서 트래픽이 많지 않으면 월 $10 수준이다.

Bedrock은 호출할 때만 비용이 발생한다. 시연 중에만 쓰면 월 $5 이하로 유지할 수 있다.
