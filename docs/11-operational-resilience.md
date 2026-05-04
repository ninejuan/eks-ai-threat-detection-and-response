# 11. 운영 안정성 설계 (Operational Resilience)

> 내부 설계 문서 v0.1 | 2026-05-04 | ATDR 캡스톤

---

## 11.1 ATDR 자체 장애 대응 (Self-Failure Handling)

ATDR 파이프라인 자체가 장애를 일으킬 수 있다. AI 분석이 실패하더라도 탐지 알림은 반드시 전달되어야 한다. 설계 원칙은 하나다.

> **탐지 전달이 분석 품질보다 우선한다.**

AI 보강(enrichment)이 실패하면 원본 알림을 그대로 Slack에 보내고 `[AI analysis unavailable]` 마커를 붙인다. 운영자가 수동으로 판단할 수 있도록 원시 데이터는 항상 포함한다.

### 컴포넌트별 폴백 전략

| 컴포넌트 | 장애 유형 | 폴백 동작 |
|---|---|---|
| SQS | 메시지 처리 실패 | DLQ로 이동 + CloudWatch 알람 |
| Lambda | 실행 오류 | SQS redrive로 재시도 (최대 3회) |
| Step Functions | 상태 전환 실패 | retry/catch → DegradedSlackNotify 상태 |
| Bedrock | 호출 실패 / 스로틀링 | 지수 백오프 재시도 → 실패 시 degraded 모드 |
| OpenSearch | 쿼리 실패 | RAG 건너뜀, `KB_UNAVAILABLE` 마커 추가 |
| Slack | 웹훅 실패 | 재시도 → 실패 시 DynamoDB `pending_notifications`에 저장 |
| DynamoDB | 쓰기 실패 | Lambda에서 재시도 (AWS SDK 기본 재시도 포함) |

### Step Functions retry/catch 패턴

Step Functions Express Workflow에서 각 AI 에이전트 상태에 retry와 catch를 설정한다. Bedrock 호출이 모두 실패하면 `DegradedSlackNotify` 상태로 분기해 원본 알림을 전송한다.

```json
{
  "Comment": "ATDR AI Agent Workflow",
  "StartAt": "TriageAgent",
  "States": {
    "TriageAgent": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${region}:${account}:function:atdr-triage-agent",
      "Retry": [
        {
          "ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException"],
          "IntervalSeconds": 5,
          "MaxAttempts": 2,
          "BackoffRate": 2.0
        }
      ],
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "Next": "DegradedSlackNotify",
          "ResultPath": "$.error"
        }
      ],
      "Next": "ForensicsAgent"
    },
    "DegradedSlackNotify": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:${region}:${account}:function:atdr-slack-notifier",
      "Parameters": {
        "mode": "degraded",
        "raw_alert.$": "$.raw_alert",
        "error.$": "$.error"
      },
      "End": true
    }
  }
}
```

### Degraded 모드 Slack 메시지 형식

AI 분석 없이 전송되는 알림은 아래 형태를 따른다.

```json
{
  "text": "[ATDR DEGRADED] AI 분석 실패 - 원본 알림 전달",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "[AI analysis unavailable] 보안 이벤트 감지"
      }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Finding ID*\n`gd-finding-abc123`" },
        { "type": "mrkdwn", "text": "*Severity*\n`HIGH`" },
        { "type": "mrkdwn", "text": "*Type*\n`UnauthorizedAccess:EC2/SSHBruteForce`" },
        { "type": "mrkdwn", "text": "*실패 원인*\n`BedrockThrottlingException`" }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "AI 분석을 완료하지 못했습니다. 원본 Finding을 직접 확인하세요."
      }
    }
  ]
}
```

실제 Slack에서는 다음과 같이 렌더링된다.

```
[AI analysis unavailable] 보안 이벤트 감지
Finding ID: gd-finding-abc123  |  Severity: HIGH
Type: UnauthorizedAccess:EC2/SSHBruteForce
실패 원인: BedrockThrottlingException

AI 분석을 완료하지 못했습니다. 원본 Finding을 직접 확인하세요.
```

### 모니터링 항목

```hcl
# modules/monitoring/alarms.tf

resource "aws_cloudwatch_metric_alarm" "sqs_oldest_message" {
  alarm_name          = "${var.project}-sqs-oldest-message"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 600  # 10분 이상 처리 안 된 메시지
  alarm_description   = "SQS 메시지가 10분 이상 처리되지 않음"

  dimensions = {
    QueueName = var.agent_queue_name
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Lambda 에이전트 오류 3회 초과"

  dimensions = {
    FunctionName = var.agent_function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "sfn_failures" {
  alarm_name          = "${var.project}-sfn-execution-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ExecutionsFailed"
  namespace           = "AWS/States"
  period              = 60
  statistic           = "Sum"
  threshold           = 2
  alarm_description   = "Step Functions 실행 실패 2회 초과"

  dimensions = {
    StateMachineArn = var.state_machine_arn
  }
}
```

### 트레이드오프

완전한 재시도 루프를 구현하면 더 높은 복구율을 얻을 수 있지만, 재시도 중 Bedrock 스로틀링이 악화될 수 있다. 캡스톤 범위에서는 2회 재시도 후 degraded 모드로 즉시 전환하는 방식을 택했다. 알림 누락보다 지연 없는 전달이 더 중요하기 때문이다.

Slack 실패 시 DynamoDB에 pending 상태로 저장하는 방식은 별도 폴링 Lambda가 필요하다. 8주 일정을 고려해 DynamoDB 저장까지만 구현하고 재전송 폴링은 선택 구현으로 남긴다.

---

## 11.2 Bedrock Rate Limiting

### 문제

5개 공격 시나리오를 동시에 시뮬레이션하면 각 시나리오당 4개 에이전트(Triage, Forensics, Remediation, Reporting)가 Bedrock을 호출한다. 최악의 경우 20개 호출이 동시에 발생한다. Bedrock Claude의 기본 RPM(Requests Per Minute) 한도를 초과하면 `ThrottlingException`이 연쇄적으로 발생한다.

### 해결 방법

별도 토큰 버킷을 구현하지 않고 기존 인프라 설정으로 동시성을 제한한다.

- `SQS batch_size = 1`: Lambda가 한 번에 하나의 인시던트만 처리
- `Lambda maximum_concurrency = 2`: 동시에 실행되는 Lambda 인스턴스 최대 2개
- Step Functions 내 에이전트 순차 실행: 하나의 인시던트 안에서 4개 에이전트가 직렬로 실행

이 조합으로 Bedrock에 동시에 도달하는 호출은 최대 2개로 제한된다.

```hcl
# modules/lambda/main.tf

resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn                   = var.sqs_queue_arn
  function_name                      = aws_lambda_function.agent.arn
  batch_size                         = 1
  maximum_concurrency                = 2
  enabled                            = true
}
```

### Bedrock 호출 재시도 설정

Step Functions에서 Bedrock 스로틀링 발생 시 지수 백오프로 재시도한다. 5초 → 10초 → 20초 → 40초 순서로 대기하고, 4회 모두 실패하면 degraded 모드로 전환한다.

```json
"Retry": [
  {
    "ErrorEquals": [
      "Bedrock.ThrottlingException",
      "Bedrock.ServiceUnavailableException"
    ],
    "IntervalSeconds": 5,
    "MaxAttempts": 4,
    "BackoffRate": 2.0,
    "MaxDelaySeconds": 40
  }
]
```

### BedrockThrottlingException 모니터링

Lambda 로그에서 스로틀링 예외를 집계하는 CloudWatch Logs 메트릭 필터를 설정한다.

```hcl
resource "aws_cloudwatch_log_metric_filter" "bedrock_throttling" {
  name           = "${var.project}-bedrock-throttling"
  log_group_name = "/aws/lambda/${var.agent_function_name}"
  pattern        = "BedrockThrottlingException"

  metric_transformation {
    name      = "BedrockThrottlingCount"
    namespace = "ATDR/Bedrock"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "bedrock_throttling" {
  alarm_name          = "${var.project}-bedrock-throttling"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BedrockThrottlingCount"
  namespace           = "ATDR/Bedrock"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "5분 내 Bedrock 스로틀링 5회 초과"
}
```

### 모니터링 항목

- `BedrockThrottlingCount` (ATDR/Bedrock 네임스페이스): 5분 내 5회 초과 시 알람
- Step Functions `ExecutionsFailed`: degraded 전환 빈도 추적
- Lambda `Duration` P99: Bedrock 응답 지연 감지

### 트레이드오프

`maximum_concurrency = 2`는 처리량을 제한한다. 실제 공격이 동시에 5개 발생하면 3개는 SQS에서 대기한다. 캡스톤 데모 환경에서는 허용 가능한 수준이다. 프로덕션이라면 Bedrock 서비스 할당량 증가 요청과 함께 동시성을 높여야 한다.

토큰 버킷 구현(예: Redis 기반 rate limiter)은 더 정밀한 제어가 가능하지만 운영 복잡도가 올라간다. 8주 일정에서는 SQS 동시성 제한으로 충분하다.

---

## 11.3 드리프트 감지 (Drift Detection)

인프라가 Terraform 상태와 달라지면 보안 설정이 조용히 무력화될 수 있다. 보안 그룹 규칙이 콘솔에서 수정되거나 GuardDuty detector가 비활성화되는 경우가 대표적이다. 두 가지 레이어로 드리프트를 감지한다.

**레이어 1**: 정기 `terraform plan`으로 전체 상태 비교  
**레이어 2**: AWS Config + EventBridge로 고위험 변경 실시간 감지

### 정기 Terraform Plan (GitHub Actions)

`terraform plan -detailed-exitcode`는 변경 사항이 있으면 exit code 2를 반환한다. GitHub Actions 스케줄로 매일 실행하고, 드리프트가 감지되면 Slack에 알린다.

```yaml
# .github/workflows/drift-detection.yml

name: Drift Detection

on:
  schedule:
    - cron: "0 1 * * *"  # 매일 오전 10시 KST
  workflow_dispatch:

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DRIFT_DETECTION_ROLE_ARN }}
          aws-region: ap-northeast-2

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "1.9.0"

      - name: Terraform Init
        working-directory: terraform/environments/dev
        run: terraform init

      - name: Terraform Plan
        id: plan
        working-directory: terraform/environments/dev
        run: |
          terraform plan -detailed-exitcode -out=tfplan 2>&1
          echo "exit_code=$?" >> $GITHUB_OUTPUT
        continue-on-error: true

      - name: Notify drift detected
        if: steps.plan.outputs.exit_code == '2'
        run: |
          curl -X POST "${{ secrets.SLACK_WEBHOOK_URL }}" \
            -H "Content-Type: application/json" \
            -d '{"text": "[ATDR DRIFT] Terraform 상태와 실제 인프라가 다릅니다. 즉시 확인하세요."}'
```

### EventBridge 고위험 변경 감지

보안 그룹, GuardDuty detector, CloudTrail 변경은 즉시 알림이 필요하다. EventBridge 규칙으로 실시간 감지한다.

```hcl
# modules/eventbridge/drift.tf

# 보안 그룹 변경 감지
resource "aws_cloudwatch_event_rule" "sg_change" {
  name        = "${var.project}-sg-change"
  description = "보안 그룹 인바운드/아웃바운드 규칙 변경 감지"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "DeleteSecurityGroup",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_change_lambda" {
  rule      = aws_cloudwatch_event_rule.sg_change.name
  target_id = "DriftNotifier"
  arn       = var.drift_notifier_lambda_arn
}

# GuardDuty detector 변경 감지
resource "aws_cloudwatch_event_rule" "guardduty_change" {
  name        = "${var.project}-guardduty-change"
  description = "GuardDuty detector 비활성화 또는 삭제 감지"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteDetector",
        "UpdateDetector",
        "DisassociateFromMasterAccount",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_change_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_change.name
  target_id = "DriftNotifier"
  arn       = var.drift_notifier_lambda_arn
}

# CloudTrail 변조 감지
resource "aws_cloudwatch_event_rule" "cloudtrail_change" {
  name        = "${var.project}-cloudtrail-change"
  description = "CloudTrail 로깅 중단 또는 삭제 감지"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_change_lambda" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_change.name
  target_id = "DriftNotifier"
  arn       = var.drift_notifier_lambda_arn
}
```

### AWS Config 범위 설정

AWS Config는 변경 이력을 기록하고 규칙 위반을 감지한다. 전체 리소스를 기록하면 비용이 올라가므로 보안 관련 리소스만 범위를 좁힌다.

```hcl
# modules/config/main.tf

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project}-recorder"
  role_arn = var.config_role_arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false

    resource_types = [
      "AWS::EC2::SecurityGroup",
      "AWS::GuardDuty::Detector",
      "AWS::CloudTrail::Trail",
      "AWS::IAM::Role",
      "AWS::IAM::Policy",
    ]
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project}-delivery"
  s3_bucket_name = var.config_bucket_name

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}
```

### 모니터링 항목

- EventBridge 규칙 매칭 횟수: 보안 그룹 변경이 하루 N회 이상이면 알람
- GitHub Actions 워크플로 실패: drift detection 잡 자체가 실패하면 알람
- AWS Config 규칙 위반 수: Config 대시보드에서 추적

### 트레이드오프

`terraform plan`은 AWS API를 호출하므로 실행 역할에 읽기 권한이 필요하다. 쓰기 권한 없이 읽기 전용 역할을 별도로 만들어 GitHub Actions에 부여한다. 이 역할이 탈취되면 인프라 구조가 노출될 수 있으므로 OIDC 기반 임시 자격증명을 사용한다.

AWS Config는 리소스 변경 기록당 과금된다. 5개 리소스 타입만 기록하면 데모 환경에서 월 $1 미만이다.

---

## 11.4 DynamoDB 백업

인시던트 기록(`incidents` 테이블)과 승인 감사 로그(`approval_audit` 테이블)는 복구 불가능한 데이터다. 두 테이블 모두 PITR(Point-in-Time Recovery)을 활성화한다.

### Terraform 설정

```hcl
# modules/dynamodb/main.tf

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.project}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"
  range_key    = "timestamp"

  attribute {
    name = "incident_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Name        = "${var.project}-incidents"
    DataClass   = "sensitive"
    BackupClass = "pitr"
  }
}

resource "aws_dynamodb_table" "approval_audit" {
  name         = "${var.project}-approval-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "audit_id"
  range_key    = "created_at"

  attribute {
    name = "audit_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = {
    Name        = "${var.project}-approval-audit"
    DataClass   = "sensitive"
    BackupClass = "pitr"
  }
}
```

### 데모 전 온디맨드 백업

데모 직전에 수동으로 온디맨드 백업을 생성한다. PITR은 35일 이내 임의 시점으로 복구하지만, 온디맨드 백업은 명시적인 스냅샷이라 "데모 직전 상태"로 정확히 돌아갈 수 있다.

```bash
# 데모 전 백업 스크립트
PROJECT="atdr"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

aws dynamodb create-backup \
  --table-name "${PROJECT}-incidents" \
  --backup-name "${PROJECT}-incidents-pre-demo-${TIMESTAMP}"

aws dynamodb create-backup \
  --table-name "${PROJECT}-approval-audit" \
  --backup-name "${PROJECT}-approval-audit-pre-demo-${TIMESTAMP}"

echo "백업 완료: ${TIMESTAMP}"
```

Makefile에 타겟으로 추가해 팀원 누구나 실행할 수 있게 한다.

```makefile
.PHONY: backup-before-demo
backup-before-demo:
	@echo "데모 전 DynamoDB 백업 시작..."
	@bash scripts/backup-dynamodb.sh
```

### S3 감사 아카이브 (선택)

장기 감사 목적으로 DynamoDB 데이터를 S3로 내보낼 수 있다. PITR이 활성화된 테이블에서만 가능하다.

```bash
aws dynamodb export-table-to-point-in-time \
  --table-arn "arn:aws:dynamodb:ap-northeast-2:${ACCOUNT_ID}:table/atdr-incidents" \
  --s3-bucket "atdr-logs-${ACCOUNT_ID}" \
  --s3-prefix "dynamodb-exports/incidents/" \
  --export-format "DYNAMODB_JSON"
```

캡스톤 범위에서는 PITR과 온디맨드 백업으로 충분하다. S3 내보내기는 감사 요구사항이 생기면 추가한다.

### 모니터링 항목

- `SystemErrors` (AWS/DynamoDB): 쓰기 실패 감지
- `ConsumedWriteCapacityUnits`: PAY_PER_REQUEST 모드에서도 급증 감지 가능
- 온디맨드 백업 생성 성공 여부: 데모 전 체크리스트에 포함

### 트레이드오프

PITR은 테이블당 월 $0.20/GB 수준의 추가 비용이 발생한다. 데모 환경에서 데이터 크기가 작으므로 무시할 수 있는 수준이다.

온디맨드 백업은 보관 기간 제한이 없지만 저장 비용이 발생한다. 데모가 끝나면 불필요한 백업을 삭제해 비용을 줄인다. `aws dynamodb list-backups`로 목록을 확인하고 `aws dynamodb delete-backup`으로 정리한다.
