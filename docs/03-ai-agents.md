# 03. AI 에이전트 설계

## 목차

1. [아키텍처 개요](#1-아키텍처-개요)
2. [Summary Agent](#2-summary-agent)
3. [Triage Agent](#3-triage-agent)
4. [Solution Agent](#4-solution-agent)
5. [Remediation Agent](#5-remediation-agent)
6. [Agent 간 통신 스키마](#6-agent-간-통신-스키마)
7. [Bedrock 모델 설정](#7-bedrock-모델-설정)
8. [Knowledge Base 설계](#8-knowledge-base-설계)

---

## 1. 아키텍처 개요

### AWS Strands Agent SDK 선택 이유

ATDR(AI Threat Detection and Response)의 AI 레이어는 AWS Strands Agent SDK를 기반으로 구축한다. 선택 근거는 세 가지다.

첫째, Bedrock 네이티브 통합이다. Strands SDK는 Amazon Bedrock을 직접 호출하도록 설계되어 있어 별도의 LLM 래퍼나 프록시 없이 Claude 모델을 사용할 수 있다. AWS SA 레퍼런스 아키텍처와 동일한 패턴을 따르므로 운영 복잡도가 낮다.

둘째, Tool use와 MCP 지원이다. Strands SDK는 Python 함수를 tool로 등록하는 방식과 Model Context Protocol(MCP) 서버 연동을 모두 지원한다. Remediation Agent가 EKS API를 직접 호출하는 구조에서 이 기능이 핵심이다.

셋째, Lambda 실행 환경과의 궁합이다. Strands Agent는 상태를 외부에 위임하는 stateless 설계를 기본으로 하므로 Lambda의 ephemeral 실행 모델과 자연스럽게 맞는다.

### Lambda 기반 실행 환경

각 Agent는 독립적인 Lambda 함수로 배포된다. Step Functions Express Workflow가 4개 Agent의 실행 순서, 재시도, 에러 핸들링을 관리한다.

```
EventBridge / SQS
      |
      v
Step Functions Express Workflow
      |
      +-- [1] Lambda: Summary Agent
      |         +-- Bedrock API (Haiku)
      |
      +-- [2] Lambda: Triage Agent
      |         +-- Bedrock API (Haiku)
      |
      +-- [3] Lambda: Solution Agent
      |         +-- Bedrock API (Sonnet) + OpenSearch KB
      |
      +-- [4] Lambda: Remediation Agent
      |         +-- Bedrock API (Sonnet) + EKS MCP
      |
      v
DynamoDB (인시던트 기록) + Slack (알림)
```

Lambda 함수별 메모리와 타임아웃 설정은 Agent 역할에 따라 다르게 잡는다.

| Agent | 메모리 | 타임아웃 | 이유 |
|---|---|---|---|
| Summary Agent | 512 MB | 30s | 단순 변환, 빠른 응답 필요 |
| Triage Agent | 512 MB | 30s | 분류 로직, 경량 |
| Solution Agent | 1024 MB | 120s | RAG 파이프라인, 벡터 검색 포함 |
| Remediation Agent | 1024 MB | 180s | EKS API 호출, 검증 루프 포함 |

### 4 Agent 오케스트레이션: Step Functions Express Workflow

ATDR은 단일 모놀리식 AI가 아니라 역할이 분리된 4개의 전문 Agent로 구성된다. 각 Agent는 이전 Agent의 출력을 입력으로 받아 처리하는 파이프라인 구조다.

```
원시 이벤트 (GuardDuty / Falco)
        |
        v
  [Summary Agent]  -- 원시 JSON → 구조화된 요약
        |
        v
  [Triage Agent]   -- 심각도 판단, 우선순위 결정
        |
        v
  [Solution Agent] -- KB 검색, 런북 매칭, 대응 추천
        |
        v
[Remediation Agent] -- 액션 실행 (Human Approval 포함)
```

기존 설계에서는 Agent 간 데이터를 SQS 큐로 전달했으나, Step Functions Express Workflow로 전환했다. 이유는 세 가지다.

첫째, end-to-end 추적이다. Step Functions 콘솔에서 전체 파이프라인의 실행 상태를 시각적으로 확인할 수 있다. 어떤 Agent에서 실패했는지, 각 단계의 입출력이 무엇인지 한눈에 보인다. X-Ray 통합도 자동으로 따라온다.

둘째, 에러 핸들링이다. Agent별로 재시도 횟수, 백오프 전략, 타임아웃을 선언적으로 정의할 수 있다. SQS 기반에서는 DLQ 재처리 운영 절차를 직접 구현해야 했다.

셋째, 비용이다. Express Workflow는 실행 횟수와 실행 시간 기반 과금이다. 데모 환경에서 하루 수십 건 처리 수준이면 월 $1 미만이다.

```json
{
  "Comment": "ATDR Agent Pipeline",
  "StartAt": "SummaryAgent",
  "States": {
    "SummaryAgent": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-2:ACCOUNT:function:atdr-summary-agent",
      "Retry": [{"ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 2, "BackoffRate": 2}],
      "Next": "TriageAgent"
    },
    "TriageAgent": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-2:ACCOUNT:function:atdr-triage-agent",
      "Retry": [{"ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 2, "BackoffRate": 2}],
      "Next": "CheckSeverity"
    },
    "CheckSeverity": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.severity",
          "StringEquals": "P4",
          "Next": "LogOnly"
        }
      ],
      "Default": "SolutionAgent"
    },
    "SolutionAgent": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-2:ACCOUNT:function:atdr-solution-agent",
      "Retry": [{"ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 2, "BackoffRate": 2}],
      "Next": "RemediationAgent"
    },
    "RemediationAgent": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-2:ACCOUNT:function:atdr-remediation-agent",
      "Retry": [{"ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 1}],
      "End": true
    },
    "LogOnly": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:ap-northeast-2:ACCOUNT:function:atdr-log-incident",
      "End": true
    }
  }
}
```

Express Workflow는 최대 5분 실행 제한이 있다. 4개 Agent의 총 실행 시간이 이 안에 들어와야 한다. Summary(~5s) + Triage(~5s) + Solution(~30s) + Remediation(~60s) = ~100초이므로 충분하다. Human Approval이 필요한 경우에는 Remediation Agent가 Slack 알림을 보내고 콜백 패턴으로 처리한다.

---
## 2. Summary Agent

### 역할

Summary Agent는 파이프라인의 첫 번째 관문이다. GuardDuty Finding이나 Falco Alert의 원시 JSON을 받아 보안 운영자가 즉시 이해할 수 있는 구조화된 요약으로 변환한다. 이 단계에서 노이즈를 줄이고 핵심 정보만 추출하는 것이 목표다.

### 모델: Claude Haiku 4.5

요약 작업은 복잡한 추론보다 빠른 처리량이 중요하다. Claude Haiku 4.5는 Claude 모델군에서 가장 빠르고 저렴하며, 구조화된 JSON 출력 생성에 충분한 성능을 보인다. 데모 환경 기준으로 GuardDuty Finding 하나를 처리하는 데 평균 2~3초, 비용은 요청당 $0.001 미만이다.

### 입력 형식

GuardDuty Finding JSON:

```json
{
  "schemaVersion": "2.0",
  "accountId": "123456789012",
  "region": "ap-northeast-2",
  "type": "UnauthorizedAccess:EC2/SSHBruteForce",
  "severity": 5.0,
  "title": "SSH brute force attack from 1.2.3.4",
  "description": "...",
  "resource": {
    "resourceType": "Instance",
    "instanceDetails": { "instanceId": "i-0abc123" }
  },
  "service": {
    "action": {
      "networkConnectionAction": {
        "remoteIpDetails": { "ipAddressV4": "1.2.3.4" }
      }
    }
  }
}
```

Falco Alert JSON:

```json
{
  "output": "Unexpected outbound connection (command=curl, connection=10.0.0.5:443)",
  "priority": "WARNING",
  "rule": "Unexpected outbound connection destination",
  "time": "2026-05-04T10:00:00Z",
  "output_fields": {
    "container.id": "abc123",
    "k8s.pod.name": "payment-service-7d9f8b-xkp2q",
    "k8s.ns.name": "production",
    "proc.name": "curl",
    "fd.rip": "10.0.0.5"
  }
}
```

### 출력 형식

```json
{
  "summary_id": "sum-20260504-001",
  "source": "guardduty",
  "threat_type": "SSH Brute Force",
  "severity_raw": 5.0,
  "affected_resource": {
    "type": "EC2 Instance",
    "id": "i-0abc123",
    "namespace": null,
    "pod_name": null
  },
  "key_evidence": [
    "외부 IP 1.2.3.4에서 SSH 포트(22)로 반복 접속 시도",
    "10분간 342회 연결 실패 기록"
  ],
  "human_summary": "외부 IP 1.2.3.4가 EC2 인스턴스 i-0abc123에 SSH 무차별 대입 공격을 시도하고 있습니다. 10분간 342회 연결 실패가 기록되었으며, 현재 진행 중입니다.",
  "timestamp": "2026-05-04T10:00:00Z",
  "raw_event_ref": "arn:aws:guardduty:ap-northeast-2:123456789012:detector/abc/finding/xyz"
}
```

### 프롬프트 설계

```python
SUMMARY_SYSTEM_PROMPT = """
당신은 AWS EKS 보안 이벤트를 분석하는 전문가입니다.
주어진 보안 이벤트 JSON을 분석하여 보안 운영자가 즉시 이해할 수 있는 구조화된 요약을 생성하세요.

출력은 반드시 다음 JSON 스키마를 따라야 합니다:
- threat_type: 위협 유형 (한국어)
- affected_resource: 영향받는 리소스 정보
- key_evidence: 핵심 증거 목록 (최대 5개)
- human_summary: 보안 운영자를 위한 한국어 요약 (2~3문장)

추측하지 말고 이벤트 데이터에 있는 사실만 기술하세요.
"""
```

### Strands Agent 코드 스켈레톤

```python
import json
import boto3
from strands import Agent
from strands.models import BedrockModel

MODEL_ID = "global.anthropic.claude-haiku-4-5-20251001-v1:0"

bedrock_model = BedrockModel(
    model_id=MODEL_ID,
    region_name="us-east-1",
    temperature=0.0,
    max_tokens=1024,
)

summary_agent = Agent(
    model=bedrock_model,
    system_prompt=SUMMARY_SYSTEM_PROMPT,
)

def handler(event, context):
    """Lambda handler for Summary Agent."""
    raw_event = json.loads(event["body"])
    source = raw_event.get("source", "unknown")

    user_message = f"""
다음 보안 이벤트를 분석하고 구조화된 요약을 JSON으로 반환하세요.

이벤트 소스: {source}
이벤트 데이터:
{json.dumps(raw_event, ensure_ascii=False, indent=2)}
"""

    response = summary_agent(user_message)
    summary = json.loads(response.message["content"][0]["text"])

    # 다음 Agent 큐로 전달
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=TRIAGE_QUEUE_URL,
        MessageBody=json.dumps(summary, ensure_ascii=False),
    )

    return {"statusCode": 200, "body": json.dumps(summary)}
```

---
## 3. Triage Agent

### 역할

Triage Agent는 Summary Agent의 출력을 받아 세 가지 판단을 내린다. 첫째, 이 이벤트가 실제 대응이 필요한 위협인지 아닌지. 둘째, 얼마나 급한지(우선순위). 셋째, 같은 pod나 namespace에서 반복되는 이벤트인지(중복 필터링). 이 단계를 거쳐야 Solution Agent가 불필요한 이벤트를 처리하는 낭비를 막을 수 있다.

### 모델: Claude Haiku 4.5

분류와 필터링은 빠른 응답이 핵심이다. Haiku 4.5로 충분하다.

### 심각도 분류 체계

| 레벨 | 이름 | 기준 | 대응 시간 목표 |
|---|---|---|---|
| P1 | Critical | 활성 침해, 데이터 유출 가능성, 권한 상승 성공 | 즉시 (자동 대응 트리거) |
| P2 | High | 의심스러운 lateral movement, 비정상 외부 통신 | 15분 이내 |
| P3 | Medium | 정책 위반, 비정상 프로세스 실행 | 1시간 이내 |
| P4 | Low | 정보성 경고, 단발성 이상 | 24시간 이내 또는 무시 |

P1 이벤트는 Triage Agent가 Remediation Agent를 직접 트리거할 수 있다. Solution Agent를 건너뛰는 fast-path다.

### 중복 탐지 로직

같은 pod나 namespace에서 동일한 위협 유형이 5분 내에 3회 이상 발생하면 중복으로 판단한다. 중복 이벤트는 기존 인시던트에 집계되고 별도 처리 파이프라인을 타지 않는다.

```python
def is_duplicate(event: dict, window_minutes: int = 5, threshold: int = 3) -> bool:
    """
    DynamoDB에서 최근 window_minutes 내 동일 조건 이벤트 수를 조회.
    threshold 이상이면 중복으로 판단.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(DEDUP_TABLE_NAME)

    key = f"{event['affected_resource']['pod_name']}#{event['threat_type']}"
    cutoff = int((datetime.utcnow() - timedelta(minutes=window_minutes)).timestamp())

    response = table.query(
        KeyConditionExpression=Key("dedup_key").eq(key) & Key("timestamp").gt(cutoff)
    )
    return response["Count"] >= threshold
```

### 에스컬레이션 규칙

다음 조건 중 하나라도 해당하면 P1으로 강제 에스컬레이션한다.

- `kube-system` 또는 `kube-public` namespace에서 발생한 이벤트
- `cluster-admin` 권한을 가진 ServiceAccount 관련 이벤트
- 외부 IP로의 대용량 데이터 전송 (>100MB/min)
- 컨테이너 탈출 시도 패턴 (privileged container, host path mount 등)

### 출력 형식

```json
{
  "triage_id": "tri-20260504-001",
  "summary_id": "sum-20260504-001",
  "priority": "P2",
  "priority_reason": "비정상 외부 통신 패턴 감지, lateral movement 가능성",
  "requires_action": true,
  "is_duplicate": false,
  "escalation_triggered": false,
  "fast_path": false,
  "recommended_next": "solution_agent",
  "timestamp": "2026-05-04T10:00:05Z"
}
```

### Strands Agent 코드 스켈레톤

```python
TRIAGE_SYSTEM_PROMPT = """
당신은 Kubernetes 보안 이벤트 트리아지 전문가입니다.
주어진 보안 이벤트 요약을 분석하여 우선순위를 결정하고 대응 필요 여부를 판단하세요.

우선순위 기준:
- P1 Critical: 활성 침해, 데이터 유출, 권한 상승 성공
- P2 High: lateral movement 의심, 비정상 외부 통신
- P3 Medium: 정책 위반, 비정상 프로세스
- P4 Low: 정보성 경고

판단 근거를 명확히 설명하고, 반드시 JSON 형식으로 출력하세요.
"""

triage_agent = Agent(
    model=BedrockModel(
        model_id=MODEL_ID,
        temperature=0.0,
        max_tokens=512,
    ),
    system_prompt=TRIAGE_SYSTEM_PROMPT,
)

def handler(event, context):
    summary = json.loads(event["body"])

    if is_duplicate(summary):
        aggregate_to_existing_incident(summary)
        return {"statusCode": 200, "body": json.dumps({"status": "deduplicated"})}

    response = triage_agent(
        f"다음 보안 이벤트 요약을 트리아지하세요:\n{json.dumps(summary, ensure_ascii=False)}"
    )
    triage_result = json.loads(response.message["content"][0]["text"])

    if triage_result["fast_path"]:
        forward_to_remediation(triage_result)
    else:
        forward_to_solution(triage_result)

    return {"statusCode": 200, "body": json.dumps(triage_result)}
```

---
## 4. Solution Agent

### 역할

Solution Agent는 파이프라인에서 가장 복잡한 추론을 담당한다. Triage Agent가 "대응이 필요하다"고 판단한 이벤트를 받아 Knowledge Base에서 관련 런북을 검색하고, 근본 원인을 분석하며, 우선순위가 매겨진 대응 액션 목록을 생성한다.

### 모델: Claude Sonnet 4.6

RAG 파이프라인을 통해 검색된 컨텍스트를 이해하고 복잡한 인과관계를 추론하는 작업에는 Haiku보다 강력한 모델이 필요하다. Claude Sonnet 4.6은 긴 컨텍스트 처리와 구조화된 추론에서 Haiku 대비 유의미하게 나은 결과를 보인다.

### RAG 파이프라인

```
Triage 결과 수신
      |
      v
쿼리 생성 (위협 유형 + 영향 리소스 기반)
      |
      v
Bedrock Knowledge Base API 호출
      |
      +-- OpenSearch Serverless 벡터 검색
      |   (Titan Embeddings V2로 인덱싱된 런북)
      |
      v
관련 런북 청크 반환 (top-k=5)
      |
      v
Claude Sonnet 4.6에 컨텍스트 주입
      |
      v
진단 + 대응 추천 생성
```

Bedrock Knowledge Base API 호출 예시:

```python
import boto3

bedrock_agent_runtime = boto3.client("bedrock-agent-runtime", region_name="us-east-1")

def retrieve_runbooks(query: str, kb_id: str, top_k: int = 5) -> list[dict]:
    """Knowledge Base에서 관련 런북 청크를 검색한다."""
    response = bedrock_agent_runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": query},
        retrievalConfiguration={
            "vectorSearchConfiguration": {
                "numberOfResults": top_k,
                "overrideSearchType": "HYBRID",  # 벡터 + 키워드 혼합
            }
        },
    )
    return [
        {
            "content": r["content"]["text"],
            "score": r["score"],
            "source": r["location"]["s3Location"]["uri"],
        }
        for r in response["retrievalResults"]
    ]
```

### 런북 매칭 로직

검색된 런북 청크는 relevance score 기준으로 정렬된다. score 0.7 미만인 청크는 컨텍스트에서 제외한다. 매칭된 런북이 없으면 Agent는 일반 보안 원칙에 기반한 추천을 생성하되, 출력에 `runbook_matched: false` 플래그를 포함한다.

### 대응 추천 생성

Solution Agent는 최대 5개의 대응 액션을 우선순위 순으로 반환한다. 각 액션은 실행 가능성(Remediation Agent가 자동 실행할 수 있는지), 예상 영향 범위, 롤백 가능 여부를 포함한다.

### 출력 형식

```json
{
  "solution_id": "sol-20260504-001",
  "triage_id": "tri-20260504-001",
  "root_cause_analysis": "payment-service pod가 내부 네트워크 스캔을 수행 중입니다. Falco 규칙 'Unexpected outbound connection'이 트리거되었으며, 동일 pod에서 10분간 47개 내부 IP에 대한 연결 시도가 확인됩니다. 컨테이너 내부 프로세스(curl)가 서비스 디스커버리 목적이 아닌 비정상 패턴으로 내부 IP를 순회하고 있어 lateral movement 시도로 판단됩니다.",
  "runbook_matched": true,
  "matched_runbooks": [
    {
      "title": "Lateral Movement - Internal Network Scan Response",
      "s3_uri": "s3://atdr-runbooks/lateral-movement/internal-scan.md",
      "relevance_score": 0.92
    }
  ],
  "recommended_actions": [
    {
      "rank": 1,
      "action_type": "network_policy_apply",
      "description": "payment-service pod에 egress NetworkPolicy를 적용하여 허용된 서비스 외 모든 아웃바운드 트래픽 차단",
      "auto_executable": true,
      "blast_radius": "low",
      "reversible": true,
      "estimated_impact": "payment-service의 외부 통신 차단. 정상 서비스 흐름에는 영향 없음"
    },
    {
      "rank": 2,
      "action_type": "pod_isolate",
      "description": "의심 pod를 격리 namespace로 이동하여 추가 분석",
      "auto_executable": false,
      "blast_radius": "medium",
      "reversible": true,
      "estimated_impact": "payment-service 일시 중단. Human Approval 필요"
    }
  ],
  "timestamp": "2026-05-04T10:00:15Z"
}
```

### Strands Agent 코드 스켈레톤

```python
SOLUTION_SYSTEM_PROMPT = """
당신은 Kubernetes 보안 인시던트 대응 전문가입니다.
주어진 트리아지 결과와 관련 런북을 바탕으로 근본 원인을 분석하고
우선순위가 매겨진 대응 액션 목록을 생성하세요.

각 대응 액션에는 다음을 포함하세요:
- 실행 가능성 (자동 실행 가능 여부)
- 예상 영향 범위 (low/medium/high)
- 롤백 가능 여부

추측하지 말고 제공된 런북과 이벤트 데이터에 근거하여 판단하세요.
런북에 해당 케이스가 없으면 명시적으로 표시하세요.
"""

solution_agent = Agent(
    model=BedrockModel(
        model_id="global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        temperature=0.1,
        max_tokens=2048,
    ),
    system_prompt=SOLUTION_SYSTEM_PROMPT,
)

def handler(event, context):
    triage_result = json.loads(event["body"])

    # 관련 런북 검색
    query = f"{triage_result['threat_type']} {triage_result['affected_resource']}"
    runbooks = retrieve_runbooks(query, kb_id=KB_ID)

    runbook_context = "\n\n".join(
        [f"[런북: {r['source']}]\n{r['content']}" for r in runbooks]
    )

    user_message = f"""
트리아지 결과:
{json.dumps(triage_result, ensure_ascii=False, indent=2)}

관련 런북:
{runbook_context}

위 정보를 바탕으로 근본 원인을 분석하고 대응 액션을 추천하세요.
"""

    response = solution_agent(user_message)
    solution = json.loads(response.message["content"][0]["text"])

    forward_to_remediation(solution)
    return {"statusCode": 200, "body": json.dumps(solution)}
```

---
## 5. Remediation Agent

### 역할

Remediation Agent는 파이프라인의 마지막 단계다. Solution Agent가 추천한 액션 목록을 받아 실제로 실행한다. 자동 실행 가능한 액션은 Human Approval 없이 처리하고, 영향 범위가 크거나 비가역적인 액션은 승인을 기다린다. 실행 후에는 결과를 검증하고 런북을 업데이트한다.

### 모델: Claude Sonnet 4.6

실행 결과를 해석하고 후속 액션을 결정하는 추론이 필요하므로 Sonnet 4.6을 사용한다.

### EKS MCP 연동

Remediation Agent는 EKS MCP(Model Context Protocol) 서버를 통해 Kubernetes API를 호출한다. MCP 서버는 EKS 클러스터와 같은 VPC 내의 Lambda 또는 ECS 태스크로 실행된다.

```python
from strands import Agent
from strands.models import BedrockModel
from strands_tools import MCPClient

# EKS MCP 서버 연결
eks_mcp = MCPClient(
    server_url=EKS_MCP_SERVER_URL,
    auth_token=get_mcp_auth_token(),
)

# MCP 서버가 노출하는 tool 목록 (예시)
# - apply_network_policy(namespace, pod_selector, egress_rules)
# - isolate_pod(namespace, pod_name, quarantine_namespace)
# - delete_pod(namespace, pod_name)
# - patch_deployment(namespace, deployment_name, patch)
# - get_pod_logs(namespace, pod_name, tail_lines)

remediation_agent = Agent(
    model=BedrockModel(
        model_id="global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        temperature=0.0,
        max_tokens=2048,
    ),
    system_prompt=REMEDIATION_SYSTEM_PROMPT,
    tools=eks_mcp.get_tools(),
)
```

### Human Approval 체크

`auto_executable: false`이거나 `blast_radius: high`인 액션은 실행 전에 승인을 요청한다. 승인 요청은 SNS를 통해 Slack 또는 이메일로 전달된다. 승인 응답은 API Gateway를 통해 수신하고 DynamoDB에 기록한다.

```python
def requires_approval(action: dict) -> bool:
    return (
        not action.get("auto_executable", False)
        or action.get("blast_radius") == "high"
        or not action.get("reversible", True)
    )

def request_approval(action: dict, solution_id: str) -> str:
    """승인 요청을 SNS로 발행하고 approval_id를 반환한다."""
    sns = boto3.client("sns")
    approval_id = f"appr-{solution_id}-{action['rank']}"

    message = {
        "approval_id": approval_id,
        "action": action,
        "approve_url": f"{APPROVAL_API_URL}/approve/{approval_id}",
        "reject_url": f"{APPROVAL_API_URL}/reject/{approval_id}",
        "expires_at": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
    }

    sns.publish(
        TopicArn=APPROVAL_TOPIC_ARN,
        Subject=f"[ATDR] 대응 액션 승인 요청: {action['action_type']}",
        Message=json.dumps(message, ensure_ascii=False),
    )
    return approval_id
```

### 실행 결과 검증

액션 실행 후 Remediation Agent는 결과를 검증한다. NetworkPolicy 적용의 경우 실제로 트래픽이 차단되었는지 확인하고, pod 격리의 경우 pod가 quarantine namespace로 이동했는지 확인한다.

### 런북 업데이트 피드백

실행 결과(성공/실패, 예상치 못한 부작용 등)는 S3의 런북 저장소에 피드백으로 기록된다. 이 데이터는 Knowledge Base 재인덱싱 시 반영되어 Solution Agent의 추천 품질을 점진적으로 개선한다.

### 출력 형식

```json
{
  "remediation_id": "rem-20260504-001",
  "solution_id": "sol-20260504-001",
  "executed_actions": [
    {
      "rank": 1,
      "action_type": "network_policy_apply",
      "status": "success",
      "executed_at": "2026-05-04T10:01:00Z",
      "approval_required": false,
      "result": {
        "policy_name": "atdr-block-payment-service-egress",
        "namespace": "production",
        "applied": true
      }
    }
  ],
  "pending_actions": [
    {
      "rank": 2,
      "action_type": "pod_isolate",
      "status": "awaiting_approval",
      "approval_id": "appr-sol-20260504-001-2",
      "approval_expires_at": "2026-05-04T10:31:00Z"
    }
  ],
  "runbook_feedback": {
    "runbook_uri": "s3://atdr-runbooks/lateral-movement/internal-scan.md",
    "feedback": "NetworkPolicy 적용으로 스캔 트래픽 즉시 차단 확인. 추가 pod 격리는 승인 대기 중.",
    "outcome": "partial_success"
  },
  "timestamp": "2026-05-04T10:01:05Z"
}
```

### Strands Agent 코드 스켈레톤

```python
REMEDIATION_SYSTEM_PROMPT = """
당신은 Kubernetes 보안 인시던트 대응 실행 전문가입니다.
주어진 대응 액션 목록을 순서대로 실행하세요.

실행 전 반드시 확인하세요:
1. auto_executable이 true인 액션만 자동 실행
2. blast_radius가 high이거나 reversible이 false인 액션은 승인 후 실행
3. 각 액션 실행 후 결과를 검증

실행 결과를 JSON 형식으로 보고하세요.
"""

def handler(event, context):
    solution = json.loads(event["body"])
    executed = []
    pending = []

    for action in solution["recommended_actions"]:
        if requires_approval(action):
            approval_id = request_approval(action, solution["solution_id"])
            pending.append({**action, "status": "awaiting_approval", "approval_id": approval_id})
            continue

        # Strands Agent가 MCP tool을 통해 실행
        result = remediation_agent(
            f"다음 액션을 실행하세요:\n{json.dumps(action, ensure_ascii=False)}"
        )
        executed.append({**action, "status": "success", "result": result})

    # 런북 피드백 기록
    record_runbook_feedback(solution, executed)

    remediation_result = {
        "remediation_id": generate_id("rem"),
        "solution_id": solution["solution_id"],
        "executed_actions": executed,
        "pending_actions": pending,
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {"statusCode": 200, "body": json.dumps(remediation_result)}
```

---

## 6. Forensic Synthesis Agent

### 역할

Remediation Agent가 끝난 후 호출되어, 수집된 모든 증거(탐지 이벤트, Summary/Triage/Solution 출력, Remediation `execution_log`, S3 evidence URI 목록)를 읽고 분석 등급의 forensic 리포트를 생성한다. 이 에이전트는 MCP 도구를 호출하지 않으며, 새 K8s/AWS 리소스도 변경하지 않는다. 순수 분석·합성 단계다.

### 모델: Claude Sonnet 4.5

- 200K 입력 컨텍스트, 64K 출력 토큰.
- `invoke_model` (`BedrockClient.invoke`) 경로를 사용하고, 응답은 JSON 한 덩어리를 요구한다. tool-use 루프나 Converse API의 스트리밍은 쓰지 않는다. 단일 JSON 결과가 재현성과 파싱 단순성 측면에서 합성 단계에 더 적합하다.

### 입력 스키마

```json
{
  "summary": {"body": {...}},
  "triage": {"body": {...}},
  "solution": {"body": {...}},
  "remediation": {"body": {"execution_log": [...], "actions_taken": 6}}
}
```

`incident_id`는 `summary.body.incident_id`에서 추출하고, S3 evidence URI는 `execution_log` 안의 tool 결과에서 자동 추출한다.

### 출력 스키마 (JSON)

```json
{
  "executive_summary": "...",
  "timeline": [{"timestamp": "ISO-8601", "event": "...", "source": "...", "evidence_ref": "...", "confidence": "high|medium|low"}],
  "iocs": [{"type": "...", "value": "...", "source": "...", "confidence": "..."}],
  "ttps": [{"framework": "MITRE ATT&CK", "technique_id": "Txxxx", "name": "...", "evidence_refs": ["..."]}],
  "blast_radius": {"affected_namespaces": [...], "affected_pods": [...], "lateral_movement_observed": false, "privilege_escalation_observed": false},
  "root_cause_hypothesis": "...",
  "remediation_assessment": {"actions_attempted": [...], "actions_succeeded": [...], "actions_failed": [...], "residual_risk": "...", "residual_risk_reason": "..."},
  "hardening_recommendations": [{"priority": 1, "recommendation": "...", "rationale": "..."}],
  "open_questions": ["..."],
  "confidence_overall": "high|medium|low"
}
```

### Evidence Citation

에이전트는 모든 주장에 대해 다음 중 하나의 출처를 반드시 명시한다.

- `execution_log[<index>].<tool>`
- `evidence_uri:s3://...`
- `summary.<field>` / `triage.<field>` / `solution.<field>`

출처 없이 추측하지 않는다. 입력에 없는 정보는 만들어 내지 않는다. 파싱 실패나 Bedrock 호출 실패가 발생하면 fallback synthesis를 생성하고 원인을 `parse_error`에 기록한다 — 인시던트 파이프라인은 계속 진행한다.

### S3 저장 구조

```
s3://${FORENSICS_BUCKET}/incidents/{incident_id}/ai/{timestamp}/
├── synthesis-report.md
├── synthesis.json
├── timeline.json
├── iocs.json
└── ttps.json
```

### DynamoDB 기록

`atdr-incidents` 테이블에 다음 필드가 갱신된다:

- `forensic_synthesis_status`: `completed` 또는 `parse_error`
- `forensic_synthesis_uris`: 각 아티팩트 S3 URI 맵
- `forensic_synthesis_summary`: `executive_summary` 앞 500자
- `forensic_synthesis_error`: parse/invoke 실패 사유

### Step Functions 연결

`RemediationAgent` 상태 이후 `ForensicSynthesisAgent` 상태가 실행된다. Remediation이 예외를 던지더라도 Catch를 통해 동일한 `ForensicSynthesisAgent`로 이동한다. 이는 대응 실패 사고에서도 분석 리포트를 만드는 것을 목표로 한다.

---

## 7. Agent 간 통신 스키마

### 전체 메시지 흐름

각 Agent는 SQS 큐를 통해 다음 Agent로 메시지를 전달한다. 메시지 본문은 JSON이며, 각 단계의 출력이 다음 단계의 입력이 된다.

```
GuardDuty/Falco Event
        |
        | (raw JSON)
        v
  [summary-input-queue]
        |
  Summary Agent
        |
        | (SummaryOutput)
        v
  [triage-input-queue]
        |
  Triage Agent
        |
        | (TriageOutput)
        v
  [solution-input-queue]
        |
  Solution Agent
        |
        | (SolutionOutput)
        v
[remediation-input-queue]
        |
  Remediation Agent
        |
        v
  [results-table] (DynamoDB)
```

### JSON 스키마 정의

각 Agent의 입출력 스키마는 Python TypedDict로 정의한다.

```python
from typing import TypedDict, Literal, Optional

class AffectedResource(TypedDict):
    type: str                    # "EC2 Instance", "Pod", "Node" 등
    id: str                      # 리소스 ID
    namespace: Optional[str]     # Kubernetes namespace
    pod_name: Optional[str]      # pod 이름

class SummaryOutput(TypedDict):
    summary_id: str
    source: Literal["guardduty", "falco", "cloudtrail"]
    threat_type: str
    severity_raw: float
    affected_resource: AffectedResource
    key_evidence: list[str]
    human_summary: str
    timestamp: str
    raw_event_ref: str

class TriageOutput(TypedDict):
    triage_id: str
    summary_id: str
    priority: Literal["P1", "P2", "P3", "P4"]
    priority_reason: str
    requires_action: bool
    is_duplicate: bool
    escalation_triggered: bool
    fast_path: bool              # True면 Solution Agent 건너뜀
    recommended_next: Literal["solution_agent", "remediation_agent", "discard"]
    timestamp: str

class RecommendedAction(TypedDict):
    rank: int
    action_type: str
    description: str
    auto_executable: bool
    blast_radius: Literal["low", "medium", "high"]
    reversible: bool
    estimated_impact: str

class MatchedRunbook(TypedDict):
    title: str
    s3_uri: str
    relevance_score: float

class SolutionOutput(TypedDict):
    solution_id: str
    triage_id: str
    root_cause_analysis: str
    runbook_matched: bool
    matched_runbooks: list[MatchedRunbook]
    recommended_actions: list[RecommendedAction]
    timestamp: str

class ExecutedAction(TypedDict):
    rank: int
    action_type: str
    status: Literal["success", "failed", "skipped"]
    executed_at: str
    approval_required: bool
    result: dict

class PendingAction(TypedDict):
    rank: int
    action_type: str
    status: Literal["awaiting_approval", "rejected"]
    approval_id: str
    approval_expires_at: str

class RunbookFeedback(TypedDict):
    runbook_uri: str
    feedback: str
    outcome: Literal["success", "partial_success", "failed"]

class RemediationOutput(TypedDict):
    remediation_id: str
    solution_id: str
    executed_actions: list[ExecutedAction]
    pending_actions: list[PendingAction]
    runbook_feedback: RunbookFeedback
    timestamp: str
```

### 에러 핸들링

Agent가 실패하면 SQS의 Dead Letter Queue(DLQ)로 메시지가 이동한다. DLQ에 메시지가 쌓이면 CloudWatch 알람이 발생하고 운영자에게 알림이 간다.

```python
# SQS 큐 설정 (Terraform)
# maxReceiveCount: 3 (3회 실패 후 DLQ로 이동)
# visibilityTimeout: Agent 타임아웃 + 30s 여유

class AgentError(Exception):
    """Agent 처리 실패 시 발생하는 예외."""
    def __init__(self, agent_name: str, reason: str, input_data: dict):
        self.agent_name = agent_name
        self.reason = reason
        self.input_data = input_data
        super().__init__(f"{agent_name} failed: {reason}")

def safe_agent_handler(handler_fn):
    """Agent Lambda handler를 감싸는 에러 핸들링 데코레이터."""
    def wrapper(event, context):
        try:
            return handler_fn(event, context)
        except Exception as e:
            # CloudWatch에 에러 메트릭 기록
            cloudwatch = boto3.client("cloudwatch")
            cloudwatch.put_metric_data(
                Namespace="ATDR/AgentErrors",
                MetricData=[{
                    "MetricName": "AgentFailure",
                    "Dimensions": [{"Name": "AgentName", "Value": context.function_name}],
                    "Value": 1,
                    "Unit": "Count",
                }],
            )
            # 예외를 다시 던져 SQS가 재시도하게 함
            raise
    return wrapper
```

---

## 8. Bedrock 모델 설정

### Claude Haiku 4.5 (Summary Agent, Triage Agent)

```python
HAIKU_CONFIG = {
    "model_id": "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "temperature": 0.0,      # 결정론적 출력 (분류/요약 작업)
    "max_tokens": 1024,      # 요약 출력에 충분한 크기
    "top_p": 1.0,
    "stop_sequences": [],
}
```

Haiku 4.5 사용 기준:
- 구조화된 JSON 출력 생성
- 빠른 응답이 필요한 작업 (목표 레이턴시 < 5s)
- 반복적으로 호출되는 고빈도 작업

### Claude Sonnet 4.6 (Solution Agent, Remediation Agent)

```python
SONNET_CONFIG = {
    "model_id": "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "temperature": 0.1,      # 약간의 다양성 허용 (추론 작업)
    "max_tokens": 2048,      # 긴 분석 결과 수용
    "top_p": 0.9,
    "stop_sequences": [],
}
```

Sonnet 4.6 사용 기준:
- 긴 컨텍스트(런북 + 이벤트 데이터) 처리
- 복잡한 인과관계 추론
- 다단계 대응 계획 수립

### 비용 추정 (데모/테스트 기준)

아래 수치는 데모 환경에서 하루 100건의 보안 이벤트를 처리하는 기준이다.

| Agent | 모델 | 평균 입력 토큰 | 평균 출력 토큰 | 일 100건 비용 |
|---|---|---|---|---|
| Summary Agent | Haiku 4.5 | 800 | 300 | ~$0.04 |
| Triage Agent | Haiku 4.5 | 500 | 200 | ~$0.02 |
| Solution Agent | Sonnet 4.6 | 3,000 | 800 | ~$1.20 |
| Remediation Agent | Sonnet 4.6 | 2,000 | 600 | ~$0.80 |
| **합계** | | | | **~$2.06/일** |

실제 프로덕션 환경에서는 이벤트 볼륨과 평균 토큰 수에 따라 달라진다. Triage Agent의 중복 필터링이 효과적으로 작동하면 Solution Agent와 Remediation Agent 호출 횟수가 줄어 비용이 크게 낮아진다.

---

## 9. Knowledge Base 설계

### OpenSearch Serverless 인덱스 구조

Bedrock Knowledge Base는 OpenSearch Serverless를 벡터 스토어로 사용한다. 인덱스 구조는 다음과 같다.

```json
{
  "settings": {
    "index": {
      "knn": true,
      "knn.algo_param.ef_search": 512
    }
  },
  "mappings": {
    "properties": {
      "bedrock-knowledge-base-default-vector": {
        "type": "knn_vector",
        "dimension": 1024,
        "method": {
          "name": "hnsw",
          "space_type": "cosine",
          "engine": "faiss"
        }
      },
      "AMAZON_BEDROCK_TEXT_CHUNK": {
        "type": "text",
        "index": true
      },
      "AMAZON_BEDROCK_METADATA": {
        "type": "text",
        "index": false
      },
      "threat_type": {
        "type": "keyword"
      },
      "severity": {
        "type": "keyword"
      },
      "runbook_version": {
        "type": "keyword"
      },
      "last_updated": {
        "type": "date"
      }
    }
  }
}
```

### S3 런북 저장소 구조

```
s3://atdr-runbooks/
├── lateral-movement/
│   ├── internal-scan.md
│   ├── namespace-traversal.md
│   └── service-account-abuse.md
├── data-exfiltration/
│   ├── large-egress.md
│   ├── dns-tunneling.md
│   └── s3-exfiltration.md
├── privilege-escalation/
│   ├── container-escape.md
│   ├── rbac-abuse.md
│   └── host-path-mount.md
├── crypto-mining/
│   ├── cpu-spike.md
│   └── known-mining-pools.md
├── brute-force/
│   ├── ssh-brute-force.md
│   └── api-server-brute-force.md
└── metadata/
    └── runbook-index.json   # 런북 목록 및 메타데이터
```

각 런북 파일은 다음 구조를 따른다.

```markdown
---
title: Internal Network Scan Response
threat_type: lateral-movement
severity: P2
version: 1.2
last_updated: 2026-05-01
---

## 위협 설명

## 탐지 지표 (IoC)

## 즉각 대응 절차

## 근본 원인 분석 방법

## 대응 액션 (우선순위 순)

## 검증 방법

## 롤백 절차

## 사후 조치
```

### 임베딩 모델: Titan Embeddings V2

```python
EMBEDDING_CONFIG = {
    "model_id": "amazon.titan-embed-text-v2:0",
    "dimensions": 1024,
    "normalize": True,
}
```

Titan Embeddings V2는 1024차원 벡터를 생성하며, 영어와 한국어 혼합 텍스트에서 안정적인 성능을 보인다. 런북이 한국어와 영어 기술 용어를 혼용하는 이 프로젝트의 특성에 적합하다.

### 인덱싱 파이프라인

런북이 S3에 업로드되면 Bedrock Knowledge Base가 자동으로 인덱싱을 트리거한다. 수동 재인덱싱이 필요한 경우 다음 API를 호출한다.

```python
def trigger_kb_sync(kb_id: str, data_source_id: str) -> str:
    """Knowledge Base 동기화를 트리거하고 ingestion job ID를 반환한다."""
    bedrock_agent = boto3.client("bedrock-agent", region_name="us-east-1")

    response = bedrock_agent.start_ingestion_job(
        knowledgeBaseId=kb_id,
        dataSourceId=data_source_id,
        description=f"Manual sync triggered at {datetime.utcnow().isoformat()}",
    )
    return response["ingestionJob"]["ingestionJobId"]

def check_sync_status(kb_id: str, data_source_id: str, job_id: str) -> dict:
    """인덱싱 작업 상태를 확인한다."""
    bedrock_agent = boto3.client("bedrock-agent", region_name="us-east-1")

    response = bedrock_agent.get_ingestion_job(
        knowledgeBaseId=kb_id,
        dataSourceId=data_source_id,
        ingestionJobId=job_id,
    )
    return {
        "status": response["ingestionJob"]["status"],
        "statistics": response["ingestionJob"].get("statistics", {}),
    }
```

Remediation Agent가 런북 피드백을 S3에 기록하면 EventBridge 규칙이 이를 감지하고 자동으로 재인덱싱을 트리거한다. 이 루프를 통해 Knowledge Base는 실제 인시던트 대응 경험을 점진적으로 축적한다.

---

*문서 버전: 0.1 | 최종 수정: 2026-05-04*
