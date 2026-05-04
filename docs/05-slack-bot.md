# 05. Slack 봇 설계

## 1. 아키텍처

### 전체 구조

```
Slack
  │
  │  HTTP (Events API / Slash Commands / Interactive Components)
  ▼
API Gateway (REST API)
  │
  ├─ /slack/events      → Lambda: event-handler
  ├─ /slack/actions     → Lambda: action-handler
  └─ /slack/commands    → Lambda: command-handler
          │
          │  내부 호출
          ├─ DynamoDB (인시던트 상태, 승인 요청)
          ├─ S3 (런북, 인시던트 히스토리)
          └─ Remediation Agent (승인 후 실행 트리거)
```

ATDR의 Slack 봇은 Slack Bolt SDK(Python)로 구현하고 AWS Lambda 위에서 실행한다.

### Socket Mode vs HTTP Mode

Lambda 환경에서는 HTTP Mode를 사용한다. Socket Mode는 장기 실행 WebSocket 연결이 필요한데, Lambda는 요청당 실행 모델이라 WebSocket을 유지할 수 없다. HTTP Mode는 Slack이 이벤트 발생 시 API Gateway 엔드포인트로 POST 요청을 보내는 방식이라 Lambda와 자연스럽게 맞는다.

```python
from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler

app = App(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"],
    process_before_response=True,   # Lambda에서 3초 ack 제약 대응
)

def lambda_handler(event, context):
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)
```

### OAuth Scopes

| Scope | 용도 |
|-------|------|
| `chat:write` | 메시지 전송 |
| `chat:write.public` | 봇이 참여하지 않은 채널에 메시지 전송 |
| `channels:read` | 채널 목록 조회 |
| `commands` | Slash Command 수신 |
| `reactions:write` | 메시지에 이모지 반응 추가 |
| `users:read` | 승인자 정보 조회 |
| `im:write` | DM 전송 (에스컬레이션용) |

---

## 2. 알림 기능

### Block Kit 메시지 포맷

심각도별로 색상 코딩된 attachment를 사용한다. Block Kit의 `color` 필드는 메시지 왼쪽 세로선 색상을 결정한다.

| 심각도 | 색상 | 코드 |
|--------|------|------|
| P1 Critical | 빨강 | `#FF0000` |
| P2 High | 주황 | `#FF6600` |
| P3 Medium | 노랑 | `#FFCC00` |
| P4 Low | 파랑 | `#0066CC` |
| 해결됨 | 초록 | `#00AA44` |

### 스레드 기반 알림 그룹핑

인시던트 최초 알림은 채널에 새 메시지로 전송한다. 이후 같은 인시던트의 상태 업데이트(트리아지 시작, 대응 실행, 해결)는 모두 해당 메시지의 스레드에 달린다. 이렇게 하면 채널 노이즈를 줄이면서 인시던트 타임라인을 한 스레드에서 추적할 수 있다.

```python
# 최초 알림 전송 후 ts 저장
response = app.client.chat_postMessage(
    channel=channel_id,
    blocks=build_incident_blocks(incident),
    attachments=[{"color": severity_color, "fallback": incident["title"]}],
)
incident_ts = response["ts"]

# DynamoDB에 ts 저장
save_incident_slack_ts(incident_id, channel_id, incident_ts)

# 이후 업데이트는 스레드로
app.client.chat_postMessage(
    channel=channel_id,
    thread_ts=incident_ts,
    text=f"대응 시작: {action_description}",
)
```

### 채널 라우팅 전략

| 채널 | 대상 |
|------|------|
| `#incidents` | P1/P2 인시던트 알림, 승인 요청 |
| `#ops-alerts` | P3/P4 알림, 자동 실행 결과 |
| `#ops` | 일일 요약, 런북 업데이트 알림 |

채널 라우팅은 `notification-config.yaml`에서 관리한다. 인시던트 심각도와 태그(namespace, threat_type)를 기준으로 라우팅 규칙을 정의할 수 있다.

```yaml
routing_rules:
  - condition:
      severity: ["P1", "P2"]
    channels: ["#incidents"]
    mention: ["@oncall"]
  - condition:
      severity: ["P3", "P4"]
    channels: ["#ops-alerts"]
  - condition:
      threat_type: "crypto_mining"
    channels: ["#incidents", "#ops-alerts"]
```

### Rate Limiting과 중복 제거

같은 인시던트에서 짧은 시간 안에 여러 이벤트가 발생하면 알림이 폭주할 수 있다. 두 가지 방법으로 제어한다.

**중복 제거**: 인시던트 ID를 키로 DynamoDB에 알림 전송 여부를 기록한다. 같은 인시던트 ID로 이미 알림이 전송됐으면 스레드 업데이트만 한다.

**Rate limiting**: 채널당 분당 최대 알림 수를 설정한다. 초과 시 알림을 큐에 쌓고 다음 분에 배치로 전송한다.

```python
RATE_LIMIT_PER_CHANNEL_PER_MINUTE = 10

def should_send_notification(channel_id: str) -> bool:
    key = f"rate_limit:{channel_id}:{int(time.time() // 60)}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, 60)
    return count <= RATE_LIMIT_PER_CHANNEL_PER_MINUTE
```

---

## 3. 승인 워크플로우

### 버튼 기반 Approve/Deny

승인 요청 메시지에는 Approve와 Deny 버튼이 포함된다. 버튼 클릭 시 Slack이 `/slack/actions` 엔드포인트로 interactive payload를 전송한다.

```python
@app.action("approve_action")
def handle_approve(ack, body, client):
    ack()   # 3초 안에 반드시 호출
    
    action_payload = body["actions"][0]["value"]
    user_id = body["user"]["id"]
    
    # 비동기로 실제 처리
    process_approval.delay(action_payload, user_id, approved=True)
    
    # 버튼 비활성화 (중복 클릭 방지)
    client.chat_update(
        channel=body["channel"]["id"],
        ts=body["message"]["ts"],
        blocks=build_approved_blocks(action_payload, user_id),
    )
```

### 서명된 액션 페이로드 (HMAC)

버튼의 `value` 필드에 담기는 페이로드는 HMAC-SHA256으로 서명한다. 이렇게 하면 페이로드 위변조를 탐지할 수 있고, 승인 요청이 실제로 ATDR에서 발행된 것인지 검증할 수 있다.

```python
import hmac
import hashlib
import json
import base64

def sign_action_payload(payload: dict, secret: str) -> str:
    payload_json = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        secret.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    
    signed = {
        "payload": payload,
        "sig": signature,
    }
    return base64.b64encode(json.dumps(signed).encode()).decode()

def verify_action_payload(signed_value: str, secret: str) -> dict:
    signed = json.loads(base64.b64decode(signed_value).decode())
    payload_json = json.dumps(signed["payload"], sort_keys=True)
    
    expected_sig = hmac.new(
        secret.encode(),
        payload_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    
    if not hmac.compare_digest(signed["sig"], expected_sig):
        raise ValueError("페이로드 서명 검증 실패")
    
    return signed["payload"]
```

### 3초 ack() 제약과 비동기 처리

Slack은 interactive payload를 전송한 후 3초 안에 HTTP 200 응답을 받지 못하면 타임아웃 오류를 표시한다. Lambda 실행 시간이 3초를 넘을 수 있으므로 `ack()`를 즉시 호출하고 실제 처리는 비동기로 분리한다.

```python
@app.action("approve_action")
def handle_approve(ack, body):
    ack()   # 즉시 응답 (Slack 3초 제약)
    
    # SQS로 작업 위임
    sqs.send_message(
        QueueUrl=APPROVAL_QUEUE_URL,
        MessageBody=json.dumps({
            "type": "approval",
            "body": body,
            "approved": True,
        }),
    )
```

별도 Lambda가 SQS 메시지를 소비해 실제 대응 실행과 Slack 메시지 업데이트를 처리한다.

### 승인 감사 로그

모든 승인/거부 이벤트는 DynamoDB에 기록하고 CloudWatch Logs로도 전송한다.

```python
def log_approval_event(
    approval_id: str,
    action: str,
    approved: bool,
    user_id: str,
    user_name: str,
):
    dynamodb.put_item(
        TableName="atdr-approval-audit",
        Item={
            "approval_id": {"S": approval_id},
            "action": {"S": action},
            "decision": {"S": "approved" if approved else "denied"},
            "decided_by_id": {"S": user_id},
            "decided_by_name": {"S": user_name},
            "decided_at": {"S": datetime.utcnow().isoformat()},
            "ttl": {"N": str(int(time.time()) + 90 * 24 * 3600)},  # 90일 보관
        },
    )
    
    logger.info(
        "approval_decision",
        extra={
            "approval_id": approval_id,
            "action": action,
            "decision": "approved" if approved else "denied",
            "user": user_name,
        },
    )
```

---

## 4. 대화형 조회

### /status 명령: 클러스터 상태 조회

```
/status [namespace]
```

현재 활성 인시던트 수, 격리된 파드 목록, 적용 중인 ATDR 관리 NetworkPolicy 목록을 반환한다.

```python
@app.command("/status")
def handle_status(ack, command, respond):
    ack()
    
    namespace = command["text"].strip() or "all"
    
    # EKS MCP를 통해 상태 조회
    status = get_cluster_status(namespace)
    
    respond(
        blocks=build_status_blocks(status),
        response_type="ephemeral",   # 명령 실행자에게만 표시
    )
```

응답 예시:

```
클러스터 상태 (2026-05-04 10:30 KST)

활성 인시던트: 2건 (P1: 1, P2: 1)
격리된 파드: payment-service-7d9f8b-xk2p9 (production)
적용 중인 격리 정책: 3개
마지막 자동 대응: 8분 전 (NetworkPolicy 적용)
```

### /incident 명령: 인시던트 히스토리 검색

```
/incident [incident-id | threat-type | namespace]
```

S3에 저장된 인시던트 히스토리를 검색해 요약을 반환한다.

```python
@app.command("/incident")
def handle_incident(ack, command, respond):
    ack()
    
    query = command["text"].strip()
    incidents = search_incidents(query, limit=5)
    
    if not incidents:
        respond(text=f"`{query}`에 해당하는 인시던트가 없습니다.")
        return
    
    respond(
        blocks=build_incident_list_blocks(incidents),
        response_type="ephemeral",
    )
```

### /pod 명령: 특정 파드 상세 정보

```
/pod <namespace>/<pod-name>
```

파드의 현재 상태, 적용된 NetworkPolicy, 최근 이벤트, 관련 인시던트를 한 번에 조회한다.

```python
@app.command("/pod")
def handle_pod(ack, command, respond):
    ack()
    
    text = command["text"].strip()
    if "/" not in text:
        respond(text="사용법: `/pod <namespace>/<pod-name>`")
        return
    
    namespace, pod_name = text.split("/", 1)
    pod_info = get_pod_details(namespace, pod_name)
    
    respond(
        blocks=build_pod_detail_blocks(pod_info),
        response_type="ephemeral",
    )
```

---

## 5. 인시던트 라이프사이클

### 탐지에서 종료까지

```
탐지
 │  ai-detector가 이상 행동 탐지
 │  correlator가 인시던트로 묶음
 ▼
알림
 │  #incidents 채널에 Block Kit 메시지 전송
 │  DynamoDB에 slack_ts 저장
 ▼
트리아지
 │  운영자가 메시지 확인
 │  스레드에 "트리아지 시작" 업데이트
 ▼
대응
 │  P1/P2: 승인 버튼 클릭
 │  P3/P4: 자동 실행
 │  스레드에 실행 결과 업데이트
 ▼
종료
 │  운영자가 /incident resolve <id> 실행
 │  또는 자동 검증 통과 시 자동 종료
 │  메시지 색상 초록으로 업데이트
 ▼
피드백
   S3 런북 업데이트
   일일 요약에 포함
```

### 스레드 업데이트 패턴

인시던트 상태가 바뀔 때마다 원본 메시지 스레드에 업데이트를 추가한다. 원본 메시지 자체는 `chat_update`로 색상과 상태 텍스트만 변경한다.

```python
def update_incident_status(
    incident_id: str,
    new_status: str,
    update_text: str,
):
    # DynamoDB에서 slack_ts 조회
    slack_info = get_incident_slack_info(incident_id)
    
    # 스레드에 업데이트 추가
    app.client.chat_postMessage(
        channel=slack_info["channel_id"],
        thread_ts=slack_info["message_ts"],
        text=update_text,
    )
    
    # 원본 메시지 상태 업데이트
    app.client.chat_update(
        channel=slack_info["channel_id"],
        ts=slack_info["message_ts"],
        blocks=build_incident_blocks(
            get_incident(incident_id),
            status=new_status,
        ),
        attachments=[{
            "color": STATUS_COLORS[new_status],
            "fallback": f"인시던트 {new_status}",
        }],
    )
```

---

## 6. Block Kit JSON 예시

### 보안 알림 메시지 (P1 Critical)

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "보안 인시던트 탐지"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*인시던트 ID*\ninc-20260504-001"
        },
        {
          "type": "mrkdwn",
          "text": "*심각도*\nP1 Critical"
        },
        {
          "type": "mrkdwn",
          "text": "*위협 유형*\n비정상 아웃바운드 트래픽"
        },
        {
          "type": "mrkdwn",
          "text": "*탐지 시각*\n2026-05-04 10:00:00 KST"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*영향 파드*\n`payment-service-7d9f8b-xk2p9`"
        },
        {
          "type": "mrkdwn",
          "text": "*네임스페이스*\n`production`"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*AI 분석 요약*\n`payment-service` 파드에서 알 수 없는 외부 IP(203.0.113.42)로 반복적인 아웃바운드 연결이 탐지됐습니다. 연결 패턴이 C2 비콘 행동과 유사합니다. 신뢰도: 87%"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*권장 대응 액션*\n1. NetworkPolicy로 파드 격리 (즉시)\n2. 파드 삭제 후 재시작 (격리 후)\n3. 외부 IP 차단 규칙 추가"
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": {
            "type": "plain_text",
            "text": "승인 (격리 실행)"
          },
          "style": "danger",
          "action_id": "approve_action",
          "value": "eyJwYXlsb2FkIjp7ImFwcHJvdmFsX2lkIjoiYXBwci0yMDI2MDUwNC0wMDEifSwic2lnIjoiYWJjMTIzIn0="
        },
        {
          "type": "button",
          "text": {
            "type": "plain_text",
            "text": "거부"
          },
          "action_id": "deny_action",
          "value": "eyJwYXlsb2FkIjp7ImFwcHJvdmFsX2lkIjoiYXBwci0yMDI2MDUwNC0wMDEifSwic2lnIjoiYWJjMTIzIn0="
        },
        {
          "type": "button",
          "text": {
            "type": "plain_text",
            "text": "상세 보기"
          },
          "action_id": "view_details",
          "value": "inc-20260504-001"
        }
      ]
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": "승인하지 않으면 5분 후 자동으로 최소 격리 액션이 실행됩니다."
        }
      ]
    }
  ],
  "attachments": [
    {
      "color": "#FF0000",
      "fallback": "[P1 Critical] 비정상 아웃바운드 트래픽 - payment-service"
    }
  ]
}
```

### 대응 완료 메시지 (스레드 업데이트)

```json
{
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*대응 완료*\n`payment-service` 파드에 NetworkPolicy 격리 정책이 적용됐습니다."
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*실행 시각*\n2026-05-04 10:02:15 KST"
        },
        {
          "type": "mrkdwn",
          "text": "*승인자*\n@juany"
        },
        {
          "type": "mrkdwn",
          "text": "*소요 시간*\n8초"
        },
        {
          "type": "mrkdwn",
          "text": "*검증 결과*\n통과 (아웃바운드 트래픽 차단 확인)"
        }
      ]
    }
  ]
}
```

### /status 응답 메시지

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "클러스터 상태"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*활성 인시던트*\n2건 (P1: 1, P2: 1)"
        },
        {
          "type": "mrkdwn",
          "text": "*격리된 파드*\n1개"
        },
        {
          "type": "mrkdwn",
          "text": "*적용 중인 격리 정책*\n3개"
        },
        {
          "type": "mrkdwn",
          "text": "*마지막 자동 대응*\n8분 전"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*격리된 파드 목록*\n• `payment-service-7d9f8b-xk2p9` (production) — NetworkPolicy 격리 중"
      }
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": "2026-05-04 10:30:00 KST 기준"
        }
      ]
    }
  ]
}
```
