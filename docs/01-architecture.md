# ATDR 시스템 아키텍처

> ATDR — AI 기반 EKS 위협 탐지 및 대응 시스템  
> 문서 버전: 0.1 | 작성일: 2026-05-04 | 대상 독자: 개발팀 (4인)

---

## 목차

1. [시스템 전체 구조](#1-시스템-전체-구조)
2. [데이터 수집 레이어](#2-데이터-수집-레이어)
3. [이벤트 라우팅 레이어](#3-이벤트-라우팅-레이어)
4. [AI 분석 레이어](#4-ai-분석-레이어)
5. [대응 실행 레이어](#5-대응-실행-레이어)
6. [관측/포렌식 레이어](#6-관측포렌식-레이어)
7. [보안 레이어](#7-보안-레이어)
8. [네트워크 아키텍처](#8-네트워크-아키텍처)

---

## 1. 시스템 전체 구조

ATDR(AI Threat Detection and Response)은 5개 레이어로 구성된다. 각 레이어는 독립적으로 교체 가능하도록 설계했으며, 레이어 간 인터페이스는 이벤트 스키마로 고정한다.

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATDR 시스템 전체 구조                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [레이어 1] 데이터 수집                                           │
│  CloudTrail │ DNS Logs │ VPC Flow Logs │ EKS Audit              │
│  GuardDuty Runtime Agent (eBPF) │ Falco DaemonSet │ Tetragon   │
│                        │                                        │
│                        ▼                                        │
│  [레이어 2] 이벤트 라우팅                                         │
│  EventBridge │ SNS │ SQS │ DLQ                                  │
│                        │                                        │
│                        ▼                                        │
│  [레이어 3] AI 분석                                              │
│  Lambda + Strands Agent SDK                                     │
│  Summary Agent → Triage Agent → Solution Agent → Remediation   │
│  Bedrock Knowledge Base (OpenSearch Serverless + S3)            │
│                        │                                        │
│                        ▼                                        │
│  [레이어 4] 대응 실행                                             │
│  EKS MCP │ NetworkPolicy │ Pod 격리 │ RBAC │ Slack 승인          │
│                        │                                        │
│                        ▼                                        │
│  [레이어 5] 관측/포렌식                                           │
│  Prometheus │ Grafana │ Loki │ Hubble │ S3 Object Lock          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 레이어별 AWS 서비스 및 오픈소스 도구 매핑

| 레이어 | AWS 서비스 | 오픈소스 도구 |
|--------|-----------|-------------|
| 데이터 수집 | CloudTrail, VPC Flow Logs, GuardDuty, EKS Audit | Falco, Tetragon (Cilium), Falcosidekick |
| 이벤트 라우팅 | EventBridge, SNS, SQS, Lambda | — |
| AI 분석 | Lambda, Bedrock (Claude), OpenSearch Serverless, S3 | Strands Agent SDK |
| 대응 실행 | EKS, IAM, Secrets Manager | EKS MCP, kubectl |
| 관측/포렌식 | CloudWatch, S3 Object Lock, CloudTrail Lake | Prometheus, Grafana, Loki, Hubble |


---

## 2. 데이터 수집 레이어

EKS 환경에서 보안 이벤트는 클라우드, 쿠버네티스, 런타임, 네트워크 4개 평면에서 발생한다. 각 소스는 서로 다른 포맷과 전달 경로를 가지므로, 수집 단계에서 소스별 특성을 이해하는 것이 중요하다.

```
┌──────────────────────────────────────────────────────────────┐
│                    데이터 수집 레이어                           │
│                                                              │
│  클라우드 평면                                                 │
│  ┌─────────────────┐    ┌──────────────────────────────┐    │
│  │  AWS CloudTrail  │───▶│       EventBridge            │    │
│  │  (API 호출 감사)  │    │  (Rule: GuardDuty Finding,   │    │
│  └─────────────────┘    │   CloudTrail Insight)         │    │
│  ┌─────────────────┐    └──────────────────────────────┘    │
│  │   DNS Logs       │───▶│       EventBridge            │    │
│  │  (Route53 쿼리)  │    └──────────────────────────────┘    │
│  └─────────────────┘                                        │
│                                                              │
│  네트워크/쿠버네티스 평면                                        │
│  ┌─────────────────┐    ┌──────────────────────────────┐    │
│  │  VPC Flow Logs   │───▶│         GuardDuty            │    │
│  │  EKS Audit Logs  │───▶│  (Finding → EventBridge)     │    │
│  │  GuardDuty       │    └──────────────────────────────┘    │
│  │  Runtime Agent   │                                        │
│  │  (eBPF, 노드별)  │                                        │
│  └─────────────────┘                                        │
│                                                              │
│  런타임 평면 (클러스터 내부)                                     │
│  ┌─────────────────┐    ┌──────────────────────────────┐    │
│  │  Falco DaemonSet │───▶│      Falcosidekick           │───▶│
│  │  (eBPF 기반)     │    │  (SNS/SQS 전달)              │    │
│  └─────────────────┘    └──────────────────────────────┘    │
│  ┌─────────────────┐                                        │
│  │    Tetragon      │───▶│  커널 이벤트 직접 차단 가능      │    │
│  │  (Cilium, eBPF)  │    │  (enforce 모드)               │    │
│  └─────────────────┘                                        │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 CloudTrail → EventBridge

CloudTrail은 AWS API 호출 전체를 기록한다. ATDR에서는 다음 이벤트 유형을 EventBridge Rule로 필터링한다.

- `ConsoleLogin` — 루트 계정 또는 MFA 없는 로그인
- `CreateUser`, `AttachUserPolicy` — IAM 권한 변경
- `RunInstances`, `CreateCluster` — 인프라 변경
- `GetSecretValue`, `Decrypt` — 시크릿/KMS 접근

EventBridge Rule 예시:

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["ConsoleLogin", "CreateUser", "AttachUserPolicy",
                  "GetSecretValue", "Decrypt", "RunInstances"],
    "errorCode": [{ "exists": false }]
  }
}
```

### 2.2 DNS Logs → EventBridge

Route 53 Resolver Query Logs를 CloudWatch Logs로 전달한 뒤, CloudWatch Logs → EventBridge 구독으로 라우팅한다. 탐지 대상:

- 알려진 C2(Command & Control) 도메인 쿼리
- 비정상적으로 긴 서브도메인 (DNS 터널링 패턴)
- 짧은 TTL + 높은 쿼리 빈도 (DGA 패턴)

### 2.3 VPC Flow Logs → GuardDuty

VPC Flow Logs는 GuardDuty가 직접 소비한다. GuardDuty는 Flow Logs를 분석해 다음 Finding 유형을 생성한다.

- `UnauthorizedAccess:EC2/MaliciousIPCaller`
- `Recon:EC2/PortProbeUnprotectedPort`
- `CryptoCurrency:EC2/BitcoinTool.B`

GuardDuty Finding은 자동으로 EventBridge에 전달된다 (`aws.guardduty` 소스).

### 2.4 EKS Audit Logs → GuardDuty

EKS Control Plane Audit Logging을 활성화하면 GuardDuty가 쿠버네티스 API 서버 감사 로그를 분석한다. 주요 Finding:

- `Kubernetes:Backdoor/RuntimeExecution` — 컨테이너 내 셸 실행
- `Kubernetes:PrivilegeEscalation/PrivilegedContainer` — 권한 상승
- `Kubernetes:Discovery/SuccessfulAnonymousAccess` — 익명 API 접근
- `Kubernetes:Impact/MaliciousIPCaller` — 알려진 악성 IP와 통신

### 2.5 GuardDuty Runtime Agent (eBPF)

EKS 노드에 GuardDuty Runtime Agent를 DaemonSet으로 배포한다. eBPF 프로브를 통해 커널 레벨 시스템 콜을 모니터링하며, 컨테이너 탈출 시도, 루트킷 설치, 비정상 프로세스 실행 등을 탐지한다.

```
노드 커널
  └── eBPF 프로브 (GuardDuty Runtime Agent)
        └── 시스템 콜 인터셉트
              ├── execve (프로세스 실행)
              ├── connect (네트워크 연결)
              ├── open (파일 접근)
              └── ptrace (프로세스 추적)
```

Finding 예시: `Runtime:Execution/NewBinaryExecuted`, `Runtime:Execution/ReverseShell`

### 2.6 Falco DaemonSet (eBPF) → Falcosidekick

Falco는 GuardDuty Runtime Agent와 독립적으로 동작하는 오픈소스 런타임 보안 도구다. 커스텀 룰을 작성할 수 있어 GuardDuty가 커버하지 못하는 애플리케이션 레벨 이상 행동을 탐지하는 데 유용하다.

Falco 룰 예시:

```yaml
- rule: Unexpected outbound connection from app pod
  desc: app 네임스페이스 Pod가 허용되지 않은 외부 IP로 연결 시도
  condition: >
    outbound and
    k8s.ns.name = "app" and
    not fd.sip in (allowed_outbound_ips)
  output: >
    Unexpected outbound from %k8s.pod.name
    (ip=%fd.sip port=%fd.sport)
  priority: WARNING
  tags: [network, lateral_movement]
```

Falcosidekick은 Falco 이벤트를 SNS로 전달한다. SNS → SQS → Lambda 경로로 ATDR AI 분석 레이어에 도달한다.

### 2.7 Tetragon (Cilium) — 커널 레벨 이벤트 수집 + 차단

Tetragon은 Cilium의 eBPF 기반 런타임 보안 컴포넌트다. Falco와 달리 **인라인 차단(enforce mode)**이 가능하다. 커널 함수 레벨에서 정책을 적용하므로 컨테이너 런타임 우회 공격에도 효과적이다.

TracingPolicy 예시 (특정 바이너리 실행 차단):

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-crypto-miner
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/xmrig"
        - "/minerd"
      matchActions:
      - action: Sigkill
```

Tetragon 이벤트는 JSON 형식으로 stdout에 출력되며, Loki로 수집해 Grafana에서 시각화한다.


---

## 3. 이벤트 라우팅 레이어

수집된 이벤트는 두 경로로 AI 분석 레이어에 도달한다. GuardDuty/CloudTrail 계열은 EventBridge를 거치고, Falco 계열은 SNS → SQS를 거친다.

```
┌──────────────────────────────────────────────────────────────────┐
│                     이벤트 라우팅 레이어                            │
│                                                                  │
│  경로 A: GuardDuty / CloudTrail                                   │
│                                                                  │
│  GuardDuty Finding ──▶ EventBridge ──▶ Lambda (Strands Agent)   │
│  CloudTrail Event  ──▶ EventBridge ──▶ Lambda (Strands Agent)   │
│  DNS Log Event     ──▶ EventBridge ──▶ Lambda (Strands Agent)   │
│                                                                  │
│  경로 B: Falco                                                    │
│                                                                  │
│  Falco Alert ──▶ Falcosidekick ──▶ SNS ──▶ SQS ──▶ Lambda      │
│                                              │                   │
│                                              ▼                   │
│                                           DLQ (실패 이벤트)       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.1 GuardDuty Finding → EventBridge → Lambda

GuardDuty Finding은 자동으로 EventBridge default event bus에 게시된다. EventBridge Rule로 심각도 4.0 이상 Finding만 필터링해 Lambda를 트리거한다.

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{ "numeric": [">=", 4.0] }]
  }
}
```

Lambda는 EventBridge 이벤트를 받아 내부 정규화 스키마로 변환한 뒤 Strands Agent 파이프라인을 시작한다.

### 3.2 Falcosidekick → SNS → SQS → Lambda

Falco 이벤트는 Falcosidekick을 통해 SNS 토픽으로 전달된다. SNS는 SQS 큐를 구독하며, Lambda는 SQS 이벤트 소스 매핑으로 배치 처리한다.

SQS 설정:
- Visibility Timeout: 300초 (Lambda 최대 실행 시간과 일치)
- Message Retention: 4일
- Batch Size: 1 (이벤트 하나씩 처리, 분석 정확도 우선)

### 3.3 DLQ (Dead Letter Queue) 처리

Lambda 처리 실패 시 이벤트는 DLQ(Dead Letter Queue)로 이동한다. DLQ는 별도 SQS 큐로 구성하며, CloudWatch Alarm으로 DLQ 메시지 수를 모니터링한다. 운영자는 DLQ 이벤트를 수동 검토 후 재처리하거나 폐기한다.

```
Lambda 실패 (3회 재시도)
  └── DLQ SQS 큐
        ├── CloudWatch Alarm (메시지 수 > 0)
        │     └── SNS → 운영자 이메일/Slack 알림
        └── 수동 재처리 또는 S3 아카이브
```

### 3.4 이벤트 스키마 정규화

GuardDuty Finding(ASFF 포맷)과 Falco JSON은 구조가 다르다. Lambda 진입점에서 두 포맷을 ATDR 내부 스키마로 정규화한다.

**GuardDuty ASFF 원본 (일부):**

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:guardduty:...",
  "ProductArn": "arn:aws:securityhub:...",
  "Type": "TTPs/Defense Evasion/Kubernetes:Backdoor-RuntimeExecution",
  "Severity": { "Label": "HIGH", "Normalized": 70 },
  "Resources": [{
    "Type": "AwsEksCluster",
    "Id": "arn:aws:eks:ap-northeast-2:123456789:cluster/atdr-cluster",
    "Details": {
      "Container": {
        "Name": "nginx",
        "ImageName": "nginx:1.25"
      }
    }
  }]
}
```

**Falco JSON 원본 (일부):**

```json
{
  "output": "Unexpected outbound from nginx-pod (ip=203.0.113.5 port=4444)",
  "priority": "WARNING",
  "rule": "Unexpected outbound connection from app pod",
  "time": "2026-05-04T10:23:45.123Z",
  "output_fields": {
    "k8s.pod.name": "nginx-pod",
    "k8s.ns.name": "app",
    "fd.sip": "203.0.113.5",
    "fd.sport": "4444"
  }
}
```

**ATDR 내부 정규화 스키마:**

```json
{
  "event_id": "evt-20260504-a1b2c3d4",
  "source": "guardduty",
  "source_raw": { "...원본 이벤트..." },
  "timestamp": "2026-05-04T10:23:45Z",
  "severity": "HIGH",
  "severity_score": 70,
  "finding_type": "Kubernetes:Backdoor/RuntimeExecution",
  "cluster": "atdr-cluster",
  "namespace": "app",
  "pod_name": "nginx-pod",
  "container_name": "nginx",
  "image": "nginx:1.25",
  "node": "ip-10-0-1-42.ap-northeast-2.compute.internal",
  "indicators": {
    "remote_ip": "203.0.113.5",
    "remote_port": 4444,
    "process": "/bin/bash",
    "syscall": "execve"
  },
  "tags": ["runtime", "reverse_shell", "lateral_movement"]
}
```


---

## 4. AI 분석 레이어

ATDR의 핵심이다. Lambda 위에서 Strands Agent SDK로 구현한 4개 Agent가 순차적으로 실행되며, 각 Agent는 이전 Agent의 출력을 입력으로 받는다.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI 분석 레이어                                 │
│                                                                     │
│  정규화된 이벤트                                                       │
│       │                                                             │
│       ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Summary Agent (Claude Haiku 4.5)                           │   │
│  │  - 이벤트 핵심 정보 추출                                       │   │
│  │  - 자연어 요약 생성                                            │   │
│  │  - 관련 엔티티 식별 (Pod, Node, IP, 프로세스)                  │   │
│  └─────────────────────┬───────────────────────────────────────┘   │
│                        │ SummaryOutput                             │
│                        ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Triage Agent (Claude Haiku 4.5)                            │   │
│  │  - 심각도 재평가 (LOW/MEDIUM/HIGH/CRITICAL)                   │   │
│  │  - 우선순위 결정                                               │   │
│  │  - 중복 이벤트 탐지 (최근 1시간 내 동일 Pod/Finding)           │   │
│  │  - 즉각 대응 필요 여부 판단                                    │   │
│  └─────────────────────┬───────────────────────────────────────┘   │
│                        │ TriageOutput                              │
│                        ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Solution Agent (Claude Sonnet 4.6)                         │   │
│  │  - Bedrock Knowledge Base 검색 (RAG)                        │   │
│  │  - 런북 매칭                                                  │   │
│  │  - 근본 원인 분석                                              │   │
│  │  - 공격 경로 추론                                              │   │
│  └─────────────────────┬───────────────────────────────────────┘   │
│                        │ SolutionOutput                            │
│                        ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Remediation Agent (Claude Sonnet 4.6)                      │   │
│  │  - 대응 액션 결정                                              │   │
│  │  - EKS MCP로 실행 (자동 또는 승인 후)                          │   │
│  │  - 런북 업데이트 피드백                                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  공통 인프라                                                          │
│  Bedrock Knowledge Base ── OpenSearch Serverless (벡터 인덱스)       │
│                        └── S3 (런북 원본 저장)                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Summary Agent (Claude Haiku 4.5)

가장 먼저 실행된다. 정규화된 이벤트를 받아 분석에 필요한 핵심 정보를 구조화된 형태로 추출한다. Haiku 4.5를 쓰는 이유는 속도와 비용이다. 요약 작업은 복잡한 추론이 필요 없으므로 빠른 모델이 적합하다.

**입력:** ATDR 정규화 스키마 이벤트

**출력 스키마 (SummaryOutput):**

```json
{
  "event_id": "evt-20260504-a1b2c3d4",
  "summary": "app 네임스페이스의 nginx-pod에서 외부 IP 203.0.113.5:4444로 역방향 셸 연결이 탐지됨. GuardDuty Runtime Agent가 /bin/bash execve 시스템 콜을 감지했으며, 해당 IP는 알려진 C2 서버 목록에 포함됨.",
  "entities": {
    "pods": ["nginx-pod"],
    "namespaces": ["app"],
    "nodes": ["ip-10-0-1-42.ap-northeast-2.compute.internal"],
    "images": ["nginx:1.25"],
    "remote_ips": ["203.0.113.5"],
    "processes": ["/bin/bash"]
  },
  "threat_indicators": [
    "reverse_shell",
    "known_c2_ip",
    "unexpected_process_execution"
  ],
  "confidence": 0.92
}
```

**시스템 프롬프트 핵심:**

```
당신은 Kubernetes 보안 이벤트 분석 전문가입니다.
주어진 보안 이벤트에서 다음을 추출하세요:
1. 무슨 일이 일어났는지 한 문장으로 요약
2. 관련된 모든 엔티티 (Pod, Node, IP, 프로세스, 이미지)
3. 위협 지표 목록
4. 분석 신뢰도 (0.0~1.0)

JSON 형식으로만 응답하세요. 추가 설명 불필요.
```

### 4.2 Triage Agent (Claude Haiku 4.5)

Summary Agent 출력을 받아 심각도를 재평가하고 대응 우선순위를 결정한다. GuardDuty가 부여한 심각도는 컨텍스트를 반영하지 못하는 경우가 있다. 예를 들어 개발 네임스페이스의 이벤트와 프로덕션 네임스페이스의 동일 이벤트는 다르게 처리해야 한다.

중복 탐지는 DynamoDB 테이블을 조회해 최근 1시간 내 동일 Pod + Finding Type 조합이 있으면 `is_duplicate: true`로 표시한다. 중복 이벤트는 Solution/Remediation Agent를 건너뛰고 기존 인시던트에 병합된다.

**출력 스키마 (TriageOutput):**

```json
{
  "event_id": "evt-20260504-a1b2c3d4",
  "severity": "CRITICAL",
  "severity_score": 95,
  "priority": 1,
  "is_duplicate": false,
  "duplicate_of": null,
  "requires_immediate_action": true,
  "namespace_criticality": "production",
  "reasoning": "역방향 셸 + 알려진 C2 IP 조합은 활성 침해(Active Compromise) 지표. 프로덕션 네임스페이스이므로 즉각 격리 필요.",
  "recommended_response_tier": "automated_with_approval"
}
```

`recommended_response_tier` 값:
- `automated` — 자동 실행 (낮은 위험, 높은 확신)
- `automated_with_approval` — Slack 승인 후 자동 실행
- `manual` — 운영자 수동 처리

### 4.3 Solution Agent (Claude Sonnet 4.6)

가장 복잡한 추론을 담당한다. Bedrock Knowledge Base를 RAG로 활용해 유사 인시던트 런북을 검색하고, 근본 원인과 공격 경로를 추론한다. Sonnet 4.6을 쓰는 이유는 복잡한 멀티홉 추론과 긴 컨텍스트 처리 능력 때문이다.

**RAG 파이프라인:**

```
런북 S3 저장소 (Markdown 파일)
  └── Bedrock Knowledge Base 인덱싱
        ├── 청크 분할 (512 토큰, 50 토큰 오버랩)
        ├── Titan Embeddings v2로 벡터화
        └── OpenSearch Serverless 저장

쿼리 시:
  SummaryOutput + TriageOutput
    └── 쿼리 임베딩 생성
          └── OpenSearch k-NN 검색 (k=5)
                └── 상위 5개 런북 청크 → 프롬프트 컨텍스트 주입
```

**출력 스키마 (SolutionOutput):**

```json
{
  "event_id": "evt-20260504-a1b2c3d4",
  "root_cause": "nginx:1.25 이미지의 알려진 RCE 취약점(CVE-2024-XXXX)을 통해 공격자가 초기 접근 획득. /bin/bash를 통해 역방향 셸 수립 후 C2 서버와 통신 중.",
  "attack_path": [
    "외부 공격자 → nginx RCE 취약점 익스플로잇",
    "컨테이너 내 /bin/bash 실행",
    "203.0.113.5:4444로 역방향 셸 연결",
    "잠재적 횡적 이동 시도 예상"
  ],
  "matched_runbooks": [
    {
      "runbook_id": "RB-K8S-001",
      "title": "컨테이너 역방향 셸 대응",
      "relevance_score": 0.94,
      "s3_key": "runbooks/RB-K8S-001-reverse-shell.md"
    }
  ],
  "recommended_actions": [
    "nginx-pod 즉시 격리 (NetworkPolicy)",
    "Pod 삭제 및 재스케줄링 방지",
    "nginx:1.25 → nginx:1.27 이미지 업데이트",
    "동일 이미지 사용 Pod 전수 조사"
  ],
  "lateral_movement_risk": "HIGH",
  "data_exfiltration_risk": "MEDIUM"
}
```

### 4.4 Remediation Agent (Claude Sonnet 4.6)

Solution Agent의 권고 액션을 실제 쿠버네티스 명령으로 변환하고 EKS MCP를 통해 실행한다. `recommended_response_tier`에 따라 즉시 실행하거나 Slack 승인을 기다린다.

**출력 스키마 (RemediationOutput):**

```json
{
  "event_id": "evt-20260504-a1b2c3d4",
  "actions_executed": [
    {
      "action_type": "create_network_policy",
      "target": "nginx-pod",
      "namespace": "app",
      "status": "success",
      "manifest_applied": "...NetworkPolicy YAML...",
      "timestamp": "2026-05-04T10:24:12Z"
    },
    {
      "action_type": "delete_pod",
      "target": "nginx-pod",
      "namespace": "app",
      "status": "pending_approval",
      "approval_request_id": "apr-20260504-x9y8z7",
      "slack_message_ts": "1746350652.123456"
    }
  ],
  "runbook_feedback": {
    "runbook_id": "RB-K8S-001",
    "effectiveness": "partial",
    "notes": "NetworkPolicy 적용 성공. Pod 삭제는 승인 대기 중.",
    "suggested_update": "역방향 셸 탐지 시 NetworkPolicy 먼저 적용 후 Pod 삭제 순서 명시 필요"
  }
}
```

### 4.5 Bedrock Knowledge Base: RAG 파이프라인

런북은 `docs/11-runbooks/` 디렉토리에 Markdown 파일로 관리한다. S3에 업로드하면 Bedrock Knowledge Base가 자동으로 인덱싱한다.

```
docs/11-runbooks/
  ├── RB-K8S-001-reverse-shell.md
  ├── RB-K8S-002-privilege-escalation.md
  ├── RB-K8S-003-crypto-mining.md
  ├── RB-NET-001-dns-tunneling.md
  └── RB-NET-002-lateral-movement.md
```

런북 파일 구조 (표준):

```markdown
# RB-K8S-001: 컨테이너 역방향 셸 대응

## 위협 유형
- Finding: Kubernetes:Backdoor/RuntimeExecution
- Falco Rule: Unexpected outbound connection

## 탐지 지표
- 컨테이너 내 /bin/bash, /bin/sh 실행
- 외부 IP로의 비정상 아웃바운드 연결
- 알려진 C2 IP 통신

## 대응 절차
1. 영향받은 Pod에 NetworkPolicy 적용 (모든 Egress 차단)
2. Pod 삭제 (재스케줄링 방지: cordon 노드)
3. 동일 이미지 사용 Pod 전수 조사
4. 이미지 취약점 스캔 (Trivy)
5. 이미지 업데이트 후 재배포

## 자동화 가능 액션
- NetworkPolicy 생성: 자동
- Pod 삭제: 승인 필요
- 노드 코든: 승인 필요
```


---

## 5. 대응 실행 레이어

AI 분석 결과를 실제 쿠버네티스 액션으로 변환하는 레이어다. EKS MCP(Model Context Protocol)가 Remediation Agent와 EKS API 서버 사이의 브릿지 역할을 한다.

```
┌──────────────────────────────────────────────────────────────────┐
│                      대응 실행 레이어                               │
│                                                                  │
│  Remediation Agent                                               │
│       │                                                          │
│       ▼                                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  EKS MCP (Model Context Protocol Server)                 │   │
│  │  - kubectl 래퍼                                           │   │
│  │  - 액션 검증 (허용된 액션 목록만 실행)                       │   │
│  │  - 감사 로그 기록                                          │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                        │
│         ┌───────────────┼───────────────┐                       │
│         ▼               ▼               ▼                       │
│  NetworkPolicy     Pod 삭제/재시작   RBAC 수정                    │
│  생성/수정         네임스페이스 격리   시크릿 로테이션               │
│                    노드 코든/드레인                                │
│                                                                  │
│  Human Approval 워크플로우                                        │
│  Remediation Agent ──▶ Slack Bot ──▶ 운영자 승인/거부             │
│                              │                                   │
│                    승인 ──▶ EKS MCP 실행                          │
│                    거부 ──▶ 수동 처리 큐                           │
│                                                                  │
│  피드백 루프                                                       │
│  실행 결과 ──▶ Bedrock Knowledge Base 런북 업데이트                │
└──────────────────────────────────────────────────────────────────┘
```

### 5.1 EKS MCP (Model Context Protocol)

EKS MCP는 Remediation Agent가 쿠버네티스 API를 안전하게 호출할 수 있도록 하는 MCP 서버다. 직접 kubectl을 실행하는 대신 MCP 도구 인터페이스를 통해 허용된 액션만 실행한다.

MCP 서버가 노출하는 도구 목록:

```python
tools = [
    "create_network_policy",      # NetworkPolicy 생성
    "delete_pod",                 # Pod 삭제
    "restart_deployment",         # Deployment 롤링 재시작
    "isolate_namespace",          # 네임스페이스 전체 격리
    "patch_rbac",                 # ClusterRoleBinding/RoleBinding 수정
    "rotate_secret",              # Secret 값 교체
    "cordon_node",                # 노드 스케줄링 비활성화
    "drain_node",                 # 노드 드레인
    "get_pod_logs",               # Pod 로그 조회 (읽기 전용)
    "describe_pod",               # Pod 상태 조회 (읽기 전용)
    "list_pods_by_image",         # 이미지 기준 Pod 목록 조회
]
```

각 도구는 실행 전 다음을 검증한다:
- 대상 네임스페이스가 허용 목록에 있는지
- 액션이 현재 인시던트 컨텍스트와 일치하는지
- 실행 결과를 CloudTrail에 기록할 수 있는지

### 5.2 대응 액션 목록

**NetworkPolicy 생성 (자동 실행 가능)**

영향받은 Pod의 모든 Ingress/Egress를 차단하는 NetworkPolicy를 생성한다. 가장 빠르고 안전한 초기 격리 수단이다.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-nginx-pod
  namespace: app
  labels:
    atdr.io/incident-id: "evt-20260504-a1b2c3d4"
    atdr.io/auto-generated: "true"
spec:
  podSelector:
    matchLabels:
      app: nginx
  policyTypes:
  - Ingress
  - Egress
  # 모든 트래픽 차단 (규칙 없음 = 전부 거부)
```

**Pod 삭제/재시작 (승인 필요)**

침해된 Pod를 삭제한다. Deployment가 관리하는 Pod라면 새 Pod가 자동 생성되므로, 노드 코든과 함께 사용해 동일 노드에 재스케줄링되지 않도록 한다.

**네임스페이스 격리 (승인 필요)**

네임스페이스 레벨 NetworkPolicy로 해당 네임스페이스의 모든 Pod 간 통신을 차단한다. 횡적 이동이 의심될 때 사용한다.

**RBAC 수정 (승인 필요)**

침해된 ServiceAccount의 ClusterRoleBinding을 제거하거나 권한을 최소화한다.

**시크릿 로테이션 (승인 필요)**

침해된 Pod가 마운트하던 Secret을 새 값으로 교체하고, 해당 Secret을 참조하는 모든 Deployment를 재시작한다.

**노드 코든/드레인 (승인 필요)**

노드 레벨 침해가 의심될 때 사용한다. `cordon`은 새 Pod 스케줄링을 막고, `drain`은 기존 Pod를 다른 노드로 이동시킨다.

### 5.3 Human Approval 워크플로우

`automated_with_approval` 또는 `manual` 티어 이벤트는 Slack 승인 워크플로우를 거친다.

```
Remediation Agent
  └── Slack Bot API 호출
        └── #security-alerts 채널에 메시지 게시
              ┌─────────────────────────────────────┐
              │ [CRITICAL] nginx-pod 역방향 셸 탐지  │
              │                                     │
              │ 네임스페이스: app                    │
              │ Pod: nginx-pod                      │
              │ 위협: Reverse Shell → 203.0.113.5   │
              │                                     │
              │ 권고 액션:                           │
              │ 1. NetworkPolicy 격리 (자동 완료)    │
              │ 2. Pod 삭제 ← 승인 필요              │
              │ 3. 노드 코든 ← 승인 필요             │
              │                                     │
              │ [승인] [거부] [상세 보기]             │
              └─────────────────────────────────────┘
                    │              │
              승인 클릭        거부 클릭
                    │              │
              EKS MCP 실행    수동 처리 큐
              결과 → Slack    운영자 직접 처리
```

승인 타임아웃은 15분이다. 타임아웃 시 에스컬레이션 알림을 보내고 수동 처리 큐로 이동한다.

### 5.4 런북 업데이트 피드백 루프

Remediation Agent는 실행 결과를 바탕으로 런북 개선 제안을 생성한다. 제안은 S3에 저장되며, 주간 리뷰 프로세스에서 팀이 검토해 런북을 업데이트한다. 업데이트된 런북은 Bedrock Knowledge Base에 자동 재인덱싱된다.

```
실행 결과 수집
  └── Remediation Agent가 효과성 평가
        └── 런북 개선 제안 생성 (JSON)
              └── S3 저장 (runbooks/feedback/)
                    └── 주간 리뷰 → 런북 업데이트
                          └── Bedrock KB 재인덱싱
```


---

## 6. 관측/포렌식 레이어

인시던트 발생 전후의 상태를 기록하고, 사후 분석에 필요한 데이터를 보존한다. 실시간 모니터링과 장기 포렌식 두 가지 목적을 동시에 충족해야 한다.

```
┌──────────────────────────────────────────────────────────────────┐
│                     관측/포렌식 레이어                              │
│                                                                  │
│  실시간 관측                                                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────────┐ │
│  │ Prometheus │  │   Loki     │  │  Hubble (Cilium)            │ │
│  │ 메트릭 수집 │  │ 로그 집계  │  │  네트워크 플로우 관측         │ │
│  └─────┬──────┘  └─────┬──────┘  └────────────┬───────────────┘ │
│        └───────────────┴──────────────────────┘                 │
│                         │                                        │
│                         ▼                                        │
│                    Grafana 대시보드                               │
│                                                                  │
│  포렌식/감사                                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  S3 Object Lock (WORM)                                   │   │
│  │  - 인시던트 이벤트 원본                                    │   │
│  │  - Agent 분석 결과                                        │   │
│  │  - 대응 액션 로그                                          │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  CloudTrail Lake                                         │   │
│  │  - AWS API 호출 이력 (SQL 쿼리 가능)                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  컨테이너 체크포인트 (K8s 1.35 beta)                       │   │
│  │  - 침해 시점 컨테이너 메모리/파일시스템 스냅샷               │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 6.1 Prometheus + Grafana

Prometheus는 클러스터 메트릭을 수집한다. kube-state-metrics와 node-exporter를 함께 배포해 Pod, Node, 네임스페이스 레벨 메트릭을 모두 수집한다.

ATDR 전용 커스텀 메트릭:

| 메트릭 이름 | 설명 |
|------------|------|
| `atdr_events_total` | 처리된 보안 이벤트 총 수 (소스별) |
| `atdr_agent_latency_seconds` | 각 Agent 처리 시간 |
| `atdr_remediation_actions_total` | 실행된 대응 액션 수 (타입별) |
| `atdr_false_positive_rate` | 운영자가 거부한 비율 |
| `atdr_mttr_seconds` | 탐지부터 대응 완료까지 시간 |

Grafana 대시보드 구성:
- **인시던트 현황**: 실시간 이벤트 스트림, 심각도 분포
- **Agent 성능**: 각 Agent 처리 시간, 오류율
- **대응 효과**: MTTR 추이, 자동화 비율
- **클러스터 상태**: 격리된 Pod/네임스페이스 현황

### 6.2 Loki

Loki는 클러스터 내 모든 컨테이너 로그를 수집한다. Promtail DaemonSet이 각 노드의 컨테이너 로그를 Loki로 전달한다. Tetragon 이벤트도 Loki로 수집한다.

인시던트 발생 시 Grafana에서 해당 Pod의 로그를 시간 범위로 조회해 공격 타임라인을 재구성할 수 있다.

### 6.3 Hubble (Cilium) 네트워크 플로우

Hubble은 Cilium의 네트워크 관측 컴포넌트다. eBPF 기반으로 모든 Pod 간 네트워크 플로우를 기록한다. L3/L4 레벨 플로우뿐 아니라 L7(HTTP, gRPC, DNS) 레벨 가시성도 제공한다.

```
Hubble Relay
  └── 클러스터 전체 플로우 집계
        ├── Hubble UI (실시간 네트워크 맵)
        └── Prometheus 메트릭 노출
              └── Grafana 시각화
```

인시던트 조사 시 `hubble observe` 명령으로 특정 Pod의 과거 플로우를 조회한다:

```bash
hubble observe \
  --pod app/nginx-pod \
  --since 30m \
  --verdict DROPPED \
  -o json
```

### 6.4 S3 Object Lock + CloudTrail Lake

**S3 Object Lock (WORM)**

모든 인시던트 데이터를 S3 Object Lock Compliance 모드로 저장한다. 저장 후 지정 기간(90일) 동안 삭제 및 수정이 불가능하다. 포렌식 증거 보전과 규정 준수 목적이다.

저장 데이터:
- 원본 이벤트 (GuardDuty Finding, Falco Alert)
- ATDR 정규화 스키마 이벤트
- 각 Agent 입출력 (전체 분석 체인)
- 실행된 대응 액션 및 결과
- Slack 승인/거부 기록

**CloudTrail Lake**

CloudTrail Lake는 AWS API 호출 이력을 SQL로 쿼리할 수 있는 서비스다. 인시던트 전후 AWS 레벨 액션을 추적하는 데 사용한다.

```sql
-- 인시던트 시점 전후 1시간 내 IAM 변경 조회
SELECT
  eventTime,
  userIdentity.arn,
  eventName,
  requestParameters
FROM atdr_cloudtrail_lake
WHERE eventTime BETWEEN '2026-05-04T09:23:00Z' AND '2026-05-04T11:23:00Z'
  AND eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreateUser', 'AttachUserPolicy', 'CreateAccessKey')
ORDER BY eventTime
```

### 6.5 컨테이너 체크포인트 (K8s 1.35 beta)

Kubernetes 1.35의 컨테이너 체크포인트 기능(CRIU 기반)을 활용해 침해 시점의 컨테이너 상태를 스냅샷으로 저장한다. 메모리 덤프, 파일시스템 상태, 열린 파일 디스크립터 등이 포함된다.

체크포인트 생성:

```bash
# kubelet API 직접 호출
curl -X POST \
  "https://${NODE_IP}:10250/checkpoint/app/nginx-pod/nginx" \
  --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt \
  --key /etc/kubernetes/pki/apiserver-kubelet-client.key \
  --cacert /etc/kubernetes/pki/ca.crt
```

생성된 체크포인트 아카이브는 S3 Object Lock 버킷에 업로드해 포렌식 분석에 활용한다.


---

## 7. 보안 레이어

ATDR 시스템 자체의 보안을 다루는 레이어다. 탐지 시스템이 침해되면 모든 대응 능력을 잃으므로, 시스템 자체 보안은 탐지 대상 워크로드만큼 중요하다.

```
┌──────────────────────────────────────────────────────────────────┐
│                        보안 레이어                                 │
│                                                                  │
│  네트워크 보안                                                     │
│  Cilium CNI + WireGuard (노드 간 암호화)                           │
│  Cilium L7 NetworkPolicy (HTTP/gRPC 레벨 제어)                    │
│                                                                  │
│  워크로드 보안                                                     │
│  ValidatingAdmissionPolicy (CEL) — 정책 위반 배포 차단             │
│  Pod Security Standards (Restricted)                             │
│                                                                  │
│  접근 제어                                                        │
│  EKS Access Entry (API mode) — 쿠버네티스 RBAC 통합               │
│  Pod Identity + IAM Role — 최소 권한 AWS 접근                     │
│                                                                  │
│  암호화                                                           │
│  KMS — EKS Secrets 암호화, CloudTrail 로그 암호화                 │
│  TLS — 모든 서비스 간 통신                                         │
└──────────────────────────────────────────────────────────────────┘
```

### 7.1 Cilium CNI + WireGuard 노드 간 암호화

Cilium을 CNI로 사용하면 WireGuard를 통한 노드 간 트래픽 암호화를 기본 제공한다. Pod 간 통신이 노드 경계를 넘을 때 자동으로 암호화된다. 별도 서비스 메시(Istio 등) 없이 투명한 암호화가 가능하다.

Cilium 설치 시 WireGuard 활성화:

```yaml
# cilium-values.yaml
encryption:
  enabled: true
  type: wireguard
  wireguard:
    userspaceFallback: false
```

### 7.2 ValidatingAdmissionPolicy (CEL)

Kubernetes 1.30+에서 GA된 ValidatingAdmissionPolicy는 OPA/Gatekeeper 없이 CEL(Common Expression Language)로 입장 정책을 작성할 수 있다. ATDR에서는 다음 정책을 적용한다.

**privileged 컨테이너 배포 차단:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-privileged-containers
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["pods"]
  validations:
  - expression: >
      !has(object.spec.containers) ||
      object.spec.containers.all(c,
        !has(c.securityContext) ||
        !has(c.securityContext.privileged) ||
        c.securityContext.privileged == false
      )
    message: "privileged 컨테이너는 허용되지 않습니다."
```

**hostNetwork/hostPID 사용 차단:**

```yaml
  validations:
  - expression: >
      object.spec.hostNetwork == false &&
      object.spec.hostPID == false &&
      object.spec.hostIPC == false
    message: "host 네임스페이스 공유는 허용되지 않습니다."
```

### 7.3 EKS Access Entry (API mode)

EKS Access Entry는 `aws-auth` ConfigMap 방식을 대체하는 IAM 기반 쿠버네티스 접근 제어다. IAM 역할을 쿠버네티스 RBAC 그룹에 직접 매핑한다.

```bash
# ATDR 운영자 역할 매핑
aws eks create-access-entry \
  --cluster-name atdr-cluster \
  --principal-arn arn:aws:iam::123456789:role/ATDROperatorRole \
  --kubernetes-groups atdr-operators

# 읽기 전용 감사 역할
aws eks create-access-entry \
  --cluster-name atdr-cluster \
  --principal-arn arn:aws:iam::123456789:role/ATDRAuditRole \
  --kubernetes-groups atdr-auditors
```

### 7.4 Pod Identity + IAM Role

EKS Pod Identity는 IRSA(IAM Roles for Service Accounts)의 후속 기능이다. ServiceAccount에 IAM Role을 직접 연결해 Pod가 AWS 서비스에 접근할 때 최소 권한 원칙을 적용한다.

ATDR Lambda 함수의 IAM 권한 (최소 권한):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:RetrieveAndGenerate"
      ],
      "Resource": "arn:aws:bedrock:ap-northeast-2::foundation-model/anthropic.*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "aoss:APIAccessAll"
      ],
      "Resource": "arn:aws:aoss:ap-northeast-2:123456789:collection/atdr-kb"
    },
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListNodegroups"
      ],
      "Resource": "arn:aws:eks:ap-northeast-2:123456789:cluster/atdr-cluster"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::atdr-forensics-bucket/*"
    }
  ]
}
```

### 7.5 KMS 암호화

| 암호화 대상 | KMS 키 | 설명 |
|------------|--------|------|
| EKS Secrets | `atdr/eks-secrets` | etcd 저장 시크릿 암호화 |
| CloudTrail 로그 | `atdr/cloudtrail` | 감사 로그 무결성 보장 |
| S3 포렌식 버킷 | `atdr/forensics` | 인시던트 데이터 암호화 |
| SQS 메시지 | `atdr/sqs` | 이벤트 전달 중 암호화 |

모든 KMS 키는 자동 로테이션(1년)을 활성화하고, 키 정책으로 접근 주체를 최소화한다.


---

## 8. 네트워크 아키텍처

### 8.1 VPC 구성

```
┌─────────────────────────────────────────────────────────────────────┐
│  VPC: 10.0.0.0/16 (ap-northeast-2)                                  │
│                                                                     │
│  ┌──────────────────────────┐  ┌──────────────────────────────────┐ │
│  │  Public Subnet           │  │  Public Subnet                   │ │
│  │  10.0.0.0/24 (AZ-a)      │  │  10.0.1.0/24 (AZ-c)             │ │
│  │                          │  │                                  │ │
│  │  NAT Gateway             │  │  NAT Gateway                     │ │
│  │  ALB (Ingress)           │  │  ALB (Ingress)                   │ │
│  └──────────────────────────┘  └──────────────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────┐  ┌──────────────────────────────────┐ │
│  │  Private Subnet          │  │  Private Subnet                  │ │
│  │  10.0.10.0/24 (AZ-a)     │  │  10.0.11.0/24 (AZ-c)            │ │
│  │                          │  │                                  │ │
│  │  EKS Worker Nodes        │  │  EKS Worker Nodes                │ │
│  │  Lambda (VPC 내)         │  │  Lambda (VPC 내)                 │ │
│  └──────────────────────────┘  └──────────────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  VPC Endpoints (PrivateLink)                                 │   │
│  │  - com.amazonaws.ap-northeast-2.ecr.api                      │   │
│  │  - com.amazonaws.ap-northeast-2.ecr.dkr                      │   │
│  │  - com.amazonaws.ap-northeast-2.s3 (Gateway)                 │   │
│  │  - com.amazonaws.ap-northeast-2.bedrock-runtime              │   │
│  │  - com.amazonaws.ap-northeast-2.aoss                         │   │
│  │  - com.amazonaws.ap-northeast-2.sqs                          │   │
│  │  - com.amazonaws.ap-northeast-2.sns                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

VPC Endpoint를 사용하는 이유: Lambda와 EKS 노드가 AWS 서비스(Bedrock, S3, SQS 등)에 접근할 때 인터넷을 거치지 않는다. 트래픽이 AWS 내부 네트워크에 머물러 보안과 지연 시간 모두 개선된다.

### 8.2 EKS Private Endpoint

EKS API 서버는 private endpoint만 활성화한다. 클러스터 외부에서 kubectl을 사용하려면 VPN 또는 Bastion Host를 거쳐야 한다.

```hcl
# terraform/eks/main.tf
resource "aws_eks_cluster" "atdr" {
  name = "atdr-cluster"

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.eks_control_plane.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }
}
```

### 8.3 Security Groups

| Security Group | 인바운드 | 아웃바운드 |
|---------------|---------|----------|
| `atdr-eks-control-plane` | 443 (노드 SG에서) | 1025-65535 (노드 SG로) |
| `atdr-eks-nodes` | 전체 (노드 SG 내부) | 443 (Control Plane SG로), 443 (VPC Endpoints) |
| `atdr-lambda` | 없음 | 443 (VPC Endpoints), 443 (SQS/SNS) |
| `atdr-vpc-endpoints` | 443 (Lambda SG, 노드 SG에서) | 없음 |

### 8.4 Cilium L7 NetworkPolicy

Cilium은 표준 Kubernetes NetworkPolicy 외에 L7 레벨 정책을 지원한다. HTTP 메서드, 경로, gRPC 서비스 단위로 트래픽을 제어할 수 있다.

**app 네임스페이스 기본 정책 (deny-all + 허용 목록):**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: app-default-policy
  namespace: app
spec:
  endpointSelector: {}
  ingress:
  - fromEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: ingress-nginx
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s:k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
  - toFQDNs:
    - matchPattern: "*.ap-northeast-2.amazonaws.com"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

**ATDR 시스템 컴포넌트 간 통신 정책:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: atdr-internal-policy
  namespace: atdr-system
spec:
  endpointSelector:
    matchLabels:
      app: atdr-eks-mcp
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: atdr-remediation-agent
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: POST
          path: "/mcp/tools/.*"
```

---

## 부록: 전체 이벤트 흐름 요약

```
공격 발생
  │
  ├── GuardDuty Runtime Agent (eBPF) 탐지
  │     └── GuardDuty Finding 생성
  │           └── EventBridge → Lambda 트리거
  │
  ├── Falco DaemonSet (eBPF) 탐지
  │     └── Falcosidekick → SNS → SQS → Lambda 트리거
  │
  └── Tetragon (Cilium) 탐지
        └── 커널 레벨 즉시 차단 (enforce 모드)
              └── 이벤트 → Loki 기록

Lambda (Strands Agent 파이프라인)
  │
  ├── 이벤트 정규화 (ASFF / Falco JSON → ATDR 스키마)
  │
  ├── Summary Agent (Haiku 4.5)
  │     └── 핵심 정보 추출, 엔티티 식별
  │
  ├── Triage Agent (Haiku 4.5)
  │     └── 심각도 재평가, 중복 탐지, 우선순위 결정
  │
  ├── Solution Agent (Sonnet 4.6)
  │     └── RAG (Bedrock KB) → 런북 매칭, 근본 원인 분석
  │
  └── Remediation Agent (Sonnet 4.6)
        ├── 자동 실행: NetworkPolicy 격리
        └── 승인 필요: Slack → 운영자 승인 → EKS MCP 실행

결과 저장
  ├── S3 Object Lock (포렌식 보존)
  ├── Prometheus 메트릭 업데이트
  ├── Loki 로그 기록
  └── 런북 피드백 → Bedrock KB 재인덱싱
```

---

*이 문서는 설계 단계 아키텍처를 기술한다. 구현 과정에서 세부 사항이 변경될 수 있으며, 변경 시 이 문서를 함께 업데이트한다.*
