# 보안 강화 설계

> ATDR — EKS 보안 강화 설계 문서
> 문서 버전: 0.1 | 작성일: 2026-05-04 | 대상 독자: 개발팀 (4인)

---

## 목차

1. [보안 강화 전략 개요](#1-보안-강화-전략-개요)
2. [Cilium CNI + WireGuard](#2-cilium-cni--wireguard)
3. [ValidatingAdmissionPolicy (CEL)](#3-validatingadmissionpolicy-cel)
4. [EKS Access Entry](#4-eks-access-entry)
5. [Pod Identity + IAM Role](#5-pod-identity--iam-role)
6. [KMS 암호화](#6-kms-암호화)
7. [네트워크 보안](#7-네트워크-보안)
8. [K8s 1.35 보안 기능](#8-k8s-135-보안-기능)
9. [공급망 보안](#9-공급망-보안)

---

## 1. 보안 강화 전략 개요

ATDR 시스템의 보안 강화는 Prevention → Detection → Response → Forensics 사이클을 기반으로 설계한다. 각 단계는 독립적으로 동작하지만, 앞 단계의 실패를 뒤 단계가 보완하는 심층 방어(defense-in-depth) 구조를 이룬다.

### 1.1 사이클 개요



각 레이어는 단일 도구에 의존하지 않는다. 예를 들어 ValidatingAdmissionPolicy가 privileged container를 차단하더라도, Falco와 Tetragon이 런타임에서 동일한 패턴을 감시한다.

### 1.2 레이어별 도구 매핑

| 단계 | 주요 도구 | 역할 |
|------|-----------|------|
| Prevention | Cilium, ValidatingAdmissionPolicy, Pod Identity, KMS | 공격 표면 축소, 정책 강제 |
| Detection | Falco, Tetragon, GuardDuty, EKS Audit, Hubble | 이상 행위 탐지, 이벤트 수집 |
| Response | EKS MCP, Lambda, NetworkPolicy, Slack Bot | 격리, 차단, 승인 기반 대응 |
| Forensics | S3 Object Lock, CloudTrail Lake, Loki, Hubble | 증거 보존, 사후 분석 |

### 1.3 설계 원칙

- **최소 권한(Least Privilege)**: Pod Identity로 서비스별 IAM 역할을 분리하고, Access Entry로 사람의 접근을 네임스페이스 단위로 제한한다.
- **불변 감사 로그(Immutable Audit Trail)**: S3 Object Lock과 CloudTrail Lake로 로그 변조를 방지한다.
- **정책 코드화(Policy as Code)**: ValidatingAdmissionPolicy와 Cilium NetworkPolicy를 Git으로 관리한다. 수동 변경은 허용하지 않는다.
- **암호화 기본값(Encryption by Default)**: 저장 데이터와 전송 데이터 모두 KMS와 WireGuard로 암호화한다.

---

## 2. Cilium CNI + WireGuard

Cilium 1.19는 eBPF 기반 CNI로, kube-proxy를 완전히 대체하고 L3/L4/L7 네트워크 정책을 커널 수준에서 강제한다. WireGuard 통합으로 노드 간 트래픽을 투명하게 암호화한다.

### 2.1 kube-proxy 대체

Cilium은 eBPF를 사용해 iptables 없이 서비스 로드밸런싱을 처리한다. kube-proxy DaemonSet을 제거하고 Cilium이 그 역할을 맡는다.

```
기존: kube-proxy (iptables) → 느린 규칙 업데이트, O(n) 조회
Cilium: eBPF map → O(1) 조회, 커널 내 처리, 규칙 수에 무관한 성능
```

### 2.2 Helm 배포

```yaml
# cilium-values.yaml
kubeProxyReplacement: true
k8sServiceHost: "API_SERVER_ENDPOINT"
k8sServicePort: 443

# WireGuard 노드 간 암호화
encryption:
  enabled: true
  type: wireguard
  wireguard:
    userspaceFallback: false

# Hubble 관측성
hubble:
  enabled: true
  relay:
    enabled: true
  ui:
    enabled: true
  metrics:
    enabled:
      - dns
      - drop
      - tcp
      - flow
      - port-distribution
      - icmp
      - httpV2:exemplars=true;labelsContext=source_ip,source_namespace,destination_ip,destination_namespace

# L7 정책 활성화
l7Proxy: true

# eBPF 호스트 라우팅
routingMode: native
autoDirectNodeRoutes: true
ipv4NativeRoutingCIDR: "10.0.0.0/8"

# 마스커레이드
bpf:
  masquerade: true

# 노드 포트
nodePort:
  enabled: true
```

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
  --version 1.19.0 \
  --namespace kube-system \
  --values cilium-values.yaml
```

### 2.3 L7 정책 (HTTP/gRPC 필터링)

Cilium CiliumNetworkPolicy는 HTTP 메서드, 경로, gRPC 서비스 단위로 트래픽을 제어한다. 표준 Kubernetes NetworkPolicy로는 불가능한 수준이다.

```yaml
# L7 HTTP 정책 예시: ai-detector는 /analyze 엔드포인트만 허용
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: ai-detector-l7
  namespace: atdr
spec:
  endpointSelector:
    matchLabels:
      app: ai-detector
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: correlator
    toPorts:
    - ports:
      - port: "8080"
        protocol: TCP
      rules:
        http:
        - method: POST
          path: /analyze
        - method: GET
          path: /health
---
# L7 gRPC 정책 예시: response-advisor gRPC 서비스 제한
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: response-advisor-grpc
  namespace: atdr
spec:
  endpointSelector:
    matchLabels:
      app: response-advisor
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: ai-detector
    toPorts:
    - ports:
      - port: "9090"
        protocol: TCP
      rules:
        http:
        - method: POST
          path: /advisor.ResponseAdvisor/Recommend
```

### 2.4 WireGuard 노드 간 암호화

`encryption.enabled: true`와 `encryption.type: wireguard`를 설정하면 Cilium이 각 노드에 WireGuard 키 쌍을 자동 생성하고 노드 간 터널을 구성한다. 애플리케이션 코드 변경 없이 모든 Pod 간 트래픽이 암호화된다.

```bash
# 암호화 상태 확인
cilium encrypt status

# 예상 출력
Encryption: Wireguard
Wireguard:
  Node count: 3
  Node with encryption: 3
  Interface: cilium_wg0
  Public key: <base64-encoded-key>
```

### 2.5 Hubble 관측성

Hubble은 Cilium의 네트워크 관측성 레이어다. eBPF로 수집한 플로우 데이터를 Prometheus 메트릭과 gRPC 스트림으로 노출한다.

```bash
# Hubble CLI로 실시간 플로우 확인
hubble observe --namespace atdr --follow

# 드롭된 패킷만 필터링
hubble observe --namespace atdr --verdict DROPPED

# 특정 Pod의 트래픽
hubble observe --pod atdr/ai-detector-xxx --follow
```

Hubble UI는 네임스페이스 간 트래픽 흐름을 시각화한다. ATDR에서는 Grafana 대시보드와 연동해 비정상 플로우를 탐지 파이프라인으로 전달한다.

---

## 3. ValidatingAdmissionPolicy (CEL)

Kubernetes 1.30에서 GA된 ValidatingAdmissionPolicy는 API 서버에 내장된 정책 엔진이다. OPA/Gatekeeper처럼 별도 웹훅 서버를 운영할 필요가 없다. CEL(Common Expression Language)로 정책을 작성하고, ValidatingAdmissionPolicyBinding으로 적용 범위를 지정한다.

### 3.1 OPA/Gatekeeper 대비 장점

| 항목 | OPA/Gatekeeper | ValidatingAdmissionPolicy |
|------|----------------|--------------------------|
| 운영 부담 | 웹훅 서버 DaemonSet 필요 | API 서버 내장, 추가 컴포넌트 없음 |
| 지연 시간 | 네트워크 왕복 발생 | 인프로세스 평가 |
| 가용성 | 웹훅 장애 시 클러스터 영향 | API 서버와 동일한 가용성 |
| 언어 | Rego | CEL (더 단순) |
| 감사 | 별도 설정 필요 | 기본 제공 |

### 3.2 승인된 레지스트리만 허용

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: allowed-registries
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
      object.spec.containers.all(c,
        c.image.startsWith("123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/") ||
        c.image.startsWith("public.ecr.aws/")
      )
    message: "승인된 ECR 레지스트리의 이미지만 사용할 수 있습니다."
  - expression: >
      !has(object.spec.initContainers) ||
      object.spec.initContainers.all(c,
        c.image.startsWith("123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/") ||
        c.image.startsWith("public.ecr.aws/")
      )
    message: "initContainer도 승인된 레지스트리만 허용합니다."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: allowed-registries-binding
spec:
  policyName: allowed-registries
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values: ["kube-system"]
```

### 3.3 이미지 다이제스트 핀닝 강제

태그는 덮어쓸 수 있다. 다이제스트(`@sha256:...`)를 강제하면 이미지 변조를 방지한다.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-image-digest
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
      object.spec.containers.all(c, c.image.contains("@sha256:"))
    message: "이미지는 태그가 아닌 SHA256 다이제스트로 지정해야 합니다."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-image-digest-binding
spec:
  policyName: require-image-digest
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchLabels:
        security.atdr/digest-required: "true"
```

### 3.4 privileged container 차단

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-privileged
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
      object.spec.containers.all(c,
        !has(c.securityContext) ||
        !has(c.securityContext.privileged) ||
        c.securityContext.privileged == false
      )
    message: "privileged container는 허용되지 않습니다."
  - expression: >
      !has(object.spec.initContainers) ||
      object.spec.initContainers.all(c,
        !has(c.securityContext) ||
        !has(c.securityContext.privileged) ||
        c.securityContext.privileged == false
      )
    message: "initContainer의 privileged 모드도 허용되지 않습니다."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-privileged-binding
spec:
  policyName: deny-privileged
  validationActions: [Deny]
  matchResources: {}
```

### 3.5 hostPath 마운트 차단

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-hostpath
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
      !has(object.spec.volumes) ||
      object.spec.volumes.all(v, !has(v.hostPath))
    message: "hostPath 볼륨 마운트는 허용되지 않습니다."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-hostpath-binding
spec:
  policyName: deny-hostpath
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values: ["kube-system", "cilium"]
```

### 3.6 root 실행 차단

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-run-as-root
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
      has(object.spec.securityContext) &&
      has(object.spec.securityContext.runAsNonRoot) &&
      object.spec.securityContext.runAsNonRoot == true
    message: "Pod는 runAsNonRoot: true를 명시해야 합니다."
  - expression: >
      object.spec.containers.all(c,
        !has(c.securityContext) ||
        !has(c.securityContext.runAsUser) ||
        c.securityContext.runAsUser > 0
      )
    message: "runAsUser는 0(root)이 될 수 없습니다."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-run-as-root-binding
spec:
  policyName: deny-run-as-root
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchLabels:
        security.atdr/enforce-nonroot: "true"
```

---

## 4. EKS Access Entry

EKS Access Entry는 aws-auth ConfigMap을 대체하는 API 기반 접근 제어 방식이다. Kubernetes 1.29부터 EKS에서 기본 모드로 전환됐다. ConfigMap 직접 편집 없이 IAM 주체와 Kubernetes RBAC을 연결한다.

### 4.1 aws-auth ConfigMap 대비 장점

| 항목 | aws-auth ConfigMap | EKS Access Entry |
|------|-------------------|-----------------|
| 관리 방식 | kubectl로 직접 편집 | AWS API / Terraform |
| 실수 위험 | YAML 오타로 클러스터 잠금 가능 | API 검증으로 방지 |
| 감사 | CloudTrail 미기록 | CloudTrail 완전 기록 |
| 네임스페이스 스코프 | 불가 | 가능 |
| IaC 통합 | 별도 처리 필요 | Terraform 네이티브 |

### 4.2 역할별 접근 제어 설계

```
보안팀 (security-team)
  IAM Role: arn:aws:iam::ACCOUNT:role/atdr-security-team
  접근 범위: cluster-wide read-only
  Kubernetes Group: atdr:security-readonly

개발팀 (dev-team)
  IAM Role: arn:aws:iam::ACCOUNT:role/atdr-dev-team
  접근 범위: atdr 네임스페이스 edit
  Kubernetes Group: atdr:dev-edit

Break-glass (긴급 대응)
  IAM Role: arn:aws:iam::ACCOUNT:role/atdr-break-glass
  접근 범위: system:masters (전체 권한)
  조건: MFA 필수, CloudTrail 알림 연동
```

### 4.3 Terraform 코드

```hcl
# terraform/eks/access_entry.tf

locals {
  cluster_name = var.cluster_name
  account_id   = data.aws_caller_identity.current.account_id
}

# 보안팀: cluster-wide read-only
resource "aws_eks_access_entry" "security_team" {
  cluster_name  = local.cluster_name
  principal_arn = "arn:aws:iam::${local.account_id}:role/atdr-security-team"
  type          = "STANDARD"

  tags = {
    Team        = "security"
    Environment = var.environment
  }
}

resource "aws_eks_access_policy_association" "security_team_view" {
  cluster_name  = local.cluster_name
  principal_arn = aws_eks_access_entry.security_team.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

  access_scope {
    type = "cluster"
  }
}

# 개발팀: atdr 네임스페이스 edit
resource "aws_eks_access_entry" "dev_team" {
  cluster_name  = local.cluster_name
  principal_arn = "arn:aws:iam::${local.account_id}:role/atdr-dev-team"
  type          = "STANDARD"

  tags = {
    Team        = "dev"
    Environment = var.environment
  }
}

resource "aws_eks_access_policy_association" "dev_team_edit" {
  cluster_name  = local.cluster_name
  principal_arn = aws_eks_access_entry.dev_team.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"

  access_scope {
    type       = "namespace"
    namespaces = ["atdr"]
  }
}

# Break-glass: system:masters (긴급용, 평소 비활성화)
resource "aws_eks_access_entry" "break_glass" {
  cluster_name  = local.cluster_name
  principal_arn = "arn:aws:iam::${local.account_id}:role/atdr-break-glass"
  type          = "STANDARD"

  # kubernetes_groups에 system:masters를 직접 매핑
  kubernetes_groups = ["system:masters"]

  tags = {
    Team        = "security"
    Purpose     = "break-glass"
    Environment = var.environment
  }
}

# Break-glass 사용 시 CloudWatch 알람 트리거를 위한 EventBridge 규칙
resource "aws_cloudwatch_event_rule" "break_glass_usage" {
  name        = "atdr-break-glass-usage"
  description = "Break-glass 역할 사용 감지"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      requestParameters = {
        roleArn = ["arn:aws:iam::${local.account_id}:role/atdr-break-glass"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "break_glass_sns" {
  rule      = aws_cloudwatch_event_rule.break_glass_usage.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}
```

### 4.4 RBAC ClusterRole 정의

Access Entry의 `kubernetes_groups`와 연결되는 ClusterRole을 별도로 정의한다.

```yaml
# k8s/base/rbac/security-readonly.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: atdr-security-readonly
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "namespaces", "nodes", "events"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumnetworkpolicies", "ciliumclusterwidenetworkpolicies"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: atdr-security-readonly-binding
subjects:
- kind: Group
  name: atdr:security-readonly
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: atdr-security-readonly
  apiGroup: rbac.authorization.k8s.io
```

---

## 5. Pod Identity + IAM Role

EKS Pod Identity는 IRSA(IAM Roles for Service Accounts)를 대체한다. OIDC 공급자 설정 없이 Pod에 IAM 역할을 직접 연결한다. 서비스별로 IAM 역할을 분리해 최소 권한 원칙을 적용한다.

### 5.1 IRSA 대비 장점

| 항목 | IRSA | Pod Identity |
|------|------|-------------|
| OIDC 공급자 | 클러스터당 설정 필요 | 불필요 |
| 토큰 갱신 | 수동 설정 | 자동 |
| 교차 계정 | 복잡 | 단순 |
| 감사 | 제한적 | CloudTrail 완전 기록 |
| SDK 지원 | AWS SDK v2 이상 | AWS SDK v2 이상 |

### 5.2 서비스별 IAM 역할 설계

```
ai-detector
  역할: atdr-ai-detector
  권한: bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream
        s3:GetObject (knowledge-base 버킷만)
        logs:CreateLogGroup, logs:PutLogEvents

correlator
  역할: atdr-correlator
  권한: sqs:ReceiveMessage, sqs:DeleteMessage (atdr-events 큐만)
        dynamodb:GetItem, dynamodb:PutItem (correlation-state 테이블만)

response-advisor
  역할: atdr-response-advisor
  권한: eks:DescribeCluster
        eks:ListNodegroups
        ssm:GetParameter (remediation-config만)

remediation-executor
  역할: atdr-remediation-executor
  권한: eks:UpdateNodegroupConfig
        ec2:DescribeInstances
        sns:Publish (security-alerts 토픽만)
```

### 5.3 Terraform 코드

```hcl
# terraform/iam/pod_identity.tf

# Pod Identity 연결을 위한 EKS addon 활성화
resource "aws_eks_addon" "pod_identity" {
  cluster_name = var.cluster_name
  addon_name   = "eks-pod-identity-agent"

  tags = {
    Environment = var.environment
  }
}

# ai-detector IAM 역할
resource "aws_iam_role" "ai_detector" {
  name = "atdr-ai-detector-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "pods.eks.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
      }
    ]
  })

  tags = {
    Service     = "ai-detector"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "ai_detector" {
  name = "atdr-ai-detector-policy"
  role = aws_iam_role.ai_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = [
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
        ]
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "arn:aws:s3:::${var.knowledge_base_bucket}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${local.account_id}:log-group:/atdr/ai-detector:*"
      }
    ]
  })
}

# Pod Identity 연결
resource "aws_eks_pod_identity_association" "ai_detector" {
  cluster_name    = var.cluster_name
  namespace       = "atdr"
  service_account = "ai-detector"
  role_arn        = aws_iam_role.ai_detector.arn
}

# correlator IAM 역할
resource "aws_iam_role" "correlator" {
  name = "atdr-correlator-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "pods.eks.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "correlator" {
  name = "atdr-correlator-policy"
  role = aws_iam_role.correlator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.atdr_events.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.correlation_state.arn
      }
    ]
  })
}

resource "aws_eks_pod_identity_association" "correlator" {
  cluster_name    = var.cluster_name
  namespace       = "atdr"
  service_account = "correlator"
  role_arn        = aws_iam_role.correlator.arn
}
```

### 5.4 ServiceAccount 매니페스트

Pod Identity는 ServiceAccount에 어노테이션이 필요 없다. Terraform의 `aws_eks_pod_identity_association`이 네임스페이스와 ServiceAccount 이름으로 연결을 관리한다.

```yaml
# k8s/base/ai-detector/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ai-detector
  namespace: atdr
  # IRSA와 달리 어노테이션 불필요
automountServiceAccountToken: true
```

---

## 6. KMS 암호화

저장 데이터 암호화는 KMS 고객 관리형 키(CMK)를 기본으로 한다. 키 로테이션을 활성화하고, 키 정책으로 접근을 최소화한다.

### 6.1 EKS Secrets 암호화 (Envelope Encryption)

EKS는 etcd에 저장되는 Kubernetes Secrets를 KMS로 암호화한다. DEK(Data Encryption Key)를 KMS CMK로 감싸는 봉투 암호화 방식이다.

```hcl
# terraform/eks/kms.tf

resource "aws_kms_key" "eks_secrets" {
  description             = "EKS Secrets 암호화 키 - ${var.cluster_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EKS Service"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose     = "eks-secrets"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/atdr-eks-secrets-${var.environment}"
  target_key_id = aws_kms_key.eks_secrets.key_id
}

# EKS 클러스터에 암호화 설정 적용
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.35"

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  # ... 나머지 설정
}
```

### 6.2 S3 버킷 암호화 (SSE-KMS)

```hcl
# terraform/s3/buckets.tf

resource "aws_kms_key" "s3" {
  description             = "S3 버킷 암호화 키"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  tags = {
    Purpose     = "s3-encryption"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/atdr-s3-${var.environment}"
  target_key_id = aws_kms_key.s3.key_id
}

# 포렌식 증거 버킷
resource "aws_s3_bucket" "forensics" {
  bucket = "atdr-forensics-${local.account_id}-${var.environment}"

  tags = {
    Purpose     = "forensics"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true  # 비용 절감: KMS 호출 횟수 감소
  }
}

# Object Lock으로 로그 변조 방지
resource "aws_s3_bucket_object_lock_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

# 퍼블릭 접근 차단
resource "aws_s3_bucket_public_access_block" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 6.3 CloudWatch Logs 암호화

```hcl
# terraform/observability/cloudwatch_kms.tf

resource "aws_kms_key" "cloudwatch" {
  description             = "CloudWatch Logs 암호화 키"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.region}:${local.account_id}:*"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "atdr" {
  name              = "/atdr/application"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.cloudwatch.arn
}

resource "aws_cloudwatch_log_group" "eks_audit" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.cloudwatch.arn
}
```

### 6.4 키 로테이션 정책 요약

| 키 용도 | 로테이션 주기 | 삭제 대기 기간 |
|---------|-------------|--------------|
| EKS Secrets | 90일 | 30일 |
| S3 버킷 | 90일 | 30일 |
| CloudWatch Logs | 365일 | 30일 |

자동 로테이션은 기존 데이터를 재암호화하지 않는다. 새 DEK 생성 시 새 CMK 버전을 사용하고, 기존 데이터는 암호화 당시의 키 버전으로 복호화한다.

---

## 7. 네트워크 보안

### 7.1 Security Groups (최소 포트 개방)

EKS 노드 그룹과 컨트롤 플레인 간 통신에 필요한 포트만 개방한다.

```hcl
# terraform/network/security_groups.tf

# 컨트롤 플레인 Security Group
resource "aws_security_group" "eks_control_plane" {
  name        = "atdr-eks-control-plane-${var.environment}"
  description = "EKS 컨트롤 플레인 Security Group"
  vpc_id      = var.vpc_id

  # 노드에서 API 서버로
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
    description     = "노드 → API 서버"
  }

  egress {
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
    description     = "API 서버 → 노드 (kubelet, webhook)"
  }

  tags = {
    Name        = "atdr-eks-control-plane"
    Environment = var.environment
  }
}

# 노드 Security Group
resource "aws_security_group" "eks_nodes" {
  name        = "atdr-eks-nodes-${var.environment}"
  description = "EKS 노드 Security Group"
  vpc_id      = var.vpc_id

  # 노드 간 통신 (Cilium WireGuard 포함)
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
    description = "노드 간 전체 통신"
  }

  # API 서버에서 kubelet으로
  ingress {
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_control_plane.id]
    description     = "API 서버 → kubelet"
  }

  # WireGuard (Cilium 암호화)
  ingress {
    from_port = 51871
    to_port   = 51871
    protocol  = "udp"
    self      = true
    description = "Cilium WireGuard"
  }

  # Hubble relay
  ingress {
    from_port       = 4244
    to_port         = 4244
    protocol        = "tcp"
    self            = true
    description     = "Hubble relay"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "아웃바운드 전체 허용 (Cilium NetworkPolicy로 세분화)"
  }

  tags = {
    Name        = "atdr-eks-nodes"
    Environment = var.environment
  }
}
```

### 7.2 Private Endpoint Only

EKS API 서버를 퍼블릭으로 노출하지 않는다. 모든 kubectl 접근은 VPN 또는 AWS Systems Manager Session Manager를 통한다.

```hcl
resource "aws_eks_cluster" "main" {
  # ...

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.eks_control_plane.id]
    endpoint_private_access = true
    endpoint_public_access  = false  # 퍼블릭 엔드포인트 비활성화
  }
}
```

### 7.3 Cilium NetworkPolicy (default-deny + allowlist)

네임스페이스 단위로 default-deny를 적용하고, 필요한 트래픽만 명시적으로 허용한다.

```yaml
# k8s/base/policies/default-deny.yaml
# atdr 네임스페이스 default-deny
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny-all
  namespace: atdr
spec:
  endpointSelector: {}  # 네임스페이스 내 모든 Pod
  ingress:
  - {}  # 빈 규칙 = 모든 인그레스 차단
  egress:
  - {}  # 빈 규칙 = 모든 이그레스 차단
---
# DNS 허용 (모든 Pod가 CoreDNS에 접근 가능해야 함)
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-dns
  namespace: atdr
spec:
  endpointSelector: {}
  egress:
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      - port: "53"
        protocol: TCP
```

### 7.4 네임스페이스 격리 정책

```yaml
# k8s/base/policies/namespace-isolation.yaml
# atdr 네임스페이스는 다른 네임스페이스에서 접근 불가
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: namespace-isolation
  namespace: atdr
spec:
  endpointSelector: {}
  ingress:
  # 같은 네임스페이스 내부 통신만 허용
  - fromEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: atdr
  # Prometheus 스크레이핑 허용
  - fromEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: monitoring
        app: prometheus
    toPorts:
    - ports:
      - port: "9090"
        protocol: TCP
  egress:
  # 같은 네임스페이스 내부 통신
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: atdr
  # AWS 서비스 (VPC 엔드포인트 경유)
  - toCIDR:
    - 10.0.0.0/8  # VPC CIDR
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # DNS
  - toEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
```

---

## 8. K8s 1.35 보안 기능

Kubernetes 1.35는 워크로드 보안과 자격증명 관리 측면에서 주목할 만한 기능을 추가했다.

### 8.1 Pod Certificates (beta): 워크로드 mTLS

Pod가 자체 X.509 인증서를 요청하고 갱신할 수 있다. 사이드카 없이 워크로드 간 mTLS를 구현하는 기반이 된다.

```yaml
# Pod Certificates 활성화 (kube-apiserver 플래그)
# --feature-gates=PodCertificates=true

# CertificateSigningRequest를 Pod가 직접 생성
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: atdr-ai-detector-tls
spec:
  request: <base64-encoded-csr>
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400  # 24시간
  usages:
  - client auth
  - server auth
```

ATDR에서는 ai-detector와 correlator 간 통신에 Pod Certificates를 적용해 서비스 메시 없이 mTLS를 구현한다. Cilium의 WireGuard가 노드 간 암호화를 담당하고, Pod Certificates가 서비스 간 인증을 담당하는 이중 구조다.

### 8.2 Fine-Grained Supplemental Groups (GA): Strict mode

`supplementalGroupsPolicy: Strict`를 설정하면 컨테이너 이미지의 `/etc/group`에 정의된 그룹을 무시하고, Pod spec에 명시된 그룹만 적용한다. 이미지에 숨겨진 그룹 권한 상승을 차단한다.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-detector
  namespace: atdr
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    supplementalGroups: [1000]
    supplementalGroupsPolicy: Strict  # GA in 1.35
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: ai-detector
    image: 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/atdr/ai-detector@sha256:abc123
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

### 8.3 Enforced Kubelet Credential Verification (beta)

kubelet이 API 서버에 제출하는 자격증명을 API 서버가 강제 검증한다. 손상된 노드가 다른 노드의 자격증명을 사용하는 공격을 방지한다.

```yaml
# kube-apiserver 설정
# --feature-gates=KubeletCredentialVerification=true
# --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
```

EKS 1.35에서는 이 기능이 관리형으로 활성화된다. 별도 설정 없이 노드 자격증명 검증이 강화된다.

### 8.4 CSI Driver SA Tokens via Secrets Field (beta)

CSI 드라이버가 ServiceAccount 토큰을 Secrets 필드를 통해 안전하게 수신한다. 기존 방식보다 토큰 노출 범위가 줄어든다.

```yaml
# CSIDriver 설정
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: secrets-store.csi.k8s.io
spec:
  tokenRequests:
  - audience: "vault"
    expirationSeconds: 3600
  requiresRepublish: true
  # beta in 1.35: Secrets 필드를 통한 토큰 전달
  podInfoOnMount: true
```

ATDR에서는 AWS Secrets Manager CSI 드라이버를 통해 데이터베이스 자격증명과 API 키를 Pod에 마운트한다. 환경 변수 대신 파일 시스템 마운트를 사용해 `kubectl describe pod`로 시크릿이 노출되지 않도록 한다.

---

## 9. 공급망 보안

컨테이너 이미지는 빌드 시점부터 배포 시점까지 무결성을 보장해야 한다. Sigstore/cosign으로 이미지에 서명하고, SLSA 프로비넌스로 빌드 출처를 검증하며, ECR 스캐닝으로 취약점을 탐지한다.

### 9.1 이미지 서명 (Sigstore/cosign)

```bash
# cosign 설치
brew install cosign

# 키 쌍 생성 (KMS 기반 권장)
cosign generate-key-pair --kms awskms:///alias/atdr-cosign-${ENVIRONMENT}

# 이미지 서명 (CI/CD 파이프라인)
cosign sign \
  --key awskms:///alias/atdr-cosign-${ENVIRONMENT} \
  --annotations "repo=${GITHUB_REPOSITORY}" \
  --annotations "workflow=${GITHUB_WORKFLOW}" \
  --annotations "commit=${GITHUB_SHA}" \
  123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/atdr/ai-detector@sha256:${IMAGE_DIGEST}

# 서명 검증
cosign verify \
  --key awskms:///alias/atdr-cosign-${ENVIRONMENT} \
  123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/atdr/ai-detector@sha256:${IMAGE_DIGEST}
```

ValidatingAdmissionPolicy와 연동해 서명되지 않은 이미지를 배포 시점에 차단한다.

```yaml
# cosign webhook을 통한 서명 검증 정책
# policy-controller (Sigstore)를 사용하는 경우
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: atdr-image-policy
spec:
  images:
  - glob: "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/atdr/**"
  authorities:
  - key:
      kms: awskms:///alias/atdr-cosign-production
    attestations:
    - name: must-have-slsa
      predicateType: https://slsa.dev/provenance/v0.2
```

### 9.2 SLSA 프로비넌스 검증

SLSA(Supply chain Levels for Software Artifacts) Level 2 이상을 목표로 한다. GitHub Actions에서 빌드 프로비넌스를 자동 생성한다.

```yaml
# .github/workflows/build.yml (관련 부분)
jobs:
  build:
    permissions:
      id-token: write
      contents: read
      packages: write

    steps:
    - name: Build and push image
      id: build
      uses: docker/build-push-action@v5
      with:
        push: true
        tags: ${{ env.IMAGE_TAG }}

    - name: Generate SLSA provenance
      uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v1.10.0
      with:
        image: ${{ env.ECR_REGISTRY }}/atdr/ai-detector
        digest: ${{ steps.build.outputs.digest }}
        registry-username: ${{ secrets.ECR_USERNAME }}
      secrets:
        registry-password: ${{ secrets.ECR_PASSWORD }}

    - name: Attest provenance to ECR
      run: |
        cosign attest \
          --key awskms:///alias/atdr-cosign-production \
          --predicate provenance.json \
          --type slsaprovenance \
          ${{ env.ECR_REGISTRY }}/atdr/ai-detector@${{ steps.build.outputs.digest }}
```

### 9.3 ECR 이미지 스캐닝

ECR Enhanced Scanning은 Amazon Inspector를 사용해 OS 패키지와 프로그래밍 언어 패키지의 CVE를 탐지한다.

```hcl
# terraform/ecr/repositories.tf

resource "aws_ecr_repository" "atdr_services" {
  for_each = toset([
    "atdr/ai-detector",
    "atdr/correlator",
    "atdr/response-advisor",
    "atdr/remediation-executor",
    "atdr/dashboard"
  ])

  name                 = each.value
  image_tag_mutability = "IMMUTABLE"  # 태그 덮어쓰기 방지

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.s3.arn
  }

  tags = {
    Environment = var.environment
  }
}

# Enhanced Scanning 활성화 (계정 수준)
resource "aws_ecr_registry_scanning_configuration" "main" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"
    repository_filter {
      filter      = "atdr/*"
      filter_type = "WILDCARD"
    }
  }
}

# 취약점 발견 시 EventBridge로 알림
resource "aws_cloudwatch_event_rule" "ecr_finding" {
  name        = "atdr-ecr-critical-finding"
  description = "ECR Critical/High 취약점 탐지"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      severity = ["CRITICAL", "HIGH"]
      resources = {
        type = ["AWS_ECR_CONTAINER_IMAGE"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "ecr_finding_sns" {
  rule      = aws_cloudwatch_event_rule.ecr_finding.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}
```

### 9.4 공급망 보안 체크리스트

| 항목 | 도구 | 적용 시점 |
|------|------|---------|
| 이미지 서명 | cosign + KMS | CI/CD 빌드 완료 후 |
| SLSA 프로비넌스 | slsa-github-generator | CI/CD 빌드 완료 후 |
| 서명 검증 | policy-controller | 배포 시 (Admission) |
| 다이제스트 핀닝 | ValidatingAdmissionPolicy | 배포 시 (Admission) |
| CVE 스캐닝 | ECR Enhanced Scanning | 푸시 시 + 지속 스캔 |
| 베이스 이미지 최소화 | distroless / scratch | 빌드 시 |
| 의존성 감사 | pip-audit / npm audit | CI/CD 빌드 중 |

---

## 10. 시크릿 관리

ATDR의 시크릿(Slack Bot Token, Bedrock 자격증명, MCP 인증 토큰 등)은 AWS Secrets Manager에 저장하고, Kubernetes 워크로드에는 External Secrets Operator(ESO)로 동기화한다. Lambda는 런타임에 Secrets Manager SDK로 직접 읽는다.

### 10.1 왜 Secrets Manager + ESO인가

Lambda 환경변수에 시크릿을 직접 넣으면 Terraform state 파일에 평문으로 남는다. 보안 프로젝트에서 이러면 신뢰도가 떨어진다.

| 항목 | 환경변수 직접 주입 | SSM Parameter Store | Secrets Manager + ESO |
|------|-------------------|--------------------|-----------------------|
| Terraform state 노출 | 평문 노출 | ARN만 노출 | ARN만 노출 |
| 자동 로테이션 | 불가 | 수동 | 내장 지원 |
| K8s Secret 동기화 | 불가 | ESO 필요 | ESO 네이티브 |
| 감사 로그 | CloudTrail 미기록 | CloudTrail 기록 | CloudTrail 완전 기록 |
| 비용 | 무료 | 무료 | 시크릿당 $0.40/월 |

ATDR에서 관리할 시크릿은 5-6개 수준이므로 월 $2-3이다.

### 10.2 시크릿 목록

| 시크릿 이름 | 용도 | 소비자 |
|------------|------|--------|
| `atdr/slack/bot-token` | Slack Bot OAuth Token | Slack Bot Lambda |
| `atdr/slack/signing-secret` | Slack Request 서명 검증 | API Gateway Lambda |
| `atdr/mcp/auth-token` | EKS MCP 서버 인증 | Remediation Agent |
| `atdr/bedrock/api-config` | Bedrock 엔드포인트 설정 | 모든 Agent Lambda |
| `atdr/opensearch/endpoint` | OpenSearch Serverless 엔드포인트 | Solution Agent |

### 10.3 Terraform 코드

```hcl
resource "aws_secretsmanager_secret" "slack_bot_token" {
  name        = "atdr/slack/bot-token"
  description = "Slack Bot OAuth Token"

  tags = {
    Project = "atdr"
  }
}

resource "aws_secretsmanager_secret" "slack_signing_secret" {
  name        = "atdr/slack/signing-secret"
  description = "Slack Request Signing Secret"

  tags = {
    Project = "atdr"
  }
}

resource "aws_secretsmanager_secret" "mcp_auth_token" {
  name        = "atdr/mcp/auth-token"
  description = "EKS MCP Server Auth Token"

  tags = {
    Project = "atdr"
  }
}
```

시크릿 값은 Terraform으로 관리하지 않는다. `aws secretsmanager put-secret-value` CLI로 수동 설정한다.

```bash
aws secretsmanager put-secret-value \
  --secret-id atdr/slack/bot-token \
  --secret-string '{"token":"xoxb-..."}'
```

### 10.4 Lambda에서 시크릿 읽기

Lambda 환경변수에는 시크릿 ARN만 넣고, 런타임에 Secrets Manager SDK로 실제 값을 가져온다.

```python
import boto3
import json
from functools import lru_cache

secrets_client = boto3.client("secretsmanager")

@lru_cache(maxsize=8)
def get_secret(secret_id: str) -> dict:
    response = secrets_client.get_secret_value(SecretId=secret_id)
    return json.loads(response["SecretString"])

def lambda_handler(event, context):
    slack_config = get_secret("atdr/slack/bot-token")
    token = slack_config["token"]
```

`@lru_cache`로 Lambda 실행 컨텍스트 내에서 동일 시크릿을 반복 조회하지 않는다.

### 10.5 External Secrets Operator (K8s 워크로드용)

ESO가 Secrets Manager의 값을 Kubernetes Secret으로 자동 동기화한다.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: mcp-auth
  namespace: atdr
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: mcp-auth-token
    creationPolicy: Owner
  data:
  - secretKey: token
    remoteRef:
      key: atdr/mcp/auth-token
      property: token
---
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-manager
spec:
  provider:
    aws:
      service: SecretsManager
      region: ap-northeast-2
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets
```

ESO의 ServiceAccount는 Pod Identity로 Secrets Manager 읽기 권한을 부여한다.

---

## 참고

- [Cilium 1.19 릴리스 노트](https://github.com/cilium/cilium/releases/tag/v1.19.0)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [EKS Access Entry](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html)
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
- [Sigstore cosign](https://docs.sigstore.dev/cosign/overview/)
- [SLSA Framework](https://slsa.dev/)

