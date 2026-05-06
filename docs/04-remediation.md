# 04. 자동 대응 설계 (Automated Remediation)

## 1. 자동 대응 전략 개요

### 탐지에서 피드백까지

ATDR의 대응 파이프라인은 여섯 단계로 순환한다.

```
탐지 → 분석 → 승인 → 실행 → 검증 → 피드백
```

각 단계는 다음 역할을 맡는다.

| 단계 | 담당 컴포넌트 | 출력 |
|------|-------------|------|
| 탐지 | ai-detector, correlator | 인시던트 이벤트 + 심각도(P1~P4) |
| 분석 | response-advisor | 대응 액션 후보 목록 + 우선순위 |
| 승인 | Slack 봇 / 자동 실행 정책 | 승인 토큰 또는 자동 실행 플래그 |
| 실행 | Remediation Agent (MCP) | K8s API 호출 결과 |
| 검증 | Remediation Agent | 대응 후 상태 확인 |
| 피드백 | Runbook Updater | S3 런북 갱신 |

### Human-in-the-loop vs 자동 실행

심각도와 액션 위험도를 기준으로 실행 경로를 나눈다.

```
P1 (Critical) ─── 즉시 Slack 알림 + 승인 대기 (타임아웃 5분 → 자동 격리)
P2 (High)     ─── Slack 알림 + 승인 대기 (타임아웃 15분 → 에스컬레이션)
P3 (Medium)   ─── 자동 실행 (설정으로 승인 요구 가능)
P4 (Low)      ─── 자동 실행 + 로그 기록
```

자동 실행 허용 여부는 `remediation-config.yaml`의 `auto_execute_threshold` 값으로 조정한다. 기본값은 P3 이하 자동 실행이다.

파드 삭제, RBAC 수정, 노드 드레인처럼 서비스 영향이 큰 액션은 심각도와 무관하게 항상 승인을 요구하도록 `require_approval_actions` 목록에 명시한다.

---

## 2. EKS MCP (Model Context Protocol)

### MCP란

MCP(Model Context Protocol)는 AI 에이전트가 외부 도구와 상호작용하는 표준 인터페이스다. Remediation Agent는 MCP 서버를 통해 Kubernetes API에 접근한다. 에이전트가 직접 `kubectl`을 실행하거나 kubeconfig를 관리하지 않아도 된다.

```
Remediation Agent (LLM)
        │
        │  MCP 프로토콜 (JSON-RPC over stdio/HTTP)
        ▼
   EKS MCP Server
        │
│  K8s API (in-cluster ServiceAccount + EKS Pod Identity)
        ▼
   EKS Control Plane
```

MCP 서버는 EKS 클러스터 내부에서 실행된다. AWS 권한이 필요한 경우 IRSA가 아니라 EKS Pod Identity를 사용하고, Kubernetes 권한은 ServiceAccount + RBAC로 제한한다. Lambda는 Kubernetes API, kubeconfig, `kubectl`을 직접 사용하지 않는다.

### MCP 도구 목록

| 도구 이름 | 설명 | 필요 권한 |
|----------|------|----------|
| `delete_pod` | 파드 삭제 (재시작 트리거) | `pods:delete` |
| `label_pod` | 파드 레이블 추가/수정 (Tetragon 격리용) | `pods:patch` |
| `checkpoint_pod` | Pod 스냅샷/로그를 S3 포렌식 버킷에 저장 | `pods:get`, `pods/log:get`, `s3:PutObject` |
| `apply_cilium_network_policy` | CiliumNetworkPolicy 생성 또는 수정 | `ciliumnetworkpolicies:create,update` |
| `patch_deployment` | Deployment 스펙 수정 (replicas 등) | `deployments:patch` |
| `cordon_node` | 노드 스케줄링 비활성화 | `nodes:patch` |
| `drain_node` | 노드 드레인 | `nodes:patch`, `pods:evict` |
| `capture_hubble_flows` | CiliumEndpoint/Hubble 증거 스냅샷을 S3에 저장 | `ciliumendpoints:list`, `s3:PutObject` |

자동 대응 문서의 실행 예시는 MCP 호출을 기준으로 한다. `kubectl` 명령은 운영자 수동 검증 또는 break-glass 상황에만 사용한다.

---

## 3. 대응 액션 상세

### 3.1 파드 격리 (Checkpoint → Tetragon → CiliumNetworkPolicy → 삭제)

**트리거 조건**
- 파드에서 비정상 아웃바운드 트래픽 탐지
- 알 수 없는 외부 IP로의 반복 연결
- 비콘 패턴 또는 C2 통신 의심
- 컨테이너 내부에서 악성 프로세스 실행 탐지

**격리 전략: Checkpoint First, Kill Second**

표준 Kubernetes NetworkPolicy는 기존 TCP 연결을 끊지 않는다. 새 연결만 차단한다. CiliumNetworkPolicy도 마찬가지다. 즉시 차단이 필요하면 Tetragon SIGKILL + Pod 삭제를 조합해야 한다.

동시에 포렌식 증거를 보존해야 하므로, 격리 전에 Container Checkpoint와 Hubble 플로우를 캡처한다.

```
실행 순서:

1. MCP forensics snapshot 저장 (1-2초)
   - Pod manifest, 최근 컨테이너 로그, CiliumEndpoint/Hubble 증거를 S3에 저장

2. Tetragon SIGKILL label 적용 (< 100ms)
   - Pod에 security.incident/compromised=true 레이블 추가
   - 사전 배포된 TracingPolicy가 해당 레이블의 아웃바운드 연결을 즉시 SIGKILL

3. CiliumNetworkPolicy deny-all 적용 (< 1초)
   - 새 인바운드/아웃바운드 연결 차단

4. Pod 강제 삭제 + Deployment scale 0 (< 2초)
   - 기존 연결 종료
   - Deployment가 새 Pod를 재생성하지 않도록 replicas=0
```

**Step 1: MCP forensics snapshot**

```json
{"tool":"checkpoint_pod","arguments":{"pod_name":"payment-service-7d9f8b-xk2p9","namespace":"production"}}
{"tool":"capture_hubble_flows","arguments":{"pod_name":"payment-service-7d9f8b-xk2p9","namespace":"production"}}
```

**Step 2: Tetragon SIGKILL label**

사전에 클러스터에 배포해 둔 TracingPolicy가 `security.incident/compromised=true` 레이블이 붙은 Pod의 아웃바운드 TCP 연결을 즉시 SIGKILL한다.

```yaml
# 사전 배포: Tetragon TracingPolicy
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: kill-compromised-outbound
spec:
  podSelector:
    matchLabels:
      security.incident/compromised: "true"
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "127.0.0.1"
      matchActions:
      - action: Sigkill
```

```json
{"tool":"label_pod","arguments":{"pod_name":"payment-service-7d9f8b-xk2p9","namespace":"production","labels":{"security.incident/compromised":"true"}}}
```

**Step 3: CiliumNetworkPolicy deny-all**

```json
{"tool":"apply_cilium_network_policy","arguments":{"policy_name":"isolate-compromised-pod","namespace":"production","pod_selector":{"security.incident/compromised":"true"},"deny_all":true}}
```

**Step 4: Pod 삭제 + Deployment scale 0**

```json
{"tool":"delete_pod","arguments":{"pod_name":"payment-service-7d9f8b-xk2p9","namespace":"production","force":true,"grace_period_seconds":0}}
{"tool":"patch_deployment","arguments":{"deployment_name":"payment-service","namespace":"production","replicas":0}}
```

**검증 방법**

```bash
# CiliumNetworkPolicy 적용 확인
kubectl get ciliumnetworkpolicy isolate-compromised-pod -n production

# Pod 종료 확인
kubectl get pods -n production -l app=payment-service

# Deployment replicas 0 확인
kubectl get deployment payment-service -n production -o jsonpath='{.spec.replicas}'

# 포렌식 증거 저장 확인
aws s3 ls s3://atdr-forensics/checkpoints/inc-20260504-001/
```

---

### 3.2 네임스페이스 격리 (default-deny CiliumNetworkPolicy)

**트리거 조건**
- 네임스페이스 내 여러 파드에서 동시 이상 행동
- 네임스페이스 간 비정상 lateral movement 탐지
- 네임스페이스 전체가 침해된 것으로 판단

**실행 방법**

네임스페이스에 default-deny NetworkPolicy를 적용해 모든 인그레스/이그레스를 차단한다. 이후 허용이 필요한 트래픽만 별도 정책으로 열어준다.

**kubectl 예시**

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: compromised-ns
  labels:
    atdr.juany.dev/managed: "true"
    atdr.juany.dev/incident-id: "inc-20260504-002"
spec:
  podSelector: {}   # 네임스페이스 내 모든 파드
  policyTypes:
  - Ingress
  - Egress
EOF
```

**검증 방법**

```bash
# 정책 적용 확인
kubectl get networkpolicy default-deny-all -n compromised-ns

# 네임스페이스 내 파드 간 통신 차단 확인
kubectl exec -n compromised-ns pod-a -- \
  curl --connect-timeout 3 http://pod-b-service || echo "blocked"
```

---

### 3.4 RBAC 수정 (ClusterRoleBinding 제거/수정)

**트리거 조건**
- 서비스 어카운트가 과도한 권한으로 API 서버에 접근
- 비정상적인 ClusterAdmin 권한 사용 탐지
- 권한 상승 시도 (privilege escalation) 탐지

**실행 방법**

`delete_cluster_role_binding` 또는 `patch_cluster_role_binding` 도구로 문제가 된 바인딩을 제거하거나 최소 권한으로 교체한다. 삭제 전 현재 바인딩 상태를 S3에 백업한다.

**kubectl 예시**

```bash
# 현재 바인딩 백업
kubectl get clusterrolebinding suspicious-admin-binding -o yaml > backup.yaml

# ClusterRoleBinding 삭제
kubectl delete clusterrolebinding suspicious-admin-binding

# 또는 최소 권한 Role로 교체
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: suspicious-admin-binding
  labels:
    atdr.juany.dev/modified: "true"
subjects:
- kind: ServiceAccount
  name: payment-service
  namespace: production
roleRef:
  kind: ClusterRole
  name: view          # cluster-admin → view로 다운그레이드
  apiGroup: rbac.authorization.k8s.io
EOF
```

**검증 방법**

```bash
# 권한 변경 확인
kubectl auth can-i list secrets \
  --as=system:serviceaccount:production:payment-service

# 감사 로그에서 해당 서비스 어카운트 API 호출 모니터링
```

---

### 3.5 시크릿 로테이션

**트리거 조건**
- 시크릿 값이 외부로 유출된 것으로 의심
- 파드 환경변수에서 시크릿 접근 후 비정상 외부 통신
- 시크릿을 마운트한 파드가 침해됨

**실행 방법**

`rotate_secret` 도구가 새 값을 생성해 Secret을 업데이트한다. 시크릿 종류에 따라 외부 시스템(DB, API 키 발급처)에도 변경을 전파해야 한다. 이 단계는 자동화 범위 밖이므로 Slack으로 운영자에게 알린다.

**kubectl 예시**

```bash
# 새 시크릿 값으로 업데이트
kubectl create secret generic db-credentials \
  --from-literal=password="$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubectl apply -f -

# 시크릿을 사용하는 파드 재시작 (새 값 반영)
kubectl rollout restart deployment/payment-service -n production
```

**검증 방법**

```bash
# 롤아웃 완료 확인
kubectl rollout status deployment/payment-service -n production

# 새 파드가 새 시크릿을 사용하는지 확인
kubectl exec -n production \
  $(kubectl get pod -n production -l app=payment-service -o name | head -1) \
  -- env | grep DB_PASSWORD
```

---

### 3.6 노드 코든/드레인

**트리거 조건**
- 노드 수준 침해 의심 (컨테이너 탈출, 호스트 프로세스 이상)
- 노드에서 실행 중인 여러 파드가 동시에 이상 행동
- 노드 자체의 무결성 검증 실패

**실행 방법**

먼저 `cordon_node`로 새 파드 스케줄링을 막고, `drain_node`로 기존 파드를 다른 노드로 이동시킨다. 드레인 후 노드는 포렌식 분석을 위해 격리 상태로 유지한다.

**kubectl 예시**

```bash
# 노드 코든 (새 파드 스케줄링 차단)
kubectl cordon ip-10-0-1-42.ap-northeast-2.compute.internal

# 노드 드레인 (기존 파드 이동)
kubectl drain ip-10-0-1-42.ap-northeast-2.compute.internal \
  --ignore-daemonsets \
  --delete-emptydir-data \
  --grace-period=60
```

**검증 방법**

```bash
# 노드 상태 확인 (SchedulingDisabled)
kubectl get node ip-10-0-1-42.ap-northeast-2.compute.internal

# 해당 노드에 남은 파드 확인 (DaemonSet 제외)
kubectl get pods --all-namespaces \
  --field-selector spec.nodeName=ip-10-0-1-42.ap-northeast-2.compute.internal
```

---

### 3.7 스케일 다운/업

**트리거 조건**
- 스케일 다운: 침해된 Deployment의 모든 레플리카를 즉시 중단
- 스케일 업: 격리 후 정상 파드로 서비스 용량 복구

**실행 방법**

`patch_deployment` 도구로 `spec.replicas`를 수정한다. 스케일 다운 시 0으로 설정하면 파드가 모두 종료된다.

**kubectl 예시**

```bash
# 스케일 다운 (모든 레플리카 종료)
kubectl scale deployment payment-service -n production --replicas=0

# 대응 완료 후 스케일 업 (서비스 복구)
kubectl scale deployment payment-service -n production --replicas=3
```

**검증 방법**

```bash
# 스케일 다운 확인
kubectl get deployment payment-service -n production

# 스케일 업 후 파드 Ready 상태 확인
kubectl wait --for=condition=ready pod \
  -l app=payment-service -n production --timeout=120s
```

---

## 4. 승인 워크플로우

### 심각도별 처리 경로

```
인시던트 생성
     │
     ├─ P1/P2 ──→ Slack 알림 발송 → 승인 대기
     │                │
     │                ├─ 승인 → 즉시 실행
     │                ├─ 거부 → 실행 취소 + 로그
     │                └─ 타임아웃 → 아래 참조
     │
     └─ P3/P4 ──→ 자동 실행 → 결과 Slack 알림
```

### 타임아웃 처리

| 심각도 | 타임아웃 | 타임아웃 후 동작 |
|--------|---------|----------------|
| P1 | 5분 | 최소 격리 액션 자동 실행 (NetworkPolicy deny-all) + 에스컬레이션 |
| P2 | 15분 | 에스컬레이션 채널로 재알림 + 추가 15분 대기 |
| P3 | 해당 없음 | 자동 실행 |
| P4 | 해당 없음 | 자동 실행 |

P1 타임아웃 시 자동으로 실행되는 최소 격리 액션은 서비스 중단을 최소화하면서 확산을 막는 수준으로 제한한다. 파드 삭제나 RBAC 수정처럼 복구가 복잡한 액션은 타임아웃 자동 실행 목록에서 제외한다.

### 승인 상태 관리

승인 요청은 DynamoDB에 다음 구조로 저장된다.

```json
{
  "approval_id": "appr-20260504-001",
  "incident_id": "inc-20260504-001",
  "action": "apply_network_policy",
  "target": "payment-service/production",
  "severity": "P1",
  "requested_at": "2026-05-04T10:00:00Z",
  "expires_at": "2026-05-04T10:05:00Z",
  "status": "pending",
  "requested_by": "response-advisor",
  "slack_message_ts": "1746345600.123456",
  "slack_channel": "C0123456789"
}
```

승인/거부 시 `status`를 `approved` 또는 `denied`로 업데이트하고, 실행 결과를 `execution_result` 필드에 기록한다.

---

## 5. 런북 업데이트 피드백 루프

### 개요

대응 실행 후 결과를 S3에 저장된 런북에 반영한다. 이 피드백 루프는 시스템이 반복되는 인시던트에서 점진적으로 개선되도록 한다.

```
대응 실행 완료
     │
     ▼
결과 수집 (성공/실패, 소요 시간, 부작용)
     │
     ▼
S3 런북 조회 (s3://atdr-runbooks/{threat_type}.json)
     │
     ▼
결과 반영 (성공률, 평균 소요 시간, 주의사항 업데이트)
     │
     ▼
런북 버전 업데이트 + 변경 이력 기록
```

### 런북 구조

```json
{
  "runbook_id": "rb-network-anomaly-001",
  "threat_type": "abnormal_outbound_traffic",
  "version": "1.3",
  "last_updated": "2026-05-04T10:30:00Z",
  "recommended_actions": [
    {
      "action": "apply_network_policy",
      "priority": 1,
      "success_rate": 0.94,
      "avg_execution_time_seconds": 8,
      "notes": "파드 레이블이 없는 경우 적용 실패. 레이블 확인 필수."
    },
    {
      "action": "delete_pod",
      "priority": 2,
      "success_rate": 0.99,
      "avg_execution_time_seconds": 15,
      "notes": "Deployment 없는 standalone 파드는 재생성 안 됨."
    }
  ],
  "execution_history": [
    {
      "incident_id": "inc-20260504-001",
      "executed_at": "2026-05-04T10:00:00Z",
      "action": "apply_network_policy",
      "result": "success",
      "duration_seconds": 7,
      "operator": "auto"
    }
  ]
}
```

### 성공/실패 기록 기준

| 결과 | 판단 기준 |
|------|---------|
| success | 검증 단계에서 기대 상태 확인, 이상 행동 중단 |
| partial | 액션은 성공했으나 이상 행동이 다른 경로로 지속 |
| failure | K8s API 오류, 권한 부족, 타임아웃 |
| rollback | 대응 후 서비스 장애 발생으로 원복 |

---

## 6. 대응 액션 YAML 예시

### NetworkPolicy: 파드 격리

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-compromised-pod
  namespace: production
  labels:
    atdr.juany.dev/managed: "true"
    atdr.juany.dev/incident-id: "inc-20260504-001"
    atdr.juany.dev/action: "pod-isolation"
  annotations:
    atdr.juany.dev/created-at: "2026-05-04T10:00:00Z"
    atdr.juany.dev/expires-at: "2026-05-04T22:00:00Z"
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
  - Ingress
  - Egress
  # 규칙 없음 = 모든 트래픽 차단
```

### NetworkPolicy: 네임스페이스 default-deny

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: compromised-ns
  labels:
    atdr.juany.dev/managed: "true"
    atdr.juany.dev/action: "namespace-isolation"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### NetworkPolicy: 격리 후 허용 정책 (모니터링 트래픽만)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-only
  namespace: compromised-ns
  labels:
    atdr.juany.dev/managed: "true"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    ports:
    - protocol: TCP
      port: 9090   # Prometheus scrape
```

### RBAC: 최소 권한으로 교체

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payment-service-binding
  labels:
    atdr.juany.dev/modified: "true"
    atdr.juany.dev/original-role: "cluster-admin"
    atdr.juany.dev/incident-id: "inc-20260504-003"
subjects:
- kind: ServiceAccount
  name: payment-service
  namespace: production
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

### RBAC: 격리용 최소 Role

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: quarantine-readonly
  namespace: production
  labels:
    atdr.juany.dev/managed: "true"
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
  # 쓰기 권한 없음
```
