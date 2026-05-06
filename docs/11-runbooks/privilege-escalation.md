# 권한 상승 (Privilege Escalation)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 컨테이너 내부에서 root 권한을 획득하거나, 권한 있는 컨테이너를 통해 호스트 노드 수준의 접근권을 확보하는 공격이다. 컨테이너 탈출의 전 단계로 이어지는 경우가 많아 즉각 대응이 필요하다.

- MITRE ATT&CK: T1611 Escape to Host, T1548 Abuse Elevation Control Mechanism
- 심각도: P1 (Critical)

---

## 탐지 시그널

**GuardDuty Finding**
- `PrivilegeEscalation:EKS/PrivilegedContainer` - 권한 있는 컨테이너에서 권한 상승 시도
- `PrivilegeEscalation:EKS/AnomalousBehavior` - 비정상적인 권한 상승 패턴
- `Execution:EKS/ExecInPod` - 실행 중인 pod에 대한 kubectl exec

**Falco Rule**
- `Privilege Escalation via setresuid` - setresuid syscall로 root 전환 시도
- `Privileged Container Spawned` - 권한 있는 컨테이너에서 셸 실행
- `Container Run as Root User` - root로 실행 중인 컨테이너 탐지
- `Sudo Potential Privilege Escalation` - sudo 실행 시도

**Tetragon TracingPolicy**
- `detect-privilege-escalation` - setuid/setgid syscall 이벤트

**기타 지표**
- `securityContext.privileged: true`인 pod 생성
- `hostPID: true`, `hostNetwork: true`, `hostIPC: true` 설정된 pod
- `/proc/1/environ` 또는 `/etc/shadow` 접근 시도
- capabilities 추가 (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN` 등)

---

## 초기 분석

**확인할 정보**
- pod의 securityContext 설정
- 실행 중인 프로세스의 UID/GID
- 마운트된 볼륨 (hostPath 여부)
- 해당 pod의 ServiceAccount 권한
- kubectl exec 실행 주체 (audit log)

**kubectl 명령어**

```bash
# pod securityContext 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.securityContext}'
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext}'

# 권한 있는 컨테이너 전체 목록 조회
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  [.metadata.namespace, .metadata.name] | @tsv'

# hostPath 마운트 사용 pod 조회
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath != null) |
  [.metadata.namespace, .metadata.name] | @tsv'

# 컨테이너 내 현재 사용자 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- id

# 컨테이너 내 capabilities 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /proc/1/status | grep Cap

# audit log에서 kubectl exec 이벤트 확인 (CloudWatch)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "create" && $.objectRef.subresource = "exec" }' \
  --start-time $(date -d '1 hour ago' +%s000)
```

**로그 확인 위치**
- CloudWatch Logs: `/aws/eks/<CLUSTER_NAME>/cluster` (audit log에서 exec 이벤트)
- GuardDuty Findings: PrivilegeEscalation 유형 필터링
- Falco 로그: `kubectl logs -n falco ds/falco | grep -i privilege`

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

P1이므로 탐지 즉시 네트워크 격리를 실행한다. Slack 승인을 기다리지 않고 격리부터 진행한다.

```bash
# pod 즉시 네트워크 격리
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-<POD_NAME>
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      <POD_LABEL_KEY>: <POD_LABEL_VALUE>
  policyTypes:
  - Ingress
  - Egress
EOF

# kubectl exec 차단을 위해 해당 ServiceAccount의 exec 권한 즉시 제거
kubectl get rolebinding,clusterrolebinding -A -o json | jq -r '
  .items[] |
  select(.subjects[]?.name == "<SERVICE_ACCOUNT_NAME>") |
  [.kind, .metadata.namespace // "cluster", .metadata.name] | @tsv'
```

### 2단계: 증거 수집

```bash
# 현재 프로세스 트리 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf > /tmp/evidence-ps-$(date +%s).txt

# 컨테이너 내 사용자 및 권한 정보 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- id > /tmp/evidence-id-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /proc/1/status >> /tmp/evidence-id-$(date +%s).txt

# 마운트 정보 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- mount > /tmp/evidence-mount-$(date +%s).txt

# pod 전체 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# audit log에서 해당 pod 관련 이벤트 수집
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.objectRef.name = \"<POD_NAME>\" }" \
  --start-time $(date -d '2 hours ago' +%s000) \
  > /tmp/evidence-auditlog-$(date +%s).json

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# pod를 생성한 주체 확인 (audit log)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "create" && $.objectRef.resource = "pods" && $.objectRef.name = "<POD_NAME>" }' \
  --start-time $(date -d '24 hours ago' +%s000)

# Deployment/StatefulSet의 securityContext 설정 확인
kubectl get deployment <DEPLOYMENT_NAME> -n <NAMESPACE> -o jsonpath='{.spec.template.spec.securityContext}'
kubectl get deployment <DEPLOYMENT_NAME> -n <NAMESPACE> -o jsonpath='{.spec.template.spec.containers[*].securityContext}'

# PodSecurityPolicy 또는 OPA/Gatekeeper 정책 확인
kubectl get psp 2>/dev/null
kubectl get constrainttemplate 2>/dev/null

# RBAC에서 privileged pod 생성 허용 여부 확인
kubectl auth can-i create pods --as=system:serviceaccount:<NAMESPACE>:<SERVICE_ACCOUNT> -n <NAMESPACE>
```

### 4단계: 복구

```bash
# 감염된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# Deployment securityContext 수정 (privileged 제거)
kubectl patch deployment <DEPLOYMENT_NAME> -n <NAMESPACE> --type=json -p='[
  {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/privileged"},
  {"op": "add", "path": "/spec/template/spec/securityContext/runAsNonRoot", "value": true},
  {"op": "add", "path": "/spec/template/spec/securityContext/runAsUser", "value": 1000}
]'

# 롤아웃 상태 확인
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 격리 NetworkPolicy 제거
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>
```

### 5단계: 사후 조치

```bash
# 클러스터 전체 privileged pod 재점검
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  [.metadata.namespace, .metadata.name, .spec.containers[].image] | @tsv'

# OPA Gatekeeper로 privileged pod 생성 차단 정책 적용
kubectl apply -f - <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: psp-privileged-container
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "falco", "tetragon"]
EOF

# 관련 RBAC 정책 감사
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  [.metadata.name, (.subjects[]? | .kind + "/" + .name)] | @tsv'
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 즉시 네트워크 격리 (승인 없이 자동 실행)
2. `get_pod` - pod securityContext 및 마운트 정보 수집
3. `delete_pod` - 격리 후 pod 삭제
4. `patch_deployment` - securityContext에서 privileged 플래그 제거
5. `delete_cluster_role_binding` - 과도한 권한의 ClusterRoleBinding 제거 (별도 승인 필요)

승인 필요 여부: P1이므로 Slack 승인 필요. `apply_network_policy`와 `delete_pod`는 즉시 자동 실행. `patch_deployment`와 RBAC 변경은 승인 후 실행. 5분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 새 pod가 non-root로 실행 중인지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- id

# privileged 플래그 제거 확인
kubectl get pod <NEW_POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext}'

# 네트워크 격리 해제 후 정상 트래픽 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- curl -s http://kubernetes.default.svc/healthz

# Falco에서 추가 권한 상승 이벤트 없는지 확인
kubectl logs -n falco ds/falco --since=5m | grep -i privilege
```

---

## 에스컬레이션

자동 대응 실패 또는 5분 내 Slack 승인 없을 때:

1. 해당 노드를 즉시 cordon해 추가 pod 스케줄링을 차단한다.

```bash
NODE_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}')
kubectl cordon $NODE_NAME
```

2. 호스트 접근이 확인된 경우 노드를 drain하고 교체한다.

```bash
kubectl drain $NODE_NAME --ignore-daemonsets --delete-emptydir-data --force

# ASG에서 인스턴스 교체
INSTANCE_ID=$(kubectl get node $NODE_NAME -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id $INSTANCE_ID \
  --should-decrement-desired-capacity false
```

3. 담당자 연락: Slack `#security-incidents` 채널. P1 인시던트이므로 즉시 응답 필요.
