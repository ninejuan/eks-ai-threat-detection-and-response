# 컨테이너 탈출 (Container Escape)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 컨테이너 격리 경계를 돌파해 호스트 노드에 접근하는 공격이다. 권한 있는 컨테이너, hostPath 마운트, 커널 취약점, runc 취약점 등을 통해 발생한다. 성공 시 해당 노드의 모든 컨테이너와 노드 자체가 침해된다.

- MITRE ATT&CK: T1611 Escape to Host
- 심각도: P1 (Critical)

---

## 탐지 시그널

**GuardDuty Finding**
- `PrivilegeEscalation:EKS/PrivilegedContainer` - 권한 있는 컨테이너에서 탈출 시도
- `PrivilegeEscalation:EKS/ContainerMounts` - 민감한 호스트 경로 마운트 후 접근
- `Execution:EKS/HostAssumption` - 컨테이너에서 호스트 프로세스 네임스페이스 접근
- `Impact:EKS/MaliciousIPCaller` - 탈출 후 호스트에서 악성 IP 연결

**Falco Rule**
- `Container Escape via Privileged Pod` - 권한 있는 컨테이너에서 호스트 파일시스템 접근
- `Write to Host Path from Container` - hostPath 마운트를 통한 호스트 파일 수정
- `Mount Sensitive Host Paths` - `/proc`, `/sys`, `/dev` 등 민감 경로 마운트
- `Namespace Escape Detected` - PID/네트워크 네임스페이스 탈출 시도
- `Read Sensitive File Untrusted` - 호스트의 `/etc/shadow`, kubeconfig 등 접근

**Tetragon TracingPolicy**
- `detect-container-escape` - 호스트 파일시스템 접근 및 네임스페이스 전환 이벤트
- `block-host-path-write` - hostPath를 통한 호스트 파일 쓰기 차단

**기타 지표**
- 컨테이너 내에서 `/host/`, `/proc/1/root/` 경로 접근
- `nsenter` 명령 실행 (호스트 네임스페이스 진입)
- `chroot` 명령으로 호스트 루트 파일시스템 진입
- 컨테이너 내에서 호스트 프로세스 목록 조회 (`ps aux`에 호스트 프로세스 포함)
- Docker 소켓(`/var/run/docker.sock`) 또는 containerd 소켓 접근
- 호스트 노드의 kubelet 자격증명 파일 접근

---

## 초기 분석

**확인할 정보**
- 탈출에 사용된 벡터 (privileged, hostPath, 소켓 마운트 등)
- 호스트 접근 성공 여부
- 호스트에서 실행된 명령 이력
- 동일 노드의 다른 컨테이너 영향 여부
- 노드의 kubelet 자격증명 노출 여부

**kubectl 명령어**

```bash
# pod의 securityContext 및 볼륨 마운트 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o json | jq '{
  privileged: .spec.containers[].securityContext.privileged,
  hostPID: .spec.hostPID,
  hostNetwork: .spec.hostNetwork,
  hostIPC: .spec.hostIPC,
  volumes: [.spec.volumes[]? | select(.hostPath != null) | {name: .name, path: .hostPath.path}]
}'

# 컨테이너 내에서 호스트 파일시스템 접근 여부 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ls /host/ 2>/dev/null
kubectl exec <POD_NAME> -n <NAMESPACE> -- ls /proc/1/root/ 2>/dev/null

# 컨테이너 내 마운트 목록 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- mount | grep -v 'overlay\|tmpfs\|proc\|sys\|dev'

# 호스트 프로세스 접근 여부 확인 (hostPID=true 시 호스트 프로세스 보임)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps aux | wc -l

# 컨테이너 내 capabilities 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /proc/1/status | grep -E 'CapPrm|CapEff|CapBnd'

# 동일 노드의 다른 pod 목록
NODE_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}')
kubectl get pods -A --field-selector spec.nodeName=$NODE_NAME
```

**호스트 접근 성공 여부 판단**

```bash
# 컨테이너에서 호스트 파일 접근 시도 흔적 (Falco 로그)
kubectl logs -n falco ds/falco --since=2h | grep -iE 'escape|host|nsenter|chroot'

# Tetragon 이벤트에서 네임스페이스 전환 확인
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --pods <POD_NAME> 2>/dev/null | grep -iE 'nsenter|chroot|escape'

# 노드에서 비정상 프로세스 실행 여부 (노드 직접 접근 가능한 경우)
# SSM Session Manager를 통한 노드 접근
aws ssm start-session --target <INSTANCE_ID>
```

**로그 확인 위치**
- Falco 로그: `kubectl logs -n falco ds/falco | grep -iE 'escape|host path|privileged'`
- Tetragon 이벤트: 네임스페이스 전환 이벤트
- GuardDuty Findings: PrivilegeEscalation 유형
- CloudWatch: 노드 수준 시스템 로그 (`/aws/ec2/...`)

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

컨테이너 탈출은 노드 전체 침해로 이어질 수 있다. 해당 pod 격리와 동시에 노드 격리를 진행한다.

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

# 해당 노드 즉시 cordon (신규 pod 스케줄링 차단)
NODE_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}')
kubectl cordon $NODE_NAME

# 노드의 다른 pod들을 다른 노드로 이동 (drain)
# 주의: 서비스 영향 있음. 승인 후 실행 권장
kubectl drain $NODE_NAME --ignore-daemonsets --delete-emptydir-data --force
```

### 2단계: 증거 수집

```bash
# 컨테이너 내 증거 수집 (탈출 전)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf > /tmp/evidence-ps-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- mount > /tmp/evidence-mount-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- find /host /proc/1/root -maxdepth 3 -type f 2>/dev/null \
  > /tmp/evidence-hostfiles-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null \
  > /tmp/evidence-history-$(date +%s).txt

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# 동일 노드의 모든 pod 목록 저장
kubectl get pods -A --field-selector spec.nodeName=$NODE_NAME -o yaml \
  > /tmp/evidence-node-pods-$(date +%s).yaml

# Falco 로그 저장
kubectl logs -n falco ds/falco --since=4h | grep -E "$NODE_NAME|<POD_NAME>" \
  > /tmp/evidence-falco-$(date +%s).txt

# Tetragon 이벤트 저장
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o json --pods <POD_NAME> 2>/dev/null \
  > /tmp/evidence-tetragon-$(date +%s).json

# 노드 수준 증거 (SSM을 통해 노드 접근 가능한 경우)
aws ssm send-command \
  --instance-ids <INSTANCE_ID> \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ps auxf > /tmp/host-ps.txt && last > /tmp/host-last.txt && find /tmp /var/tmp -newer /proc/1 -type f 2>/dev/null > /tmp/host-tmpfiles.txt"]' \
  --output-s3-bucket-name atdr-evidence-bucket \
  --output-s3-key-prefix "incidents/<INCIDENT_ID>/node/"

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 탈출 벡터 파악

# 1) Privileged container 여부
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext.privileged}'

# 2) hostPath 마운트 여부 및 경로
kubectl get pod <POD_NAME> -n <NAMESPACE> -o json | \
  jq '.spec.volumes[] | select(.hostPath != null) | .hostPath.path'

# 3) 소켓 마운트 여부
kubectl get pod <POD_NAME> -n <NAMESPACE> -o json | \
  jq '.spec.volumes[] | select(.hostPath.path | test("docker.sock|containerd.sock|cri.sock"))'

# 4) 커널 취약점 익스플로잇 여부 (Tetragon 이벤트 분석)
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o json 2>/dev/null | \
  jq 'select(.process_kprobe.function_name | test("commit_creds|prepare_kernel_cred"))'

# pod 생성 주체 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "create" && $.objectRef.resource = "pods" && $.objectRef.name = "<POD_NAME>" }' \
  --start-time $(date -d '48 hours ago' +%s000)

# 노드 kubelet 자격증명 노출 여부 확인
# kubelet 자격증명으로 API 호출 이력 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.user.username = "system:node:<NODE_NAME>" }' \
  --start-time $(date -d '2 hours ago' +%s000)
```

### 4단계: 복구

```bash
# 감염된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# 노드 교체 (탈출 성공이 확인된 경우 노드는 신뢰할 수 없음)
INSTANCE_ID=$(kubectl get node $NODE_NAME -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id $INSTANCE_ID \
  --should-decrement-desired-capacity false

# 새 노드가 준비되면 cordon 해제
# (ASG가 자동으로 새 노드를 프로비저닝)
kubectl get nodes -w  # 새 노드 준비 대기

# Deployment securityContext 수정 (privileged 제거, hostPath 제거)
kubectl patch deployment <DEPLOYMENT_NAME> -n <NAMESPACE> --type=json -p='[
  {"op": "remove", "path": "/spec/template/spec/containers/0/securityContext/privileged"},
  {"op": "add", "path": "/spec/template/spec/securityContext/runAsNonRoot", "value": true},
  {"op": "add", "path": "/spec/template/spec/securityContext/seccompProfile", "value": {"type": "RuntimeDefault"}}
]'

# 격리 NetworkPolicy 제거
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>
```

### 5단계: 사후 조치

```bash
# 클러스터 전체 위험 pod 재점검
# Privileged pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  [.metadata.namespace, .metadata.name] | @tsv'

# hostPath 마운트 pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath != null) |
  [.metadata.namespace, .metadata.name, (.spec.volumes[] | select(.hostPath != null) | .hostPath.path)] | @tsv'

# 소켓 마운트 pod
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.hostPath.path | test("docker.sock|containerd.sock"; "g")) |
  [.metadata.namespace, .metadata.name] | @tsv'

# OPA Gatekeeper로 위험 설정 차단 정책 적용
kubectl apply -f - <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostFilesystem
metadata:
  name: psp-host-filesystem
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "falco", "tetragon", "cilium"]
  parameters:
    allowedHostPaths: []
EOF

# 노드 보안 그룹에서 불필요한 인바운드 규칙 제거
aws ec2 describe-security-groups \
  --filters "Name=tag:kubernetes.io/cluster/<CLUSTER_NAME>,Values=owned" \
  --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}'
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 즉시 완전 격리 (자동 실행)
2. `cordon_node` - 해당 노드 즉시 cordon (자동 실행)
3. `get_pod` - pod securityContext 및 볼륨 정보 수집
4. `delete_pod` - 감염 pod 삭제
5. `drain_node` - 노드 drain 후 교체 (별도 승인 필요)

승인 필요 여부: P1이므로 Slack 승인 필요. `apply_network_policy`와 `cordon_node`는 즉시 자동 실행. `drain_node`와 노드 교체는 서비스 영향이 크므로 반드시 승인 후 실행. 5분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 노드 cordon 확인
kubectl get node $NODE_NAME -o jsonpath='{.spec.unschedulable}'

# 새 pod가 다른 노드에서 실행 중인지 확인
kubectl get pods -n <NAMESPACE> -o wide | grep <DEPLOYMENT_NAME>

# 새 pod의 securityContext 확인 (privileged 없는지)
kubectl get pod <NEW_POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext}'

# Falco에서 추가 탈출 시도 없는지 확인
kubectl logs -n falco ds/falco --since=10m | grep -iE 'escape|host path|privileged'

# 교체된 노드가 정상 동작하는지 확인
kubectl get nodes
```

---

## 에스컬레이션

자동 대응 실패 또는 5분 내 Slack 승인 없을 때:

1. 탈출이 확인된 노드는 즉시 격리하고 ASG에서 제거한다.

```bash
# 노드 즉시 격리 (Security Group에서 모든 인바운드 차단)
aws ec2 revoke-security-group-ingress \
  --group-id <NODE_SG_ID> \
  --protocol all \
  --source-group <NODE_SG_ID>

# ASG에서 인스턴스 교체
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id $INSTANCE_ID \
  --should-decrement-desired-capacity false
```

2. 동일 노드에서 실행 중이던 모든 pod의 자격증명을 교체한다. 노드가 침해됐다면 해당 노드에서 실행된 모든 컨테이너의 Secret과 SA 토큰이 노출됐을 수 있다.

3. 담당자 연락: Slack `#security-incidents` 채널. 컨테이너 탈출은 노드 전체 침해를 의미하므로 즉각적인 포렌식 분석과 전체 클러스터 점검이 필요하다.
