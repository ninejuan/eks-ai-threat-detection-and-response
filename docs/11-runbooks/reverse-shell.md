# 리버스 셸 (Reverse Shell)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 컨테이너 내부에서 외부 C2 서버로 역방향 연결을 맺어 원격 명령 실행 환경을 확보하는 공격이다. 인바운드 방화벽을 우회하기 위해 컨테이너에서 먼저 연결을 시작하는 방식을 사용한다. 탐지 즉시 P1으로 처리한다.

- MITRE ATT&CK: T1059 Command and Scripting Interpreter, T1071.001 Application Layer Protocol: Web Protocols
- 심각도: P1 (Critical)

---

## 탐지 시그널

**GuardDuty Finding**
- `Backdoor:EKS/C2Activity.B` - 알려진 C2 서버로의 연결
- `Backdoor:EKS/MaliciousFile.Binary` - 리버스 셸 바이너리 실행
- `UnauthorizedAccess:EKS/TorIPCaller` - Tor 네트워크를 통한 접근
- `Execution:EKS/MaliciousFile` - 악성 파일 실행 탐지

**Falco Rule**
- `Reverse Shell Detected` - 셸 프로세스가 네트워크 소켓을 stdin/stdout으로 사용
- `Shell Spawned by Non-Shell Parent` - 비정상적인 부모 프로세스에서 셸 실행
- `Outbound Connection from Shell` - 셸 프로세스에서 외부 연결 시도
- `Interactive Shell Opened` - TTY가 연결된 인터랙티브 셸 실행

**Tetragon TracingPolicy**
- `detect-reverse-shell` - 셸 프로세스의 소켓 연결 이벤트
- `block-shell-network` - 셸에서 외부 연결 시도 시 Sigkill

**기타 지표**
- 셸 프로세스(`bash`, `sh`, `zsh`)가 외부 IP로 TCP 연결 유지
- `/dev/tcp` 또는 `/dev/udp`를 통한 네트워크 연결
- `nc`, `ncat`, `socat`을 이용한 외부 연결
- Python, Perl, Ruby 등 스크립트 언어로 소켓 연결 후 셸 실행
- 컨테이너 내 TTY 할당 (`proc.tty != 0`)과 외부 연결 동시 발생

---

## 초기 분석

**확인할 정보**
- 어떤 프로세스가 어떤 외부 IP/포트로 연결했는지
- 연결이 현재도 유지 중인지
- 셸을 실행한 부모 프로세스 (초기 침투 경로)
- 연결된 외부 IP의 위협 인텔리전스 평판
- 셸에서 실행된 명령 이력

**kubectl 명령어**

```bash
# 컨테이너 내 네트워크 연결 확인 (셸 프로세스 연결 여부)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp | grep -E 'bash|sh|zsh|nc|socat'

# 실행 중인 프로세스 트리 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf

# TTY가 연결된 프로세스 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps aux | awk '$7 != "?" {print}'

# 외부 연결 중인 프로세스 상세 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  ls -la /proc/$(pgrep -f bash)/fd 2>/dev/null | grep socket

# 컨테이너 내 최근 실행된 명령 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /proc/1/cmdline | tr '\0' ' '

# 외부 연결 IP 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp | \
  awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u
```

**외부 IP 위협 인텔리전스 확인**

```bash
# GuardDuty Finding에서 C2 IP 추출
aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID> \
  --query 'Findings[0].Service.Action.NetworkConnectionAction.RemoteIpDetails'

# VPC Flow Logs에서 해당 연결 확인
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=<POD_IP>, destination=<C2_IP>, ...]" \
  --start-time $(date -d '2 hours ago' +%s000)
```

**로그 확인 위치**
- Falco 로그: `kubectl logs -n falco ds/falco | grep -iE 'reverse|shell|c2'`
- GuardDuty Findings: Backdoor 유형 Finding
- VPC Flow Logs: 외부 연결 트래픽
- Tetragon 이벤트: `kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods <POD_NAME>`

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

P1이므로 탐지 즉시 네트워크를 차단한다. 연결이 유지 중이면 즉시 끊어야 한다.

```bash
# 즉시 네트워크 격리 (모든 인그레스/이그레스 차단)
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

# 격리 적용 확인 후 셸 프로세스 강제 종료
SHELL_PID=$(kubectl exec <POD_NAME> -n <NAMESPACE> -- pgrep -f 'bash\|sh\|nc\|socat' 2>/dev/null | head -1)
if [ -n "$SHELL_PID" ]; then
  kubectl exec <POD_NAME> -n <NAMESPACE> -- kill -9 $SHELL_PID
fi
```

### 2단계: 증거 수집

격리 직후, pod를 삭제하기 전에 증거를 수집한다.

```bash
# 프로세스 트리 전체 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf > /tmp/evidence-ps-$(date +%s).txt

# 네트워크 연결 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp > /tmp/evidence-net-$(date +%s).txt

# 파일 디스크립터 확인 (소켓 연결 증거)
for pid in $(kubectl exec <POD_NAME> -n <NAMESPACE> -- pgrep -f 'bash|sh' 2>/dev/null); do
  kubectl exec <POD_NAME> -n <NAMESPACE> -- ls -la /proc/$pid/fd 2>/dev/null \
    >> /tmp/evidence-fd-$(date +%s).txt
done

# bash history 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null \
  > /tmp/evidence-history-$(date +%s).txt

# /tmp, /dev/shm 등 임시 디렉터리 파일 목록
kubectl exec <POD_NAME> -n <NAMESPACE> -- find /tmp /dev/shm /var/tmp -type f 2>/dev/null \
  > /tmp/evidence-tmpfiles-$(date +%s).txt

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# Falco 로그 저장
kubectl logs -n falco ds/falco --since=2h | grep <POD_NAME> \
  > /tmp/evidence-falco-$(date +%s).txt

# Tetragon 이벤트 저장
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o json --pods <POD_NAME> 2>/dev/null \
  > /tmp/evidence-tetragon-$(date +%s).json

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 셸을 실행한 부모 프로세스 확인 (초기 침투 경로)
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  ps -eo pid,ppid,cmd --forest 2>/dev/null | grep -A5 -B5 bash

# 웹 애플리케이션 취약점 익스플로잇 여부 확인 (access log)
kubectl logs <POD_NAME> -n <NAMESPACE> | grep -E 'POST|PUT' | tail -50

# 컨테이너 이미지에 포함된 취약점 확인
aws ecr describe-image-scan-findings \
  --repository-name <REPO_NAME> \
  --image-id imageTag=<TAG> \
  --query 'imageScanFindings.findings[?severity==`CRITICAL`]'

# 최근 배포 이력 확인
kubectl rollout history deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 연결된 C2 IP 분석
C2_IP=$(kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp 2>/dev/null | \
  grep -E 'bash|sh' | awk '{print $5}' | cut -d: -f1 | head -1)
echo "C2 IP: $C2_IP"

# audit log에서 해당 pod 관련 이벤트 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.objectRef.name = \"<POD_NAME>\" }" \
  --start-time $(date -d '24 hours ago' +%s000)
```

### 4단계: 복구

```bash
# 감염된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# 취약한 이미지 사용 중이면 이전 버전으로 롤백
kubectl rollout undo deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 격리 NetworkPolicy 제거 (새 pod 정상 확인 후)
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>

# 새 pod 정상 동작 확인
kubectl get pods -n <NAMESPACE> -w
```

### 5단계: 사후 조치

```bash
# 동일 이미지를 사용하는 모든 pod 점검
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
  grep <COMPROMISED_IMAGE>

# C2 IP를 Security Group에서 차단
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number 1 \
  --protocol tcp \
  --rule-action deny \
  --egress \
  --cidr-block <C2_IP>/32 \
  --port-range From=0,To=65535

# Tetragon TracingPolicy로 셸의 외부 연결 차단 정책 강화
kubectl apply -f - <<EOF
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-shell-outbound
spec:
  kprobes:
  - call: "sys_connect"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/bin/bash"
        - "/bin/sh"
        - "/usr/bin/bash"
        - "/usr/bin/sh"
      matchActions:
      - action: Sigkill
EOF

# 이미지 취약점 패치 후 재배포
# ECR 이미지 스캔 강제 실행
aws ecr start-image-scan \
  --repository-name <REPO_NAME> \
  --image-id imageTag=<NEW_TAG>
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 즉시 완전 격리 (자동 실행, 승인 불필요)
2. `get_pod` - pod 정보 및 이미지 수집
3. `delete_pod` - 격리 후 즉시 pod 삭제 (자동 실행)
4. `patch_deployment` - 이전 이미지 버전으로 롤백

승인 필요 여부: P1이므로 Slack 승인 필요. `apply_network_policy`와 `delete_pod`는 즉시 자동 실행. `patch_deployment`(롤백)는 승인 후 실행. 5분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 격리 NetworkPolicy 적용 확인
kubectl get networkpolicy isolate-<POD_NAME> -n <NAMESPACE>

# 새 pod에서 외부 연결 없는지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- ss -tnp | grep -E 'bash|sh|nc|socat'

# Falco에서 추가 리버스 셸 이벤트 없는지 확인
kubectl logs -n falco ds/falco --since=10m | grep -iE 'reverse|shell|c2'

# C2 IP로의 연결 차단 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- \
  timeout 5 bash -c "echo > /dev/tcp/<C2_IP>/4444" 2>&1 | grep -i 'refused\|timeout'
```

---

## 에스컬레이션

자동 대응 실패 또는 5분 내 Slack 승인 없을 때:

1. 해당 노드를 즉시 cordon하고 drain한다.

```bash
NODE_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}')
kubectl cordon $NODE_NAME
kubectl drain $NODE_NAME --ignore-daemonsets --delete-emptydir-data --force
```

2. 리버스 셸이 장시간 유지됐다면 해당 노드 인스턴스를 교체한다.

```bash
INSTANCE_ID=$(kubectl get node $NODE_NAME -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id $INSTANCE_ID \
  --should-decrement-desired-capacity false
```

3. C2 서버 IP를 VPC NACL에서 즉시 차단하고 Security Hub에 IOC로 등록한다.

4. 담당자 연락: Slack `#security-incidents` 채널. P1 인시던트이므로 즉시 응답 필요. 리버스 셸 유지 시간이 길수록 피해 범위가 크므로 신속한 포렌식 분석이 필요하다.
