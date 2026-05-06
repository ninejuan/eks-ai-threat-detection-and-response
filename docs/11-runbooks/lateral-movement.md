# 횡적 이동 (Lateral Movement)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 초기 침투한 컨테이너에서 다른 pod, 네임스페이스, 또는 클러스터 내 서비스로 이동하는 공격이다. ServiceAccount 토큰을 이용한 Kubernetes API 접근, 내부 서비스 스캐닝, 취약한 서비스 익스플로잇이 주요 수법이다.

- MITRE ATT&CK: T1210 Exploitation of Remote Services, T1021 Remote Services, T1550.001 Use Alternate Authentication Material
- 심각도: P2 (High)

---

## 탐지 시그널

**GuardDuty Finding**
- `Discovery:EKS/MaliciousIPCaller` - 악성 IP에서 EKS 내부 API 호출
- `CredentialAccess:EKS/AnomalousBehavior` - 비정상적인 자격증명 사용 패턴
- `Execution:EKS/ExecInPod` - 여러 pod에 대한 연속적인 kubectl exec
- `Discovery:EKS/TorIPCaller` - Tor 네트워크를 통한 API 호출

**Falco Rule**
- `Contact K8S API Server From Container` - 컨테이너에서 Kubernetes API 서버 직접 호출
- `Network Connection Outside Expected Range` - 비정상적인 내부 네트워크 연결
- `Port Scan Detected` - 내부 네트워크 포트 스캔
- `Unexpected Network Connection` - 허용되지 않은 pod 간 직접 연결

**Tetragon TracingPolicy**
- `detect-lateral-movement` - 내부 네트워크 스캔 및 비정상 연결 이벤트

**기타 지표**
- 컨테이너에서 `kubectl`, `curl`, `wget`으로 Kubernetes API 서버(`kubernetes.default.svc`) 직접 호출
- 짧은 시간 내 다수의 내부 IP/포트 연결 시도 (포트 스캔)
- 평소 통신하지 않던 pod 간 연결 수립
- ServiceAccount 토큰으로 다른 네임스페이스 리소스 조회 시도
- 내부 서비스 디스커버리 명령 실행 (`nmap`, `masscan`, `nc` 등)

---

## 초기 분석

**확인할 정보**
- 어떤 pod에서 어떤 대상으로 이동을 시도했는지
- 사용된 자격증명 (SA 토큰, 탈취된 kubeconfig 등)
- 접근에 성공한 리소스 범위
- 이동 경로 (어떤 pod에서 시작됐는지)
- 현재 진행 중인 스캔 또는 연결 여부

**kubectl 명령어**

```bash
# 해당 pod의 ServiceAccount 권한 확인
SA_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}')
kubectl auth can-i --list --as=system:serviceaccount:<NAMESPACE>:$SA_NAME

# 다른 네임스페이스 리소스 접근 가능 여부 확인
kubectl auth can-i list pods --as=system:serviceaccount:<NAMESPACE>:$SA_NAME -n kube-system
kubectl auth can-i list secrets --as=system:serviceaccount:<NAMESPACE>:$SA_NAME -n <OTHER_NAMESPACE>

# 컨테이너 내 네트워크 연결 현황
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -unp

# 컨테이너 내 실행 중인 프로세스 확인 (스캔 도구 여부)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps aux | grep -E 'nmap|masscan|nc|netcat|curl|wget'

# audit log에서 해당 SA의 API 호출 이력 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"system:serviceaccount:<NAMESPACE>:<SA_NAME>\" }" \
  --start-time $(date -d '2 hours ago' +%s000) \
  --query 'events[*].message' | jq -r '.[] | fromjson | [.requestURI, .verb, .objectRef.resource] | @tsv'

# Hubble로 pod 간 네트워크 흐름 확인
hubble observe --pod <NAMESPACE>/<POD_NAME> --follow
hubble observe --namespace <NAMESPACE> --verdict DROPPED --follow
```

**내부 스캔 탐지**

```bash
# CoreDNS 로그에서 내부 서비스 열거 시도 확인
kubectl logs -n kube-system -l k8s-app=kube-dns --since=1h | \
  grep <POD_IP> | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# VPC Flow Logs에서 포트 스캔 패턴 확인 (짧은 시간 내 다수 포트)
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=<POD_IP>, ...]" \
  --start-time $(date -d '1 hour ago' +%s000)
```

**로그 확인 위치**
- CloudWatch Logs: `/aws/eks/<CLUSTER_NAME>/cluster` (audit log)
- VPC Flow Logs: 내부 트래픽 패턴
- Hubble: pod 간 네트워크 흐름
- Falco 로그: `kubectl logs -n falco ds/falco | grep -i lateral`

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

침투된 pod와 이동 대상 pod를 모두 격리한다.

```bash
# 침투된 pod 네트워크 격리
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-source-<POD_NAME>
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      <POD_LABEL_KEY>: <POD_LABEL_VALUE>
  policyTypes:
  - Ingress
  - Egress
EOF

# 이동 대상이 된 pod도 격리 (접근 성공한 경우)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-target-<TARGET_POD_NAME>
  namespace: <TARGET_NAMESPACE>
spec:
  podSelector:
    matchLabels:
      <TARGET_LABEL_KEY>: <TARGET_LABEL_VALUE>
  policyTypes:
  - Ingress
  - Egress
EOF

# 해당 SA 토큰 즉시 비활성화
kubectl patch serviceaccount <SA_NAME> -n <NAMESPACE> \
  -p '{"automountServiceAccountToken": false}'
```

### 2단계: 증거 수집

```bash
# 프로세스 및 네트워크 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf > /tmp/evidence-ps-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp > /tmp/evidence-net-$(date +%s).txt

# 컨테이너 내 명령 실행 이력 (bash history)
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null \
  > /tmp/evidence-history-$(date +%s).txt
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /home/*/.bash_history 2>/dev/null \
  >> /tmp/evidence-history-$(date +%s).txt

# audit log 수집 (SA의 모든 API 호출)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"system:serviceaccount:<NAMESPACE>:<SA_NAME>\" }" \
  --start-time $(date -d '24 hours ago' +%s000) \
  > /tmp/evidence-audit-$(date +%s).json

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# 영향받은 리소스 목록 저장
kubectl get pods,services,secrets -n <TARGET_NAMESPACE> -o yaml \
  > /tmp/evidence-target-ns-$(date +%s).yaml

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 이동 경로 재구성 (audit log 시계열 분석)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"system:serviceaccount:<NAMESPACE>:<SA_NAME>\" }" \
  --start-time $(date -d '24 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .verb, .objectRef.namespace, .objectRef.resource, .objectRef.name] | @tsv' | \
  sort

# SA에 부여된 RBAC 권한 전체 확인
kubectl get rolebinding,clusterrolebinding -A -o json | jq -r '
  .items[] |
  select(.subjects[]? | select(.kind == "ServiceAccount" and .name == "<SA_NAME>" and .namespace == "<NAMESPACE>")) |
  [.kind, .metadata.namespace // "cluster", .metadata.name, .roleRef.name] | @tsv'

# 초기 침투 경로 파악
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "create" && $.objectRef.resource = "pods" && $.objectRef.name = "<POD_NAME>" }' \
  --start-time $(date -d '48 hours ago' +%s000)

# 접근 성공한 리소스 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.user.username = "system:serviceaccount:<NAMESPACE>:<SA_NAME>" && $.responseStatus.code = 200 }' \
  --start-time $(date -d '24 hours ago' +%s000)
```

### 4단계: 복구

```bash
# 침투된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# 이동 대상 pod도 감염 여부 확인 후 필요 시 삭제
kubectl delete pod <TARGET_POD_NAME> -n <TARGET_NAMESPACE>

# SA 권한 최소화 (과도한 ClusterRole 제거)
kubectl delete clusterrolebinding <EXCESSIVE_BINDING_NAME>

# 새 SA 생성 및 최소 권한 재부여
kubectl create serviceaccount <NEW_SA_NAME> -n <NAMESPACE>
# 필요한 최소 권한만 RoleBinding으로 재부여

# Deployment에 새 SA 적용
kubectl patch deployment <DEPLOYMENT_NAME> -n <NAMESPACE> \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"<NEW_SA_NAME>"}}}}'

# 격리 NetworkPolicy 제거 (복구 확인 후)
kubectl delete networkpolicy isolate-source-<POD_NAME> -n <NAMESPACE>
kubectl delete networkpolicy isolate-target-<TARGET_POD_NAME> -n <TARGET_NAMESPACE>
```

### 5단계: 사후 조치

```bash
# 클러스터 전체 과도한 SA 권한 감사
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  [.metadata.name, (.subjects[]? | .kind + "/" + (.namespace // "cluster") + "/" + .name)] | @tsv'

# 네임스페이스 간 통신 제한 기본 정책 적용
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-cross-namespace
  namespace: <NAMESPACE>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
EOF

# Kubernetes API 서버 접근 제한 (컨테이너에서 직접 접근 차단)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-k8s-api-access
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      app: <APP_LABEL>
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 172.20.0.1/32  # kubernetes.default.svc ClusterIP
EOF
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 침투 pod 즉시 격리 (승인 없이 자동 실행)
2. `get_pod` - pod 및 SA 정보 수집
3. `patch_deployment` - automountServiceAccountToken 비활성화
4. `delete_pod` - 침투 pod 삭제
5. `delete_cluster_role_binding` - 과도한 권한 ClusterRoleBinding 제거 (별도 승인 필요)

승인 필요 여부: P2이므로 Slack 승인 필요. `apply_network_policy`는 즉시 자동 실행. RBAC 변경은 승인 후 실행. 15분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 격리 NetworkPolicy 적용 확인
kubectl get networkpolicy -n <NAMESPACE>

# SA 권한 제거 확인
kubectl auth can-i list pods --as=system:serviceaccount:<NAMESPACE>:<SA_NAME> -n kube-system

# 새 pod가 최소 권한 SA로 실행 중인지 확인
kubectl get pod -n <NAMESPACE> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}'

# audit log에서 해당 SA의 추가 API 호출 없는지 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"system:serviceaccount:<NAMESPACE>:<SA_NAME>\" }" \
  --start-time $(date --iso-8601=seconds)
```

---

## 에스컬레이션

자동 대응 실패 또는 15분 내 Slack 승인 없을 때:

1. 이동이 여러 네임스페이스에 걸쳐 발생한 경우 영향받은 모든 네임스페이스를 격리한다.

```bash
# 영향받은 네임스페이스 목록 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"system:serviceaccount:<NAMESPACE>:<SA_NAME>\" && $.responseStatus.code = 200 }" \
  --start-time $(date -d '24 hours ago' +%s000) \
  --query 'events[*].message' | jq -r '.[] | fromjson | .objectRef.namespace' | sort -u
```

2. 클러스터 전체 침해가 의심되면 EKS 클러스터의 API 서버 엔드포인트 접근을 제한한다.

```bash
# EKS API 서버 퍼블릭 접근 제한 (허용 CIDR만 유지)
aws eks update-cluster-config \
  --name <CLUSTER_NAME> \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=<ALLOWED_CIDR>
```

3. 담당자 연락: Slack `#security-incidents` 채널. 다중 네임스페이스 침해 시 즉시 응답 필요.
