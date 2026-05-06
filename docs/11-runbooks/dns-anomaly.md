# DNS 이상 (DNS Anomaly)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

컨테이너에서 알려진 악성 도메인, C2 서버, 또는 DNS 터널링을 통한 데이터 유출 시도가 탐지되는 공격이다. DNS 쿼리는 방화벽을 우회하기 쉬워 C2 통신 채널로 자주 악용된다.

- MITRE ATT&CK: T1071.004 Application Layer Protocol: DNS, T1048.003 Exfiltration Over Alternative Protocol
- 심각도: P3 (Medium)

---

## 탐지 시그널

**GuardDuty Finding**
- `CryptoCurrency:EKS/BitcoinTool.B!DNS` - 알려진 마이닝 풀 도메인 쿼리
- `Backdoor:EKS/C2Activity.B!DNS` - 알려진 C2 도메인 쿼리
- `Trojan:EKS/DNSDataExfiltration` - DNS 터널링을 통한 데이터 유출 의심
- `UnauthorizedAccess:EKS/MaliciousDomain.Rep` - 악성 평판 도메인 쿼리

**Falco Rule**
- `Unexpected DNS Query` - 허용 목록 외 도메인 쿼리
- `DNS Tunneling Detected` - 비정상적으로 긴 DNS 쿼리 또는 높은 쿼리 빈도
- `Outbound Connection to C2 Servers` - 알려진 C2 IP/도메인 연결

**Tetragon TracingPolicy**
- `detect-dns-anomaly` - 비정상 DNS 쿼리 패턴 이벤트

**기타 지표**
- 비정상적으로 긴 서브도메인 (DNS 터널링 특징: `aGVsbG8gd29ybGQ.evil.com` 형태)
- 짧은 시간 내 동일 도메인에 대한 반복 쿼리 (100회/분 이상)
- TXT, NULL, CNAME 레코드 타입 쿼리 빈도 급증
- 알려진 위협 인텔리전스 피드에 등록된 도메인 쿼리
- 내부 DNS 서버가 아닌 외부 DNS 서버(8.8.8.8, 1.1.1.1)로 직접 쿼리

---

## 초기 분석

**확인할 정보**
- 쿼리된 도메인 이름과 레코드 타입
- 쿼리 빈도와 패턴 (터널링 여부)
- 해당 pod의 정상 동작 범위
- 도메인의 위협 인텔리전스 평판
- 실제 연결이 성립됐는지 여부

**kubectl 명령어**

```bash
# 해당 pod의 DNS 쿼리 로그 확인 (CoreDNS 로그)
kubectl logs -n kube-system -l k8s-app=kube-dns --since=1h | grep <POD_IP>

# pod IP 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.podIP}'

# 컨테이너 내 DNS 설정 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /etc/resolv.conf

# 컨테이너에서 직접 DNS 쿼리 테스트
kubectl exec <POD_NAME> -n <NAMESPACE> -- nslookup <SUSPICIOUS_DOMAIN> 2>/dev/null

# 현재 네트워크 연결 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp

# Hubble로 DNS 흐름 확인 (Cilium 사용 시)
hubble observe --pod <NAMESPACE>/<POD_NAME> --protocol DNS --follow
```

**CoreDNS 로그 분석**

```bash
# CoreDNS에서 특정 도메인 쿼리 빈도 확인
kubectl logs -n kube-system -l k8s-app=kube-dns --since=1h | \
  grep -oP 'A \K[^\s]+' | sort | uniq -c | sort -rn | head -20

# 비정상적으로 긴 서브도메인 탐지 (DNS 터널링 지표)
kubectl logs -n kube-system -l k8s-app=kube-dns --since=1h | \
  awk '{for(i=1;i<=NF;i++) if(length($i)>50 && $i ~ /\./) print $i}' | sort -u

# 외부 DNS 서버로 직접 쿼리 시도 탐지
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -unp | grep ':53'
```

**GuardDuty Finding 상세 확인**

```bash
# GuardDuty Finding 상세 조회
aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID> \
  --query 'Findings[0].{Severity:Severity,Type:Type,Description:Description,Service:Service}'
```

**로그 확인 위치**
- CoreDNS 로그: `kubectl logs -n kube-system -l k8s-app=kube-dns`
- VPC Flow Logs: UDP/TCP 포트 53 트래픽
- GuardDuty Findings: DNS 관련 Finding 유형
- Hubble: DNS 프로토콜 필터링

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

P3이므로 자동 실행. 의심 도메인으로의 DNS 쿼리를 차단한다.

```bash
# CoreDNS에 악성 도메인 차단 규칙 추가
kubectl get configmap coredns -n kube-system -o yaml > /tmp/coredns-backup.yaml

kubectl patch configmap coredns -n kube-system --type=merge -p '{
  "data": {
    "Corefile": ".:53 {\n    errors\n    health\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n      pods insecure\n      fallthrough in-addr.arpa ip6.arpa\n    }\n    hosts {\n      fallthrough\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf\n    cache 30\n    loop\n    reload\n    loadbalance\n    rewrite name <MALICIOUS_DOMAIN> blocked.internal\n}"
  }
}'

# CoreDNS 재시작으로 설정 반영
kubectl rollout restart deployment/coredns -n kube-system

# 해당 pod에서 외부 DNS 직접 쿼리 차단 (NetworkPolicy)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-external-dns-<POD_LABEL_VALUE>
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      <POD_LABEL_KEY>: <POD_LABEL_VALUE>
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
EOF
```

### 2단계: 증거 수집

```bash
# DNS 쿼리 로그 저장
kubectl logs -n kube-system -l k8s-app=kube-dns --since=2h \
  > /tmp/evidence-coredns-$(date +%s).txt

# pod 네트워크 연결 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnup > /tmp/evidence-net-$(date +%s).txt

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# GuardDuty Finding 전체 저장
aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID> \
  --output json > /tmp/evidence-guardduty-$(date +%s).json

# VPC Flow Logs에서 포트 53 트래픽 조회
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source, destination, srcport, destport=53, ...]" \
  --start-time $(date -d '2 hours ago' +%s000) \
  > /tmp/evidence-flowlogs-$(date +%s).txt

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 도메인 위협 인텔리전스 확인
# VirusTotal API (설정된 경우)
curl -s "https://www.virustotal.com/api/v3/domains/<SUSPICIOUS_DOMAIN>" \
  -H "x-apikey: <VT_API_KEY>" | jq '.data.attributes.last_analysis_stats'

# 도메인 등록 정보 확인
whois <SUSPICIOUS_DOMAIN> 2>/dev/null | grep -E 'Registrar|Creation|Expiry'

# DNS 터널링 여부 판단 (엔트로피 분석)
# 서브도메인 길이 분포 확인
kubectl logs -n kube-system -l k8s-app=kube-dns --since=2h | \
  grep <BASE_DOMAIN> | \
  awk '{print $NF}' | \
  awk -F. '{print length($1)}' | \
  sort -n | uniq -c

# 쿼리 빈도 분석 (분당 쿼리 수)
kubectl logs -n kube-system -l k8s-app=kube-dns --since=1h | \
  grep <SUSPICIOUS_DOMAIN> | \
  awk '{print $1}' | \
  cut -d: -f1,2 | \
  uniq -c | sort -rn | head -10

# 해당 pod의 정상 DNS 쿼리 패턴과 비교
kubectl logs -n kube-system -l k8s-app=kube-dns --since=24h | \
  grep <POD_IP> | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

### 4단계: 복구

```bash
# DNS 터널링이 확인된 경우 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# 단순 악성 도메인 쿼리인 경우 CoreDNS 차단 유지 + pod 재시작
kubectl rollout restart deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# CoreDNS 차단 규칙 영구 적용 (ConfigMap 업데이트)
# 임시 패치 대신 GitOps 파이프라인을 통해 영구 반영

# 외부 DNS 직접 쿼리 차단 NetworkPolicy 유지
# (모든 pod가 kube-dns만 사용하도록 클러스터 전체 정책 적용 검토)
```

### 5단계: 사후 조치

```bash
# 동일 도메인을 쿼리한 다른 pod 확인
kubectl logs -n kube-system -l k8s-app=kube-dns --since=24h | \
  grep <SUSPICIOUS_DOMAIN> | \
  awk '{print $3}' | sort -u

# CoreDNS 로깅 강화 (상세 로그 활성화)
kubectl patch configmap coredns -n kube-system --type=merge -p '{
  "data": {
    "Corefile": ".:53 {\n    log\n    errors\n    ..."
  }
}'

# 위협 인텔리전스 피드를 CoreDNS에 통합 검토
# (예: CoreDNS blocklist 플러그인 사용)

# GuardDuty 위협 인텔리전스 커스텀 목록 업데이트
aws guardduty create-threat-intel-set \
  --detector-id <DETECTOR_ID> \
  --name "custom-malicious-domains" \
  --format TXT \
  --location s3://atdr-threat-intel/domains.txt \
  --activate
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 외부 DNS 직접 쿼리 차단 (자동 실행)
2. `get_pod` - pod 정보 및 DNS 설정 수집
3. CoreDNS ConfigMap 패치 - 악성 도메인 차단 규칙 추가 (자동 실행)

승인 필요 여부: P3이므로 자동 실행. 결과는 Slack으로 알림만 전송.

---

## 검증

```bash
# 악성 도메인 차단 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- nslookup <MALICIOUS_DOMAIN> 2>&1 | \
  grep -E 'NXDOMAIN|blocked|refused'

# CoreDNS 차단 규칙 적용 확인
kubectl get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' | \
  grep <MALICIOUS_DOMAIN>

# 외부 DNS 직접 쿼리 차단 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  timeout 5 bash -c 'echo "" | nc -u 8.8.8.8 53' 2>&1 | grep -i timeout

# GuardDuty에서 동일 Finding 재발 없는지 모니터링 (24시간)
aws guardduty list-findings \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{"Criterion":{"type":{"Eq":["CryptoCurrency:EKS/BitcoinTool.B!DNS"]},"updatedAt":{"Gte":'$(date -d '1 hour ago' +%s000)'}}}' \
  --query 'FindingIds'
```

---

## 에스컬레이션

자동 대응 실패 시:

1. DNS 터널링이 확인된 경우 P3에서 P2로 심각도를 상향하고 pod를 완전 격리한다.

```bash
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
```

2. 클러스터 전체에서 동일 패턴이 발견되면 CoreDNS 전체 로깅을 활성화하고 담당자에게 보고한다.

3. 담당자 연락: Slack `#security-incidents` 채널. DNS 터널링 확인 시 즉시 응답 요청.
