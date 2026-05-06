# 데이터 유출 (Data Exfiltration)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 컨테이너 내부에서 민감한 데이터를 외부로 전송하는 공격이다. HTTP/HTTPS, DNS 터널링, 클라우드 스토리지 업로드 등 다양한 채널을 통해 발생한다. 데이터베이스 덤프, 설정 파일, 사용자 데이터 등이 주요 대상이다.

- MITRE ATT&CK: T1041 Exfiltration Over C2 Channel, T1048 Exfiltration Over Alternative Protocol, T1567 Exfiltration Over Web Service
- 심각도: P1 (Critical)

---

## 탐지 시그널

**GuardDuty Finding**
- `UnauthorizedAccess:EKS/ExfiltratedData.Suspicious` - 비정상적인 외부 데이터 전송
- `Exfiltration:S3/AnomalousBehavior` - S3 버킷에서 비정상적인 대량 다운로드
- `Exfiltration:IAM/AnomalousBehavior` - IAM 자격증명을 통한 데이터 유출
- `Trojan:EKS/DNSDataExfiltration` - DNS 터널링을 통한 데이터 유출
- `Impact:EKS/AnomalousBehavior` - 비정상적인 대용량 데이터 전송

**Falco Rule**
- `Outbound Data Transfer Anomaly` - 비정상적인 아웃바운드 데이터 전송량
- `Sensitive Data Access and Network Activity` - 민감 파일 접근 후 네트워크 전송
- `Database Dump Detected` - 데이터베이스 덤프 명령 실행
- `Cloud Storage Upload` - 외부 클라우드 스토리지로 업로드 시도

**Tetragon TracingPolicy**
- `detect-data-exfiltration` - 대용량 파일 읽기 후 외부 전송 이벤트

**기타 지표**
- 평소보다 현저히 높은 아웃바운드 트래픽 (수 GB 이상)
- 업무 시간 외 대용량 데이터 전송
- 알 수 없는 외부 IP/도메인으로의 지속적인 연결
- `curl`, `wget`, `aws s3 cp` 등을 이용한 외부 전송 명령
- 데이터베이스 클라이언트 도구 실행 후 외부 연결
- 압축 도구(`tar`, `gzip`, `zip`) 실행 후 네트워크 전송

---

## 초기 분석

**확인할 정보**
- 어떤 데이터가 유출됐는지 (파일 유형, 크기, 내용)
- 유출 대상 외부 IP/도메인
- 전송된 데이터 양
- 유출 채널 (HTTP, DNS, S3 등)
- 유출이 현재도 진행 중인지

**kubectl 명령어**

```bash
# 컨테이너 내 네트워크 연결 및 전송량 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /proc/net/dev

# 실행 중인 프로세스 확인 (전송 도구 여부)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps aux | grep -E 'curl|wget|nc|aws|gsutil|rclone|rsync'

# 최근 접근된 파일 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find / -newer /tmp -type f -size +1M 2>/dev/null | grep -v '/proc\|/sys\|/dev'

# bash history에서 전송 명령 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null | \
  grep -E 'curl|wget|aws s3|nc|tar|gzip'

# 컨테이너 내 임시 파일 확인 (압축 파일 등)
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find /tmp /var/tmp /dev/shm -type f -size +1M 2>/dev/null

# pod의 아웃바운드 트래픽 확인 (Hubble)
hubble observe --pod <NAMESPACE>/<POD_NAME> --type l4 --follow | grep -v 'kube-dns'
```

**VPC Flow Logs 분석**

```bash
# 해당 pod IP에서 외부로 나가는 대용량 트래픽 확인
POD_IP=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.podIP}')

aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=$POD_IP, destination, srcport, destport, protocol, packets, bytes>1000000, ...]" \
  --start-time $(date -d '2 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | split(" ") | {src: .[3], dst: .[4], bytes: .[9], action: .[12]}' | \
  jq -s 'sort_by(.bytes | tonumber) | reverse | .[0:10]'

# 외부 IP 목록 추출
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=$POD_IP, destination, ...]" \
  --start-time $(date -d '2 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | split(" ") | .[4]' | \
  grep -v '^10\.\|^172\.\|^192\.168\.' | sort -u
```

**S3 유출 확인**

```bash
# S3 버킷에서 비정상적인 GetObject 이벤트 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --query 'Events[?SourceIPAddress!=`<EXPECTED_IP>`]' | \
  jq -r '.[] | [.EventTime, .Username, .SourceIPAddress, (.Resources[]? | .ResourceName)] | @tsv'

# 외부 S3 버킷으로 PutObject 이벤트 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --query 'Events[*].{Time:EventTime,User:Username,Source:SourceIPAddress,Resource:Resources}'
```

**로그 확인 위치**
- VPC Flow Logs: 아웃바운드 트래픽 볼륨
- CloudTrail: S3 GetObject/PutObject 이벤트
- GuardDuty Findings: Exfiltration 유형
- Falco 로그: `kubectl logs -n falco ds/falco | grep -iE 'exfil|transfer|upload'`

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

P1이므로 탐지 즉시 네트워크를 차단해 진행 중인 유출을 중단시킨다.

```bash
# 즉시 완전 네트워크 격리
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

# 유출에 사용된 외부 IP를 NACL에서 즉시 차단
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL_ID> \
  --rule-number 1 \
  --protocol tcp \
  --rule-action deny \
  --egress \
  --cidr-block <EXFIL_IP>/32 \
  --port-range From=0,To=65535

# S3 유출인 경우 해당 버킷 접근 즉시 차단
aws s3api put-bucket-policy \
  --bucket <TARGET_BUCKET> \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyAll",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<TARGET_BUCKET>", "arn:aws:s3:::<TARGET_BUCKET>/*"]
    }]
  }'
```

### 2단계: 증거 수집

```bash
# 전송 중인 또는 전송된 파일 목록 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find / -newer /tmp -type f -size +100k 2>/dev/null | \
  grep -v '/proc\|/sys\|/dev' > /tmp/evidence-files-$(date +%s).txt

# 네트워크 연결 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp > /tmp/evidence-net-$(date +%s).txt

# bash history 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null \
  > /tmp/evidence-history-$(date +%s).txt

# 임시 디렉터리 파일 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find /tmp /var/tmp /dev/shm -type f 2>/dev/null | \
  xargs -I{} ls -la {} > /tmp/evidence-tmpfiles-$(date +%s).txt

# VPC Flow Logs 저장 (전체 트래픽)
POD_IP=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.podIP}')
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=$POD_IP, ...]" \
  --start-time $(date -d '4 hours ago' +%s000) \
  > /tmp/evidence-flowlogs-$(date +%s).json

# CloudTrail 이벤트 저장
aws cloudtrail lookup-events \
  --start-time $(date -d '4 hours ago' --iso-8601=seconds) \
  --output json > /tmp/evidence-cloudtrail-$(date +%s).json

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 유출된 데이터 유형 파악
# 1) 데이터베이스 덤프 여부
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find / -name '*.sql' -o -name '*.dump' -o -name '*.csv' 2>/dev/null | \
  grep -v '/proc\|/sys'

# 2) 설정 파일 접근 여부
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find / -name '*.env' -o -name '*.conf' -o -name '*.yaml' -o -name '*.json' 2>/dev/null | \
  grep -v '/proc\|/sys\|/usr\|/lib' | head -20

# 유출 경로 분석
# HTTP/HTTPS 유출인 경우
kubectl exec <POD_NAME> -n <NAMESPACE> -- cat /root/.bash_history 2>/dev/null | \
  grep -E 'curl|wget' | grep -v 'localhost\|127.0.0.1\|kubernetes.default'

# S3 유출인 경우 - 어떤 버킷으로 전송됐는지
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
  --start-time $(date -d '4 hours ago' --iso-8601=seconds) \
  --query 'Events[*].{Time:EventTime,Bucket:Resources[0].ResourceName,Source:SourceIPAddress}'

# 초기 침투 경로 파악
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "create" && $.objectRef.resource = "pods" && $.objectRef.name = "<POD_NAME>" }' \
  --start-time $(date -d '48 hours ago' +%s000)

# 유출 규모 추정 (VPC Flow Logs 바이트 합산)
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=$POD_IP, destination, srcport, destport, protocol, packets, bytes, ...]" \
  --start-time $(date -d '4 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | split(" ") | .[9]' | \
  awk '{sum += $1} END {print "Total bytes: " sum " (" sum/1024/1024 " MB)"}'
```

### 4단계: 복구

```bash
# 감염된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# Deployment 롤백 (취약한 버전인 경우)
kubectl rollout undo deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 유출에 사용된 자격증명 교체
# SA 토큰 교체
kubectl delete serviceaccount <SA_NAME> -n <NAMESPACE>
kubectl create serviceaccount <SA_NAME> -n <NAMESPACE>

# AWS 자격증명 교체
aws iam update-access-key \
  --access-key-id <COMPROMISED_KEY_ID> \
  --status Inactive \
  --user-name <IAM_USER_NAME>

# 격리 NetworkPolicy 제거 (새 pod 정상 확인 후)
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>

# NACL 차단 규칙 검토 (정상 트래픽 영향 없는지 확인 후 유지 또는 제거)
```

### 5단계: 사후 조치

```bash
# 유출된 데이터 범위 파악 및 규정 준수 검토
# GDPR, 개인정보보호법 등 데이터 침해 신고 의무 확인

# 영향받은 데이터 소유자 통보 절차 시작
# (법무팀, 개인정보보호 담당자와 협의)

# 데이터베이스 접근 자격증명 전체 교체
kubectl get secrets -n <NAMESPACE> | grep -i 'db\|database\|mysql\|postgres\|redis'
# 각 Secret 교체

# 외부 접근 가능한 서비스 점검
kubectl get svc -A | grep -E 'LoadBalancer|NodePort'

# NetworkPolicy 강화 (필요한 외부 연결만 허용)
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress-<APP_LABEL>
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      app: <APP_LABEL>
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - port: 53
      protocol: UDP
  - to:
    - podSelector:
        matchLabels:
          app: <DATABASE_APP>
    ports:
    - port: 5432
EOF

# GuardDuty S3 Protection 활성화 (미활성화 상태인 경우)
aws guardduty update-detector \
  --detector-id <DETECTOR_ID> \
  --data-sources '{"S3Logs":{"Enable":true}}'
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 즉시 완전 격리 (자동 실행, 승인 불필요)
2. `get_pod` - pod 정보 및 네트워크 연결 수집
3. `delete_pod` - 격리 후 즉시 pod 삭제 (자동 실행)
4. `rotate_secret` - 유출된 자격증명 교체
5. `patch_deployment` - 취약한 이미지 롤백

승인 필요 여부: P1이므로 Slack 승인 필요. `apply_network_policy`와 `delete_pod`는 즉시 자동 실행. `rotate_secret`과 `patch_deployment`는 승인 후 실행. 5분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 격리 NetworkPolicy 적용 확인
kubectl get networkpolicy isolate-<POD_NAME> -n <NAMESPACE>

# 새 pod에서 외부 연결 없는지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- ss -tnp | \
  grep -v 'kube-dns\|kubernetes.default'

# VPC Flow Logs에서 해당 pod IP의 외부 트래픽 없는지 확인
NEW_POD_IP=$(kubectl get pod <NEW_POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.podIP}')
aws logs filter-log-events \
  --log-group-name "/aws/vpc/flowlogs" \
  --filter-pattern "[version, account, eni, source=$NEW_POD_IP, destination, srcport, destport, protocol, packets, bytes>100000, ...]" \
  --start-time $(date --iso-8601=seconds) \
  --query 'events | length'

# GuardDuty에서 동일 유형 Finding 재발 없는지 확인
aws guardduty list-findings \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": ["UnauthorizedAccess:EKS/ExfiltratedData.Suspicious"]},
      "updatedAt": {"Gte": '$(date -d '1 hour ago' +%s000)'}
    }
  }' \
  --query 'FindingIds | length'
```

---

## 에스컬레이션

자동 대응 실패 또는 5분 내 Slack 승인 없을 때:

1. 유출이 진행 중이면 해당 노드의 Security Group에서 모든 아웃바운드 트래픽을 차단한다.

```bash
NODE_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}')
INSTANCE_ID=$(kubectl get node $NODE_NAME -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
NODE_SG=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)

# 아웃바운드 트래픽 전체 차단 (긴급 조치)
aws ec2 revoke-security-group-egress \
  --group-id $NODE_SG \
  --ip-permissions '[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]'
```

2. 개인정보 또는 민감 데이터 유출이 확인된 경우 법무팀과 개인정보보호 담당자에게 즉시 통보한다. 규정에 따라 72시간 이내 감독기관 신고가 필요할 수 있다.

3. 유출 규모가 크거나 지속적인 경우 AWS Support에 연락해 계정 수준 조사를 요청한다.

4. 담당자 연락: Slack `#security-incidents` 채널. P1 인시던트이므로 즉시 응답 필요. 데이터 유출 규모와 유형에 따라 법적 대응 절차가 필요할 수 있다.
