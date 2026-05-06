# 시크릿 탈취 (Secret Exfiltration)

> 자동 대응은 MCP 도구를 우선 사용한다. 아래 `kubectl` 명령은 운영자 수동 검증 또는 break-glass 절차다.

## 개요

공격자가 컨테이너 내부에서 Kubernetes Secret, ServiceAccount 토큰, 환경변수에 포함된 자격증명, AWS IAM 자격증명 등을 탈취하는 공격이다. 탈취된 자격증명은 횡적 이동이나 클라우드 리소스 접근에 사용된다.

- MITRE ATT&CK: T1552 Unsecured Credentials, T1528 Steal Application Access Token
- 심각도: P1 (Critical)

---

## 탐지 시그널

**GuardDuty Finding**
- `CredentialAccess:EKS/AnomalousBehavior` - 비정상적인 자격증명 접근 패턴
- `UnauthorizedAccess:IAM/InstanceCredentialExfiltration.OutsideAWS` - EC2 메타데이터 자격증명이 AWS 외부에서 사용됨
- `Recon:IAM/UserPermissions` - IAM 권한 열거 시도
- `Discovery:EKS/MaliciousIPCaller` - 악성 IP에서 EKS API 호출

**Falco Rule**
- `ServiceAccount Token Read by Unexpected Process` - 예상치 못한 프로세스가 SA 토큰 접근
- `Sensitive File Access in Container` - `/etc/shadow`, `/root/.ssh/id_rsa` 등 접근
- `Read Environment Variables from Proc Filesystem` - `/proc/<pid>/environ` 읽기 시도
- `AWS Credential Access` - AWS 자격증명 파일 접근

**Tetragon TracingPolicy**
- `detect-secret-access` - 민감 파일 경로 open syscall 이벤트

**기타 지표**
- IMDS(Instance Metadata Service) 엔드포인트(`169.254.169.254`)로의 비정상 접근
- Kubernetes API 서버에 대한 비정상적인 Secret 조회 요청
- 환경변수에서 자격증명 패턴 탐지 (`AWS_ACCESS_KEY`, `DB_PASSWORD` 등)
- 외부 IP로의 소량 데이터 전송 반복

---

## 초기 분석

**확인할 정보**
- 어떤 프로세스가 어떤 파일/경로에 접근했는지
- 접근된 Secret의 종류와 범위
- 탈취된 자격증명이 이미 사용됐는지 (CloudTrail 확인)
- 해당 ServiceAccount의 RBAC 권한 범위
- 외부 전송 여부

**kubectl 명령어**

```bash
# 해당 namespace의 Secret 목록 확인
kubectl get secrets -n <NAMESPACE>

# Secret에 접근 가능한 ServiceAccount 확인
kubectl get rolebinding,clusterrolebinding -n <NAMESPACE> -o json | jq -r '
  .items[] |
  select(.rules[]?.resources[]? == "secrets") |
  [.metadata.name, (.subjects[]? | .name)] | @tsv'

# pod에 마운트된 Secret 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.volumes}'
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].env}'

# ServiceAccount 토큰 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}'
SA_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}')
kubectl get serviceaccount $SA_NAME -n <NAMESPACE> -o yaml

# 컨테이너 내 환경변수 확인 (자격증명 포함 여부)
kubectl exec <POD_NAME> -n <NAMESPACE> -- env | grep -iE 'key|secret|password|token|credential'

# IMDS 접근 여부 확인 (컨테이너 네트워크 로그)
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp | grep 169.254.169.254
```

**CloudTrail/CloudWatch 확인**

```bash
# 해당 SA 토큰으로 실행된 AWS API 호출 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<SERVICE_ACCOUNT_NAME> \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --max-results 50

# IMDS를 통해 발급된 임시 자격증명 사용 여부 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=sts.amazonaws.com \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds)

# 비정상 지역에서의 API 호출 확인
aws cloudtrail lookup-events \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --query 'Events[?awsRegion!=`ap-northeast-2`]'
```

**로그 확인 위치**
- CloudTrail: 자격증명 사용 이력
- CloudWatch Logs: `/aws/eks/<CLUSTER_NAME>/cluster` (Secret 접근 audit log)
- GuardDuty: CredentialAccess 유형 Finding

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

자격증명 탈취가 확인되면 즉시 두 가지를 병행한다. pod 격리와 자격증명 무효화.

```bash
# pod 네트워크 격리
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

# ServiceAccount 토큰 즉시 무효화 (토큰 삭제 시 자동 재발급되므로 SA 자체를 비활성화)
# 방법 1: SA에 연결된 Secret 삭제
kubectl get secrets -n <NAMESPACE> -o json | jq -r '
  .items[] |
  select(.metadata.annotations["kubernetes.io/service-account.name"] == "<SA_NAME>") |
  .metadata.name' | xargs kubectl delete secret -n <NAMESPACE>

# 방법 2: SA의 automountServiceAccountToken 비활성화
kubectl patch serviceaccount <SA_NAME> -n <NAMESPACE> \
  -p '{"automountServiceAccountToken": false}'
```

### 2단계: 증거 수집

```bash
# 컨테이너 내 접근된 파일 목록 (최근 변경/접근 파일)
kubectl exec <POD_NAME> -n <NAMESPACE> -- find /var/run/secrets /etc -newer /tmp -type f 2>/dev/null \
  > /tmp/evidence-files-$(date +%s).txt

# 환경변수 전체 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- env > /tmp/evidence-env-$(date +%s).txt

# 네트워크 연결 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp > /tmp/evidence-net-$(date +%s).txt

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# audit log에서 Secret 접근 이벤트 수집
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.objectRef.resource = "secrets" }' \
  --start-time $(date -d '2 hours ago' +%s000) \
  > /tmp/evidence-secret-audit-$(date +%s).json

# CloudTrail 이벤트 저장
aws cloudtrail lookup-events \
  --start-time $(date -d '2 hours ago' --iso-8601=seconds) \
  --output json > /tmp/evidence-cloudtrail-$(date +%s).json

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 탈취된 자격증명 유형 파악
# 1) Kubernetes SA 토큰인 경우
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}'

# 2) AWS IRSA 자격증명인 경우 - 연결된 IAM Role 확인
SA_NAME=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}')
kubectl get serviceaccount $SA_NAME -n <NAMESPACE> -o jsonpath='{.metadata.annotations}'

# 3) 환경변수로 주입된 자격증명인 경우 - Secret 출처 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].envFrom}'

# 자격증명이 외부에서 사용됐는지 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<ACCESS_KEY_ID> \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds)

# 공격 진입점 파악 (어떻게 pod에 접근했는지)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.objectRef.name = "<POD_NAME>" && $.verb = "create" }' \
  --start-time $(date -d '24 hours ago' +%s000)
```

### 4단계: 복구

```bash
# 탈취된 자격증명 유형별 무효화

# 1) Kubernetes SA 토큰 - SA 재생성
kubectl delete serviceaccount <SA_NAME> -n <NAMESPACE>
kubectl create serviceaccount <SA_NAME> -n <NAMESPACE>

# 2) AWS IAM 자격증명 - 액세스 키 비활성화
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --user-name <IAM_USER_NAME>

# 3) IRSA - IAM Role의 신뢰 정책 수정 (해당 SA 제거)
aws iam update-assume-role-policy \
  --role-name <ROLE_NAME> \
  --policy-document file://updated-trust-policy.json

# 4) Kubernetes Secret 교체
kubectl create secret generic <SECRET_NAME> \
  --from-literal=<KEY>=<NEW_VALUE> \
  --dry-run=client -o yaml | kubectl apply -f -

# 감염된 pod 삭제 및 재배포
kubectl delete pod <POD_NAME> -n <NAMESPACE>
kubectl rollout restart deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 격리 NetworkPolicy 제거
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>
```

### 5단계: 사후 조치

```bash
# 동일 Secret을 마운트하는 다른 pod 점검
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.volumes[]?.secret.secretName == "<SECRET_NAME>") |
  [.metadata.namespace, .metadata.name] | @tsv'

# Secret에 대한 RBAC 권한 최소화
kubectl get rolebinding,clusterrolebinding -A -o json | jq -r '
  .items[] |
  select(.rules[]?.resources[]? == "secrets") |
  [.kind, .metadata.namespace // "cluster", .metadata.name] | @tsv'

# IMDS v2 강제 적용 (IMDSv1 차단)
aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Secret을 환경변수 대신 외부 시크릿 매니저로 이관 검토
# AWS Secrets Manager + External Secrets Operator 사용 권장
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 즉시 네트워크 격리 (자동 실행)
2. `get_pod` - 마운트된 Secret 및 환경변수 목록 수집
3. `rotate_secret` - 탈취된 Kubernetes Secret 값 교체
4. `patch_deployment` - automountServiceAccountToken 비활성화
5. `delete_pod` - 감염 pod 삭제

승인 필요 여부: P1이므로 Slack 승인 필요. `apply_network_policy`는 즉시 자동 실행. `rotate_secret`과 IAM 자격증명 무효화는 승인 후 실행. 5분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# SA 토큰 재발급 확인
kubectl get secrets -n <NAMESPACE> | grep <SA_NAME>

# 새 pod가 새 토큰을 사용하는지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token | \
  cut -d. -f2 | base64 -d 2>/dev/null | jq .iat

# 이전 자격증명으로 API 호출 시 거부되는지 확인
aws sts get-caller-identity --profile <OLD_CREDENTIALS_PROFILE> 2>&1 | grep -i invalid

# CloudTrail에서 이전 자격증명 사용 시도 모니터링
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<OLD_ACCESS_KEY_ID> \
  --start-time $(date --iso-8601=seconds)
```

---

## 에스컬레이션

자동 대응 실패 또는 5분 내 Slack 승인 없을 때:

1. 탈취된 자격증명이 AWS 외부에서 사용된 경우 즉시 IAM 자격증명을 비활성화한다.

```bash
# 해당 IAM Role의 모든 세션 무효화
aws iam put-role-policy \
  --role-name <ROLE_NAME> \
  --policy-name DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

2. 광범위한 자격증명 노출이 의심되면 해당 namespace의 모든 Secret을 교체한다.

```bash
# namespace 내 모든 Secret 목록 확인
kubectl get secrets -n <NAMESPACE> -o name

# 각 Secret 교체 (값은 별도 보안 채널로 전달받아 입력)
```

3. 담당자 연락: Slack `#security-incidents` 채널. AWS 계정 수준 침해가 의심되면 AWS Support에도 즉시 연락.
