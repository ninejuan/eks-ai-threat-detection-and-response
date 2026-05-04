# RBAC 남용 (RBAC Abuse)

## 개요

공격자가 과도하게 부여된 Kubernetes RBAC 권한을 이용하거나, 새로운 ClusterRoleBinding을 생성해 cluster-admin 권한을 획득하는 공격이다. 합법적인 자격증명을 사용하기 때문에 탐지가 어렵고, 성공 시 클러스터 전체를 장악할 수 있다.

- MITRE ATT&CK: T1078 Valid Accounts, T1098 Account Manipulation
- 심각도: P2 (High)

---

## 탐지 시그널

**GuardDuty Finding**
- `PrivilegeEscalation:EKS/AnomalousBehavior` - 비정상적인 권한 상승 패턴
- `Persistence:EKS/AnomalousBehavior` - 비정상적인 RBAC 리소스 생성
- `Discovery:EKS/MaliciousIPCaller` - 악성 IP에서 RBAC 리소스 조회
- `CredentialAccess:EKS/AnomalousBehavior` - 비정상적인 자격증명 사용

**Falco Rule**
- `ClusterRole With Wildcard Created` - 와일드카드 권한을 가진 ClusterRole 생성
- `ClusterRoleBinding To Cluster Admin` - cluster-admin에 대한 새 바인딩 생성
- `Attach To Cluster Admin ClusterRole` - cluster-admin 역할 바인딩 시도
- `Create Sensitive Mount Pod` - 민감한 마운트를 가진 pod 생성 시도

**Tetragon TracingPolicy**
- `detect-rbac-abuse` - Kubernetes API 서버에 대한 비정상적인 RBAC 변경 이벤트

**기타 지표**
- 업무 시간 외 ClusterRoleBinding 생성
- 알 수 없는 사용자 또는 ServiceAccount에 cluster-admin 바인딩
- 짧은 시간 내 다수의 RBAC 리소스 조회 (권한 열거)
- `*` 동사 또는 `*` 리소스를 포함한 Role/ClusterRole 생성
- 기존 ClusterRoleBinding 수정 (subjects 추가)

---

## 초기 분석

**확인할 정보**
- 어떤 주체가 RBAC 변경을 수행했는지
- 변경된 RBAC 리소스의 내용
- 변경 시점과 출처 IP
- 새로 부여된 권한으로 실제 액션이 수행됐는지
- 정상적인 운영 변경인지 여부

**kubectl 명령어**

```bash
# cluster-admin 바인딩 전체 목록 확인
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  [.metadata.name, .metadata.creationTimestamp,
   (.subjects[]? | .kind + "/" + (.namespace // "cluster") + "/" + .name)] | @tsv'

# 최근 생성된 ClusterRoleBinding 확인 (24시간 이내)
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.metadata.creationTimestamp > (now - 86400 | todate)) |
  [.metadata.name, .metadata.creationTimestamp, .roleRef.name] | @tsv'

# 와일드카드 권한을 가진 ClusterRole 확인
kubectl get clusterrole -o json | jq -r '
  .items[] |
  select(.rules[]? | (.verbs[]? == "*") or (.resources[]? == "*")) |
  [.metadata.name, (.rules[] | [.verbs, .resources] | @json)] | @tsv'

# 특정 SA의 실제 권한 확인
kubectl auth can-i --list --as=system:serviceaccount:<NAMESPACE>:<SA_NAME>

# 특정 사용자의 실제 권한 확인
kubectl auth can-i --list --as=<USERNAME>

# 최근 RBAC 관련 audit log 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.objectRef.resource = "clusterrolebindings" || $.objectRef.resource = "rolebindings" }' \
  --start-time $(date -d '24 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .verb, .objectRef.resource, .objectRef.name, .user.username, .sourceIPs[0]] | @tsv'
```

**권한 열거 탐지**

```bash
# 짧은 시간 내 다수의 RBAC 조회 (권한 열거 패턴)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.verb = "list" && ($.objectRef.resource = "roles" || $.objectRef.resource = "clusterroles" || $.objectRef.resource = "rolebindings") }' \
  --start-time $(date -d '1 hour ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .user.username, .objectRef.resource] | @tsv' | \
  sort | uniq -c | sort -rn | head -20

# 특정 사용자의 API 호출 패턴 분석
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"<SUSPICIOUS_USER>\" }" \
  --start-time $(date -d '2 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .verb, .objectRef.resource, .objectRef.name] | @tsv'
```

**로그 확인 위치**
- CloudWatch Logs: `/aws/eks/<CLUSTER_NAME>/cluster` (RBAC 변경 audit log)
- GuardDuty Findings: PrivilegeEscalation, Persistence 유형
- Falco 로그: `kubectl logs -n falco ds/falco | grep -iE 'clusterrole|rbac|admin'`

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

의심스러운 ClusterRoleBinding을 즉시 제거하거나 비활성화한다.

```bash
# 의심스러운 ClusterRoleBinding 즉시 삭제
kubectl delete clusterrolebinding <SUSPICIOUS_BINDING_NAME>

# 의심스러운 RoleBinding 삭제
kubectl delete rolebinding <SUSPICIOUS_BINDING_NAME> -n <NAMESPACE>

# 해당 사용자/SA의 kubeconfig 자격증명 즉시 무효화
# AWS IAM 사용자인 경우
aws iam update-access-key \
  --access-key-id <ACCESS_KEY_ID> \
  --status Inactive \
  --user-name <IAM_USER_NAME>

# ServiceAccount인 경우 토큰 무효화
kubectl patch serviceaccount <SA_NAME> -n <NAMESPACE> \
  -p '{"automountServiceAccountToken": false}'

# 해당 SA의 기존 토큰 삭제
kubectl get secrets -n <NAMESPACE> -o json | jq -r '
  .items[] |
  select(.metadata.annotations["kubernetes.io/service-account.name"] == "<SA_NAME>") |
  .metadata.name' | xargs kubectl delete secret -n <NAMESPACE>
```

### 2단계: 증거 수집

```bash
# 현재 RBAC 상태 전체 저장
kubectl get clusterrole,clusterrolebinding -o yaml > /tmp/evidence-clusterrbac-$(date +%s).yaml
kubectl get role,rolebinding -A -o yaml > /tmp/evidence-nsrbac-$(date +%s).yaml

# 의심스러운 바인딩 상세 저장
kubectl get clusterrolebinding <SUSPICIOUS_BINDING_NAME> -o yaml \
  > /tmp/evidence-binding-$(date +%s).yaml

# audit log 수집 (RBAC 변경 이력 전체)
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern '{ $.objectRef.resource = "clusterrolebindings" || $.objectRef.resource = "rolebindings" || $.objectRef.resource = "clusterroles" || $.objectRef.resource = "roles" }' \
  --start-time $(date -d '48 hours ago' +%s000) \
  > /tmp/evidence-rbac-audit-$(date +%s).json

# 해당 사용자의 모든 API 호출 이력
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"<SUSPICIOUS_USER>\" }" \
  --start-time $(date -d '48 hours ago' +%s000) \
  > /tmp/evidence-user-audit-$(date +%s).json

# CloudTrail에서 해당 사용자의 AWS API 호출 이력
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<IAM_USER_NAME> \
  --start-time $(date -d '48 hours ago' --iso-8601=seconds) \
  --output json > /tmp/evidence-cloudtrail-$(date +%s).json

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# RBAC 변경을 수행한 주체의 출처 IP 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.objectRef.name = \"<SUSPICIOUS_BINDING_NAME>\" && $.verb = \"create\" }" \
  --start-time $(date -d '48 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .user.username, .sourceIPs[0], .userAgent] | @tsv'

# 해당 IP의 다른 API 호출 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.sourceIPs[0] = \"<SOURCE_IP>\" }" \
  --start-time $(date -d '48 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .verb, .objectRef.resource, .objectRef.name] | @tsv'

# 새로 부여된 권한으로 실제 액션 수행 여부 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"<SUSPICIOUS_USER>\" && $.responseStatus.code = 200 }" \
  --start-time $(date -d '24 hours ago' +%s000) \
  --query 'events[*].message' | \
  jq -r '.[] | fromjson | [.requestReceivedTimestamp, .verb, .objectRef.resource, .objectRef.name] | @tsv'

# 초기 침투 경로 파악 (어떻게 자격증명을 획득했는지)
# kubeconfig 파일 노출, SA 토큰 탈취, IAM 자격증명 탈취 등 검토
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<IAM_USER_NAME> \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[?EventName==`GetCallerIdentity` || EventName==`AssumeRole`]'
```

### 4단계: 복구

```bash
# 의심스러운 RBAC 리소스 모두 제거
kubectl delete clusterrolebinding <SUSPICIOUS_BINDING_NAME>

# 정상 RBAC 상태로 복원 (GitOps 파이프라인 통해 재적용)
# 또는 백업에서 복원
kubectl apply -f /tmp/rbac-baseline-backup.yaml

# 침해된 자격증명 교체
# IAM 사용자인 경우 새 액세스 키 발급
aws iam create-access-key --user-name <IAM_USER_NAME>
aws iam delete-access-key \
  --access-key-id <OLD_ACCESS_KEY_ID> \
  --user-name <IAM_USER_NAME>

# SA인 경우 새 SA 생성 및 최소 권한 재부여
kubectl delete serviceaccount <SA_NAME> -n <NAMESPACE>
kubectl create serviceaccount <SA_NAME> -n <NAMESPACE>

# EKS 클러스터 액세스 엔트리 검토 (aws-auth ConfigMap 또는 EKS Access Entry)
kubectl get configmap aws-auth -n kube-system -o yaml
# 또는
aws eks list-access-entries --cluster-name <CLUSTER_NAME>
```

### 5단계: 사후 조치

```bash
# 전체 RBAC 권한 감사 (과도한 권한 식별)
# cluster-admin 바인딩 목록
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  [.metadata.name, (.subjects[]? | .kind + "/" + .name)] | @tsv'

# 와일드카드 권한 ClusterRole 목록
kubectl get clusterrole -o json | jq -r '
  .items[] |
  select(.rules[]? | (.verbs[]? == "*") or (.resources[]? == "*")) |
  select(.metadata.name | test("^system:") | not) |
  .metadata.name'

# RBAC 변경에 대한 AlertRule 추가 (CloudWatch Metric Filter)
aws logs put-metric-filter \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-name "rbac-changes" \
  --filter-pattern '{ $.objectRef.resource = "clusterrolebindings" && $.verb = "create" }' \
  --metric-transformations \
    metricName=RBACChanges,metricNamespace=ATDR/Security,metricValue=1

# EKS Access Entry로 마이그레이션 (aws-auth ConfigMap 대신 사용 권장)
aws eks create-access-entry \
  --cluster-name <CLUSTER_NAME> \
  --principal-arn <IAM_ROLE_ARN> \
  --type STANDARD

# 최소 권한 원칙 적용: 네임스페이스 범위 Role 사용 권장
# ClusterRole 대신 Role + RoleBinding 조합으로 교체
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `get_pod` - 관련 pod 및 SA 정보 수집
2. `delete_cluster_role_binding` - 의심스러운 ClusterRoleBinding 즉시 삭제
3. `patch_cluster_role_binding` - 과도한 권한 바인딩 수정 (subjects 제거)
4. `rotate_secret` - 침해된 SA 토큰 교체

승인 필요 여부: P2이므로 Slack 승인 필요. `delete_cluster_role_binding`은 서비스 영향이 있을 수 있으므로 승인 후 실행. 15분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 의심스러운 바인딩 제거 확인
kubectl get clusterrolebinding <SUSPICIOUS_BINDING_NAME> 2>&1 | grep -i 'not found'

# 해당 사용자의 권한이 제거됐는지 확인
kubectl auth can-i create pods --as=<SUSPICIOUS_USER> -n kube-system

# cluster-admin 바인딩 목록이 정상인지 확인
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  [.metadata.name, (.subjects[]? | .kind + "/" + .name)] | @tsv'

# audit log에서 해당 사용자의 추가 API 호출 없는지 확인
aws logs filter-log-events \
  --log-group-name "/aws/eks/<CLUSTER_NAME>/cluster" \
  --filter-pattern "{ $.user.username = \"<SUSPICIOUS_USER>\" }" \
  --start-time $(date --iso-8601=seconds) \
  --query 'events[*].message' | jq length
```

---

## 에스컬레이션

자동 대응 실패 또는 15분 내 Slack 승인 없을 때:

1. 침해된 자격증명으로 cluster-admin 권한이 행사됐다면 클러스터 전체 RBAC를 감사하고 비정상 리소스를 모두 제거한다.

```bash
# 최근 24시간 내 생성된 모든 RBAC 리소스 확인
kubectl get clusterrole,clusterrolebinding,role,rolebinding -A -o json | \
  jq -r '.items[] | select(.metadata.creationTimestamp > (now - 86400 | todate)) | [.kind, .metadata.namespace // "cluster", .metadata.name, .metadata.creationTimestamp] | @tsv'
```

2. EKS API 서버 엔드포인트 접근을 허용 IP로 제한한다.

```bash
aws eks update-cluster-config \
  --name <CLUSTER_NAME> \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=<ALLOWED_CIDR_LIST>
```

3. 담당자 연락: Slack `#security-incidents` 채널. cluster-admin 권한 남용이 확인된 경우 전체 클러스터 감사가 필요하므로 즉시 응답 요청.
