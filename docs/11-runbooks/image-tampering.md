# 이미지 변조 (Image Tampering)

## 개요

공격자가 컨테이너 이미지에 악성 코드를 삽입하거나, 신뢰할 수 없는 레지스트리의 이미지를 배포하는 공격이다. CI/CD 파이프라인 침해, ECR 접근 권한 탈취, 또는 이미지 태그 하이재킹을 통해 발생한다. 감염된 이미지는 클러스터 전체로 확산될 수 있다.

- MITRE ATT&CK: T1610 Deploy Container, T1195.002 Compromise Software Supply Chain
- 심각도: P2 (High)

---

## 탐지 시그널

**GuardDuty Finding**
- `Trojan:EKS/DockerLayerInjection.B` - 컨테이너 이미지 레이어에 악성 코드 삽입 탐지
- `Execution:EKS/MaliciousFile.Binary` - 이미지에서 악성 바이너리 실행
- `Backdoor:EKS/MaliciousFile` - 이미지 내 백도어 파일 탐지
- `UnauthorizedAccess:ECR/MaliciousIPCaller` - 악성 IP에서 ECR 접근

**Falco Rule**
- `Launch Disallowed Container` - 허용 목록에 없는 이미지 실행
- `Container Image Not From Trusted Registry` - 신뢰할 수 없는 레지스트리 이미지 실행
- `Unexpected Spawned Process` - 이미지 정의에 없는 프로세스 실행
- `Write Below Binary Dir` - `/bin`, `/usr/bin` 등 바이너리 디렉터리에 파일 쓰기

**Tetragon TracingPolicy**
- `detect-image-tampering` - 바이너리 디렉터리 수정 및 예상치 못한 실행 파일 이벤트

**기타 지표**
- ECR 이미지 다이제스트 불일치 (배포된 이미지와 레지스트리 이미지 해시 다름)
- 이미지 스캔에서 새로운 CRITICAL 취약점 탐지
- 예상치 못한 이미지 레이어 추가 (이미지 히스토리 변경)
- CI/CD 파이프라인 외부에서 ECR push 이벤트 발생
- 이미지 태그가 다른 다이제스트를 가리키도록 변경됨

---

## 초기 분석

**확인할 정보**
- 실행 중인 이미지의 다이제스트와 ECR의 다이제스트 일치 여부
- 이미지 레이어 히스토리 변경 여부
- ECR에 이미지를 push한 주체
- CI/CD 파이프라인 정상 동작 여부
- 동일 이미지를 사용하는 다른 pod 범위

**kubectl 명령어**

```bash
# 실행 중인 이미지 다이제스트 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.containerStatuses[*].imageID}'

# ECR에서 해당 이미지 태그의 다이제스트 확인
aws ecr describe-images \
  --repository-name <REPO_NAME> \
  --image-ids imageTag=<TAG> \
  --query 'imageDetails[0].imageDigest'

# 두 다이제스트 비교 (불일치 시 이미지 변조 의심)
RUNNING_DIGEST=$(kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.containerStatuses[0].imageID}' | cut -d@ -f2)
ECR_DIGEST=$(aws ecr describe-images --repository-name <REPO_NAME> --image-ids imageTag=<TAG> --query 'imageDetails[0].imageDigest' --output text)
echo "Running: $RUNNING_DIGEST"
echo "ECR:     $ECR_DIGEST"
[ "$RUNNING_DIGEST" = "$ECR_DIGEST" ] && echo "MATCH" || echo "MISMATCH - POSSIBLE TAMPERING"

# 동일 이미지를 사용하는 모든 pod 확인
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | \
  grep <IMAGE_NAME>

# 이미지 레이어 히스토리 확인
aws ecr batch-get-image \
  --repository-name <REPO_NAME> \
  --image-ids imageTag=<TAG> \
  --query 'images[0].imageManifest' \
  --output text | jq '.history'

# 컨테이너 내 예상치 못한 바이너리 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- find /bin /usr/bin /usr/local/bin -newer /etc/passwd -type f 2>/dev/null
```

**ECR 접근 이력 확인**

```bash
# ECR에 이미지를 push한 주체 확인 (CloudTrail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time $(date -d '48 hours ago' --iso-8601=seconds) \
  --query 'Events[?Resources[?ResourceName==`<REPO_NAME>`]]'

# ECR 레포지토리 정책 확인
aws ecr get-repository-policy --repository-name <REPO_NAME> 2>/dev/null

# ECR 이미지 스캔 결과 확인
aws ecr describe-image-scan-findings \
  --repository-name <REPO_NAME> \
  --image-id imageTag=<TAG> \
  --query 'imageScanFindings.findings[?severity==`CRITICAL`]'
```

**로그 확인 위치**
- CloudTrail: ECR PutImage, GetAuthorizationToken 이벤트
- GuardDuty Findings: Trojan, Backdoor 유형
- Falco 로그: `kubectl logs -n falco ds/falco | grep -iE 'image|registry|binary'`
- CI/CD 파이프라인 로그 (CodePipeline, GitHub Actions 등)

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

변조된 이미지를 사용하는 pod를 즉시 격리하고 추가 배포를 차단한다.

```bash
# 변조된 이미지를 사용하는 모든 pod 네트워크 격리
# 레이블 기반으로 일괄 격리
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-tampered-image
  namespace: <NAMESPACE>
spec:
  podSelector:
    matchLabels:
      app: <APP_LABEL>
  policyTypes:
  - Ingress
  - Egress
EOF

# Deployment 스케일 0으로 즉시 중단 (추가 pod 생성 차단)
kubectl scale deployment <DEPLOYMENT_NAME> -n <NAMESPACE> --replicas=0

# ECR 이미지 pull 차단 (레포지토리 정책으로 특정 태그 접근 제한)
aws ecr set-repository-policy \
  --repository-name <REPO_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyPull",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
      "Condition": {
        "StringEquals": {
          "ecr:ResourceTag/status": "compromised"
        }
      }
    }]
  }'

# 변조된 이미지 태그에 compromised 레이블 추가
aws ecr tag-resource \
  --resource-arn arn:aws:ecr:<REGION>:<ACCOUNT_ID>:repository/<REPO_NAME> \
  --tags Key=status,Value=compromised
```

### 2단계: 증거 수집

```bash
# 실행 중인 컨테이너의 파일시스템 스냅샷
kubectl exec <POD_NAME> -n <NAMESPACE> -- find / -newer /etc/os-release -type f 2>/dev/null | \
  grep -v '/proc\|/sys\|/dev' > /tmp/evidence-newfiles-$(date +%s).txt

# 컨테이너 내 예상치 못한 바이너리 해시 수집
kubectl exec <POD_NAME> -n <NAMESPACE> -- \
  find /bin /usr/bin /usr/local/bin -type f -exec md5sum {} \; 2>/dev/null \
  > /tmp/evidence-binhash-$(date +%s).txt

# 이미지 매니페스트 저장
aws ecr batch-get-image \
  --repository-name <REPO_NAME> \
  --image-ids imageTag=<TAG> \
  --output json > /tmp/evidence-manifest-$(date +%s).json

# ECR push 이력 저장
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --output json > /tmp/evidence-ecr-push-$(date +%s).json

# pod 스펙 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# Falco 로그 저장
kubectl logs -n falco ds/falco --since=4h | grep -E '<IMAGE_NAME>|<POD_NAME>' \
  > /tmp/evidence-falco-$(date +%s).txt

# 증거 S3 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# CI/CD 파이프라인 침해 여부 확인
# CodePipeline 실행 이력
aws codepipeline list-pipeline-executions \
  --pipeline-name <PIPELINE_NAME> \
  --max-results 10

# 비정상적인 ECR push 주체 확인
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time $(date -d '7 days ago' --iso-8601=seconds) \
  --query 'Events[*].{Time:EventTime,User:Username,Source:SourceIPAddress}'

# 이미지 레이어 비교 (정상 이미지 vs 변조 이미지)
# 정상 이미지 다이제스트 (이전 배포 이력에서 확인)
kubectl rollout history deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>
PREV_IMAGE=$(kubectl rollout history deployment/<DEPLOYMENT_NAME> -n <NAMESPACE> --revision=<PREV_REVISION> -o jsonpath='{.spec.template.spec.containers[*].image}')

# 이전 이미지와 현재 이미지 레이어 비교
aws ecr batch-get-image \
  --repository-name <REPO_NAME> \
  --image-ids imageDigest=<PREV_DIGEST> \
  --query 'images[0].imageManifest' | jq '.layers[].digest' > /tmp/prev-layers.txt

aws ecr batch-get-image \
  --repository-name <REPO_NAME> \
  --image-ids imageTag=<CURRENT_TAG> \
  --query 'images[0].imageManifest' | jq '.layers[].digest' > /tmp/current-layers.txt

diff /tmp/prev-layers.txt /tmp/current-layers.txt

# IAM 자격증명 탈취 여부 확인 (ECR push에 사용된 자격증명)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetAuthorizationToken \
  --start-time $(date -d '48 hours ago' --iso-8601=seconds) \
  --query 'Events[*].{Time:EventTime,User:Username,Source:SourceIPAddress}'
```

### 4단계: 복구

```bash
# 변조된 이미지 태그 삭제
aws ecr batch-delete-image \
  --repository-name <REPO_NAME> \
  --image-ids imageTag=<COMPROMISED_TAG>

# 검증된 이전 이미지로 Deployment 롤백
kubectl rollout undo deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 또는 신뢰할 수 있는 이미지 다이제스트로 직접 지정
kubectl set image deployment/<DEPLOYMENT_NAME> \
  <CONTAINER_NAME>=<REPO_URI>@<TRUSTED_DIGEST> \
  -n <NAMESPACE>

# Deployment 스케일 복구
kubectl scale deployment <DEPLOYMENT_NAME> -n <NAMESPACE> --replicas=<ORIGINAL_REPLICAS>

# 격리 NetworkPolicy 제거
kubectl delete networkpolicy isolate-tampered-image -n <NAMESPACE>

# ECR 레포지토리 정책 복원
aws ecr delete-repository-policy --repository-name <REPO_NAME>
```

### 5단계: 사후 조치

```bash
# 동일 이미지를 사용하는 모든 Deployment 점검
kubectl get deployments -A -o json | jq -r '
  .items[] |
  select(.spec.template.spec.containers[].image | test("<IMAGE_NAME>")) |
  [.metadata.namespace, .metadata.name, .spec.template.spec.containers[].image] | @tsv'

# ECR 이미지 스캔 자동화 활성화
aws ecr put-image-scanning-configuration \
  --repository-name <REPO_NAME> \
  --image-scanning-configuration scanOnPush=true

# ECR 이미지 불변성 활성화 (태그 덮어쓰기 방지)
aws ecr put-image-tag-mutability \
  --repository-name <REPO_NAME> \
  --image-tag-mutability IMMUTABLE

# Admission Controller로 서명된 이미지만 허용 (Cosign + Kyverno)
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-signature
    match:
      resources:
        kinds:
        - Pod
    verifyImages:
    - imageReferences:
      - "<ECR_REGISTRY>/<REPO_NAME>:*"
      attestors:
      - entries:
        - keyless:
            subject: "https://github.com/<ORG>/<REPO>/.github/workflows/*.yml@refs/heads/main"
            issuer: "https://token.actions.githubusercontent.com"
EOF

# CI/CD 파이프라인 자격증명 교체
# GitHub Actions secrets, CodePipeline IAM Role 등 점검
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 변조 이미지 사용 pod 즉시 격리
2. `get_pod` - 실행 중인 이미지 다이제스트 수집
3. `patch_deployment` - 이전 검증된 이미지 다이제스트로 롤백
4. `delete_pod` - 변조 이미지 사용 pod 삭제

승인 필요 여부: P2이므로 Slack 승인 필요. `apply_network_policy`는 즉시 자동 실행. `patch_deployment`(롤백)는 승인 후 실행. 15분 타임아웃 후 에스컬레이션.

---

## 검증

```bash
# 새 pod가 신뢰할 수 있는 이미지 다이제스트로 실행 중인지 확인
kubectl get pod -n <NAMESPACE> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[*].imageID}{"\n"}{end}'

# 실행 중인 이미지 다이제스트와 ECR 다이제스트 일치 확인
RUNNING_DIGEST=$(kubectl get pod <NEW_POD_NAME> -n <NAMESPACE> -o jsonpath='{.status.containerStatuses[0].imageID}' | cut -d@ -f2)
ECR_DIGEST=$(aws ecr describe-images --repository-name <REPO_NAME> --image-ids imageTag=<TRUSTED_TAG> --query 'imageDetails[0].imageDigest' --output text)
[ "$RUNNING_DIGEST" = "$ECR_DIGEST" ] && echo "VERIFIED" || echo "MISMATCH"

# ECR 이미지 스캔 결과 확인 (새 이미지)
aws ecr describe-image-scan-findings \
  --repository-name <REPO_NAME> \
  --image-id imageTag=<TRUSTED_TAG> \
  --query 'imageScanFindings.findingSeverityCounts'

# Falco에서 추가 이미지 관련 이벤트 없는지 확인
kubectl logs -n falco ds/falco --since=10m | grep -iE 'image|registry|binary dir'
```

---

## 에스컬레이션

자동 대응 실패 또는 15분 내 Slack 승인 없을 때:

1. 변조된 이미지를 사용하는 모든 Deployment를 즉시 스케일 0으로 내린다.

```bash
# 변조 이미지를 사용하는 모든 Deployment 중단
kubectl get deployments -A -o json | jq -r '
  .items[] |
  select(.spec.template.spec.containers[].image | test("<COMPROMISED_IMAGE>")) |
  [.metadata.namespace, .metadata.name] | @tsv' | \
  while IFS=$'\t' read ns name; do
    kubectl scale deployment $name -n $ns --replicas=0
  done
```

2. ECR 레포지토리 전체 접근을 일시 차단한다.

```bash
aws ecr set-repository-policy \
  --repository-name <REPO_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyAll",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "ecr:*"
    }]
  }'
```

3. CI/CD 파이프라인을 즉시 중단하고 담당자에게 보고한다.

4. 담당자 연락: Slack `#security-incidents` 채널. 소프트웨어 공급망 침해가 의심되므로 전체 파이프라인 감사가 필요하다.
