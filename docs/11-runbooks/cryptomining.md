# 크립토마이닝 (Cryptomining)

## 개요

공격자가 컨테이너 내부에서 크립토마이닝 바이너리를 실행해 클러스터 컴퓨팅 자원을 무단으로 사용하는 공격이다. 초기 침투 후 지속적인 수익 창출을 목적으로 하며, CPU 사용률 급등과 외부 마이닝 풀 연결이 주요 지표다.

- MITRE ATT&CK: T1496 Resource Hijacking
- 심각도: P2 (High)

---

## 탐지 시그널

**GuardDuty Finding**
- `CryptoCurrency:EKS/BitcoinTool.B!DNS` - 알려진 마이닝 풀 도메인으로의 DNS 쿼리
- `CryptoCurrency:EKS/BitcoinTool.B` - 알려진 마이닝 풀 IP로의 직접 연결
- `Execution:EKS/MaliciousFile.Binary` - 악성 바이너리 실행 탐지

**Falco Rule**
- `Known Cryptominer Binary Executed` - xmrig, minerd, cpuminer 등 실행
- `Cryptomining Stratum Protocol Detected` - stratum 포트(3333, 4444, 5555, 7777) 연결

**Tetragon TracingPolicy**
- `block-cryptominer-binaries` - 알려진 마이너 바이너리 execve 이벤트

**기타 지표**
- 노드 CPU 사용률 지속적 90% 이상
- 비정상적인 아웃바운드 TCP 연결 (포트 3333, 4444, 5555, 7777, 14444, 45700)
- 컨테이너 내 예상치 못한 네트워크 연결 수 증가

---

## 초기 분석

**확인할 정보**
- 어떤 pod에서 탐지됐는지
- 실행된 프로세스 이름과 커맨드라인
- 연결된 외부 IP/도메인
- 해당 pod의 이미지 출처
- 동일 이미지를 사용하는 다른 pod 존재 여부

**kubectl 명령어**

```bash
# 탐지된 pod 상세 정보 확인
kubectl describe pod <POD_NAME> -n <NAMESPACE>

# pod 내 실행 중인 프로세스 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps aux

# pod의 네트워크 연결 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp

# 동일 이미지를 사용하는 pod 목록
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep <IMAGE_NAME>

# 최근 이벤트 확인
kubectl get events -n <NAMESPACE> --sort-by='.lastTimestamp' | tail -20

# pod 리소스 사용량 확인
kubectl top pod <POD_NAME> -n <NAMESPACE>
```

**로그 확인 위치**
- CloudWatch Logs: `/aws/eks/<CLUSTER_NAME>/cluster` (audit log)
- GuardDuty Findings: AWS Console > GuardDuty > Findings
- Falco 로그: `kubectl logs -n falco ds/falco | grep <POD_NAME>`
- OpenSearch: `atdr-security-events` 인덱스에서 `pod_name` 필드로 검색

---

## 대응 절차

### 1단계: 즉시 조치 (격리)

감염된 pod의 네트워크를 즉시 차단한다. pod를 삭제하기 전에 증거를 먼저 수집한다.

```bash
# NetworkPolicy로 pod 격리 (인그레스/이그레스 모두 차단)
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

### 2단계: 증거 수집

```bash
# 프로세스 목록 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ps auxf > /tmp/evidence-ps-$(date +%s).txt

# 네트워크 연결 상태 저장
kubectl exec <POD_NAME> -n <NAMESPACE> -- ss -tnp > /tmp/evidence-netstat-$(date +%s).txt

# 컨테이너 파일시스템에서 의심 바이너리 위치 확인
kubectl exec <POD_NAME> -n <NAMESPACE> -- find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null

# pod 스펙 전체 저장
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml > /tmp/evidence-pod-$(date +%s).yaml

# 컨테이너 로그 저장
kubectl logs <POD_NAME> -n <NAMESPACE> --previous > /tmp/evidence-logs-$(date +%s).txt 2>/dev/null
kubectl logs <POD_NAME> -n <NAMESPACE> > /tmp/evidence-logs-current-$(date +%s).txt

# 증거를 S3에 업로드
aws s3 cp /tmp/evidence-* s3://atdr-evidence-bucket/incidents/<INCIDENT_ID>/
```

### 3단계: 근본 원인 분석

```bash
# 이미지 레이어 히스토리 확인 (이미지 변조 여부)
aws ecr describe-images --repository-name <REPO_NAME> --image-ids imageTag=<TAG>

# 이미지 취약점 스캔 결과 확인
aws ecr describe-image-scan-findings --repository-name <REPO_NAME> --image-id imageTag=<TAG>

# pod가 속한 Deployment/DaemonSet 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.metadata.ownerReferences}'

# Deployment 이미지 확인
kubectl get deployment <DEPLOYMENT_NAME> -n <NAMESPACE> -o jsonpath='{.spec.template.spec.containers[*].image}'

# 최근 Deployment 변경 이력
kubectl rollout history deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# ConfigMap, Secret 마운트 확인 (악성 스크립트 주입 여부)
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.volumes}'
```

### 4단계: 복구

```bash
# 감염된 pod 삭제
kubectl delete pod <POD_NAME> -n <NAMESPACE>

# Deployment가 오염된 이미지를 사용 중이면 이전 버전으로 롤백
kubectl rollout undo deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 롤백 상태 확인
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# 격리 NetworkPolicy 제거 (복구 확인 후)
kubectl delete networkpolicy isolate-<POD_NAME> -n <NAMESPACE>

# 새로 생성된 pod 정상 동작 확인
kubectl get pods -n <NAMESPACE> -w
```

### 5단계: 사후 조치

```bash
# 동일 이미지를 사용하는 모든 pod 점검
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep <COMPROMISED_IMAGE>

# ECR 이미지 스캔 강제 실행
aws ecr start-image-scan --repository-name <REPO_NAME> --image-id imageTag=<TAG>

# 오염된 이미지 태그 삭제 (검증 후)
aws ecr batch-delete-image --repository-name <REPO_NAME> --image-ids imageTag=<COMPROMISED_TAG>

# Falco 룰에 해당 바이너리 해시 추가 (커스텀 룰 업데이트)
# GuardDuty Suppression Rule 검토 (오탐 여부 확인)
```

---

## 자동 대응 액션

Remediation Agent가 실행하는 액션 목록:

1. `apply_network_policy` - 감염 pod 즉시 네트워크 격리
2. `get_pod` - pod 상세 정보 및 이미지 정보 수집
3. `delete_pod` - 격리 후 pod 삭제 (Deployment가 새 pod 재생성)
4. `patch_deployment` - 오염된 이미지 사용 시 이전 revision으로 롤백

승인 필요 여부: P2이므로 Slack 승인 필요. 15분 내 응답 없으면 에스컬레이션.

단, `apply_network_policy`(격리)는 승인 없이 즉시 실행한다. 격리는 서비스 영향이 제한적이고 가역적이기 때문이다.

---

## 검증

```bash
# 격리 NetworkPolicy 적용 확인
kubectl get networkpolicy -n <NAMESPACE>

# 새 pod가 정상 이미지로 실행 중인지 확인
kubectl get pod -n <NAMESPACE> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# 마이닝 관련 프로세스 없는지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- ps aux | grep -E 'xmrig|minerd|cpuminer'

# 외부 마이닝 풀 연결 없는지 확인
kubectl exec <NEW_POD_NAME> -n <NAMESPACE> -- ss -tnp | grep -E '3333|4444|5555|7777'

# CPU 사용률 정상화 확인
kubectl top pod -n <NAMESPACE>
```

---

## 에스컬레이션

자동 대응이 실패하거나 15분 내 Slack 승인이 없을 때:

1. 노드 수준 격리가 필요한 경우 해당 노드를 cordon 처리한다.

```bash
# 감염 pod가 실행 중인 노드 확인
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.spec.nodeName}'

# 노드 cordon (신규 pod 스케줄링 차단)
kubectl cordon <NODE_NAME>

# 필요 시 노드 drain
kubectl drain <NODE_NAME> --ignore-daemonsets --delete-emptydir-data
```

2. 동일 노드에서 다수 pod가 감염된 경우 노드를 교체한다.

```bash
# Auto Scaling Group에서 해당 노드 인스턴스 종료
aws autoscaling terminate-instance-in-auto-scaling-group \
  --instance-id <INSTANCE_ID> \
  --should-decrement-desired-capacity false
```

3. 담당자 연락: Slack `#security-incidents` 채널에 인시던트 ID와 함께 수동 대응 요청.
