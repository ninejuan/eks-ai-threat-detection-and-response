# 07. 포렌식 준비 전략 (Forensic Readiness)

> 증거 보전, 불변 저장, 장기 감사 추적 설계

---

## 1. 포렌식 전략 개요

### 증거 보전 원칙

포렌식 준비(Forensic Readiness)는 인시던트가 발생하기 전에 증거 수집과 보전 체계를 갖추는 것이다. ATDR은 세 가지 원칙을 기반으로 포렌식 파이프라인을 설계한다.

| 원칙 | 설명 | 구현 |
|------|------|------|
| 무결성 | 수집된 증거가 변조되지 않았음을 보장 | S3 Object Lock + KMS 암호화 + SHA-256 해시 |
| 불변성 | 저장된 데이터를 삭제하거나 덮어쓸 수 없음 | WORM(Write Once Read Many) 정책 |
| 추적 가능성 | 누가 언제 어떤 증거에 접근했는지 기록 | CloudTrail + S3 Access Logs |

### Chain of Custody

증거의 수집부터 분석까지 모든 접근 이력을 기록한다.

```
이벤트 발생
    │
    ▼
자동 수집 (Falco, GuardDuty, Hubble)
    │
    ▼
S3 Object Lock 저장 (타임스탬프 + SHA-256)
    │
    ▼
접근 로그 기록 (CloudTrail + S3 Access Logs)
    │
    ▼
분석 (읽기 전용 복사본 사용)
    │
    ▼
보고서 생성 (원본 해시 포함)
```

분석 시에는 원본 데이터를 직접 사용하지 않는다. S3에서 별도 버킷으로 복사한 후 읽기 전용으로 분석한다. 원본 버킷의 Object Lock 설정은 분석 과정에서도 유지된다.

### 포렌식 심도 계층

ATDR의 포렌식 전략은 모든 환경에서 안정적으로 동작하는 기본 경로와, 더 깊은 분석을 제공하는 선택 경로를 분리한다. 핵심 대응 경로는 특정 노드 런타임 기능에 의존하지 않아야 하며, 고급 포렌식 기능이 실패해도 증거 수집과 대응 흐름은 계속 진행되어야 한다.

| 계층 | 이름 | 목적 | 기본 상태 | 실패 시 처리 |
|------|------|------|-----------|--------------|
| Core | Evidence Bundle | 런타임/네트워크/컨트롤 플레인 증거를 안정적으로 수집 | 항상 실행 | 실패 항목을 manifest에 기록하고 가능한 증거로 계속 진행 |
| Core | Forensic Synthesis | 수집 증거를 AI가 타임라인, IOC, TTP, 대응 근거로 재구성 | 항상 실행 | 누락 증거를 명시하고 부분 리포트 생성 |
| Advanced | Ephemeral Container Live Forensics | 실행 중인 파드의 프로세스/네트워크/파일 상태를 제한된 프로파일로 수집 | 승인 기반 선택 실행 | 미지원/실패 사유를 기록하고 Core evidence로 fallback |
| Experimental | CRIU Container Checkpoint | 지원 노드에서 컨테이너 메모리/프로세스 상태를 checkpoint로 보존 | 명시적 승인 기반 실험 기능 | `unsupported` 또는 실패 사유를 기록하고 live forensics/Core evidence로 fallback |

이 계층화의 목적은 CRIU 같은 고위험 기능을 핵심 성공 조건으로 만들지 않는 것이다. ATDR의 기본 완성도는 Evidence Bundle과 Forensic Synthesis에서 확보하고, CRIU는 호환 노드에서 더 깊은 보존을 제공하는 선택 기능으로 다룬다.

### Evidence-aware Remediation 순서

파드를 삭제하거나 노드를 드레인하는 조치는 증거를 훼손할 수 있다. 따라서 destructive action은 반드시 현재 인시던트의 증거 수집 상태를 확인한 뒤 실행한다.

```
탐지
  → 최소 격리/오염 라벨
  → Core Evidence Bundle 수집
  → Forensic Synthesis Agent 분석
  → 승인
  → 격리/삭제/드레인 등 대응 실행
  → 사후 리포트
```

`delete_pod`, `patch_deployment(replicas=0)`, `apply_cilium_network_policy`, `cordon_node`, `drain_node` 같은 조치는 SYSTEM_PROMPT만 믿지 않는다. Step Functions 또는 Remediation handler에서 현재 `execution_log`를 확인해 필수 증거 수집이 성공했거나, 운영자가 명시적으로 우회 승인한 경우에만 실행한다.

### Forensic Synthesis Agent

증거를 많이 저장하는 것만으로는 분석 자동화가 완성되지 않는다. ATDR은 수집된 증거를 AI가 읽고, 사람이 검토 가능한 분석 산출물로 재구성하는 Forensic Synthesis Agent를 둔다.

입력 증거는 다음을 포함한다.

- 원본 탐지 이벤트(Falco, Tetragon, GuardDuty)
- Pod/Deployment/ReplicaSet/ServiceAccount 메타데이터
- 컨테이너 로그와 Kubernetes 이벤트
- Tetragon 프로세스/파일/네트워크 이벤트
- Hubble/Cilium flow
- EKS audit log / CloudTrail 이벤트
- Remediation execution log
- 선택적으로 live forensic snapshot 또는 CRIU checkpoint metadata

출력 산출물은 S3 evidence bundle 아래에 저장한다.

```text
incidents/{incident_id}/ai/
├── synthesis-report.md
├── timeline.json
├── iocs.json
├── ttps.json
└── remediation-rationale.json
```

리포트는 추측만 쓰지 않는다. 각 판단에는 어떤 증거 파일, 이벤트 ID, 시간 범위를 근거로 삼았는지 citation을 붙인다.

---

## 2. 불변 로그 저장 (S3 Object Lock)

### 설계 원칙

모든 보안 이벤트 원본은 S3 Object Lock이 활성화된 버킷에 저장한다. GOVERNANCE 모드를 사용해 일반 사용자는 삭제할 수 없고, 특별 권한을 가진 관리자만 잠금을 해제할 수 있다.

### 왜 GOVERNANCE 모드를 쓰는가

S3 Object Lock은 `GOVERNANCE`와 `COMPLIANCE` 두 가지 모드를 지원한다. ATDR은 **GOVERNANCE**를 선택한다.

| 모드 | 설명 | ATDR 적합성 |
|------|------|------|
| COMPLIANCE | 루트 사용자도 retention 해제 불가. 보존 기간이 끝날 때까지 어떤 방법으로도 삭제할 수 없다. | ❌ 데모/스테이징 환경에서 `make infra-down` → `make infra-up` 같은 반복 teardown이 불가능해진다. 버킷 자체를 지울 수 없어 Terraform destroy가 영구 실패한다. |
| GOVERNANCE | `s3:BypassGovernanceRetention` 권한을 가진 특별 사용자(관리자)만 retention을 해제할 수 있다. 일반 사용자는 여전히 삭제 불가. | ✅ 평시 불변성은 유지하되, 환경 재구성(`infra-down`)이 가능하다. `make infra-down-preflight`가 bypass 권한으로 객체를 드레인한 뒤 버킷을 파괴한다. |

실운영 환경에서는 COMPLIANCE가 권장되는 경우가 많지만, ATDR은 평가·데모·재현 환경까지 같은 Terraform/Makefile로 관리한다는 전제 하에 **GOVERNANCE + 관리자 bypass**로 균형을 잡는다. 이 결정은 Makefile의 `infra-down-preflight` target이 `aws s3api delete-object --bypass-governance-retention`으로 버킷을 비우는 동작과 짝을 이룬다.

일반 Lambda/MCP ServiceRole에는 bypass 권한을 부여하지 않는다. 인시던트 대응 중 실수나 LLM 환각으로 증거가 삭제될 위험은 여전히 막힌다.

```
이벤트 원본 데이터
    │
    ├── GuardDuty Findings    ──► s3://atdr-forensics/guardduty/
    ├── Falco 이벤트          ──► s3://atdr-forensics/falco/
    ├── EKS Audit Logs        ──► s3://atdr-forensics/eks-audit/
    ├── CloudTrail            ──► s3://atdr-forensics/cloudtrail/
    └── Hubble 플로우         ──► s3://atdr-forensics/hubble/
```

### Terraform 설정

```hcl
# terraform/forensics/s3.tf

resource "aws_s3_bucket" "forensics" {
  bucket = "atdr-forensics-${var.account_id}"

  tags = {
    Project     = "atdr"
    Purpose     = "forensics"
    Compliance  = "7year-retention"
  }
}

# Object Lock 활성화 (버킷 생성 시에만 설정 가능)
resource "aws_s3_bucket_object_lock_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    default_retention {
      mode  = "GOVERNANCE"
      years = 7
    }
  }
}

# KMS 암호화
resource "aws_s3_bucket_server_side_encryption_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.forensics.arn
    }
    bucket_key_enabled = true
  }
}

# 버전 관리 (Object Lock 사용 시 필수)
resource "aws_s3_bucket_versioning" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  versioning_configuration {
    status = "Enabled"
  }
}

# 퍼블릭 액세스 차단
resource "aws_s3_bucket_public_access_block" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS 키
resource "aws_kms_key" "forensics" {
  description             = "ATDR forensics data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow forensics write"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.forensics_writer.arn
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 버킷 정책 (쓰기는 허용, 삭제는 차단)
resource "aws_s3_bucket_policy" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyDeleteObject"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.forensics.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = var.forensics_admin_role_arn
          }
        }
      },
      {
        Sid    = "DenyDisableObjectLock"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObjectLegalHold",
          "s3:PutObjectRetention"
        ]
        Resource = "${aws_s3_bucket.forensics.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = var.forensics_admin_role_arn
          }
        }
      },
      {
        Sid    = "EnforceSSL"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.forensics.arn,
          "${aws_s3_bucket.forensics.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
```

### 7년 보관 정책

```hcl
# 수명 주기 규칙: 스토리지 클래스 전환으로 비용 최적화
resource "aws_s3_bucket_lifecycle_configuration" "forensics" {
  bucket = aws_s3_bucket.forensics.id

  rule {
    id     = "forensics-lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    transition {
      days          = 730
      storage_class = "DEEP_ARCHIVE"
    }

    # 7년(2555일) 후 만료 — Object Lock 기간과 일치
    expiration {
      days = 2555
    }

    noncurrent_version_expiration {
      noncurrent_days = 2555
    }
  }
}
```

---

## 3. CloudTrail Lake

### 개요

CloudTrail Lake는 EKS 감사 로그를 포함한 AWS API 호출 이력을 SQL로 쿼리할 수 있는 장기 보관 서비스다. 기존 CloudTrail S3 저장 방식과 달리 이벤트 데이터 스토어에 직접 인덱싱되어 복잡한 포렌식 쿼리를 빠르게 실행할 수 있다.

```hcl
# terraform/forensics/cloudtrail-lake.tf

resource "aws_cloudtrail_event_data_store" "main" {
  name                 = "atdr-forensics-lake"
  retention_period     = 2555  # 7년 (일 단위)
  multi_region_enabled = true
  organization_enabled = false

  advanced_event_selector {
    name = "EKS Audit Logs"
    field_selector {
      field  = "eventSource"
      equals = ["eks.amazonaws.com"]
    }
  }

  advanced_event_selector {
    name = "All Management Events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "GuardDuty Events"
    field_selector {
      field  = "eventSource"
      equals = ["guardduty.amazonaws.com"]
    }
  }

  tags = {
    Project    = "atdr"
    Purpose    = "forensics"
    Retention  = "7years"
  }
}
```

### SQL 기반 포렌식 쿼리 예시

```sql
-- 특정 시간대 kubectl exec 호출 전체 조회
SELECT
  eventTime,
  userIdentity.arn,
  requestParameters,
  sourceIPAddress,
  userAgent
FROM atdr-forensics-lake
WHERE
  eventSource = 'eks.amazonaws.com'
  AND eventName = 'CreatePodExecOptions'
  AND eventTime BETWEEN '2026-05-04 00:00:00' AND '2026-05-04 23:59:59'
ORDER BY eventTime DESC;

-- 인시던트 기간 동안 특정 IAM 역할의 모든 API 호출
SELECT
  eventTime,
  eventName,
  eventSource,
  requestParameters,
  responseElements,
  errorCode,
  errorMessage
FROM atdr-forensics-lake
WHERE
  userIdentity.arn LIKE '%payment-service%'
  AND eventTime BETWEEN '2026-05-04 09:00:00' AND '2026-05-04 11:00:00'
ORDER BY eventTime ASC;

-- 비정상 IAM 권한 상승 시도 탐지
SELECT
  eventTime,
  userIdentity.arn,
  eventName,
  sourceIPAddress,
  errorCode
FROM atdr-forensics-lake
WHERE
  eventName IN (
    'AttachRolePolicy',
    'CreateRole',
    'PutRolePolicy',
    'AssumeRole',
    'CreateAccessKey'
  )
  AND eventTime >= DATEADD(day, -7, NOW())
ORDER BY eventTime DESC;

-- 특정 파드에서 발생한 AWS API 호출 (IRSA 추적)
SELECT
  eventTime,
  eventName,
  eventSource,
  userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
  userIdentity.sessionContext.webIdFederationData.federatedUserId AS pod_identity,
  sourceIPAddress
FROM atdr-forensics-lake
WHERE
  userIdentity.type = 'AssumedRole'
  AND userIdentity.sessionContext.webIdFederationData.federatedUserId
      LIKE '%payment-service%'
  AND eventTime BETWEEN '2026-05-04 09:00:00' AND '2026-05-04 11:00:00'
ORDER BY eventTime ASC;

-- 삭제된 리소스 목록 (인시던트 후 증거 인멸 시도 탐지)
SELECT
  eventTime,
  userIdentity.arn,
  eventName,
  requestParameters
FROM atdr-forensics-lake
WHERE
  eventName LIKE 'Delete%'
  AND eventTime >= DATEADD(hour, -24, NOW())
ORDER BY eventTime DESC;
```

---

## 4. 실험적 컨테이너 체크포인트 (Experimental Container Checkpoint)

### 개요

컨테이너 체크포인트는 의심스러운 컨테이너의 메모리와 프로세스 상태를 보존할 수 있는 고급 포렌식 기능이다. 성공하면 일반 로그나 이벤트만으로는 확인하기 어려운 휘발성 증거(메모리 내 payload, 열린 파일 디스크립터, 프로세스 상태)를 남길 수 있다.

다만 EKS에서 CRIU 기반 체크포인트는 노드 OS, containerd/CRI 설정, kubelet feature gate, 권한 모델에 강하게 의존한다. 따라서 ATDR은 이 기능을 기본 대응 경로가 아니라 **명시적 승인 기반 Experimental mode**로 제공한다. 체크포인트 실패는 인시던트 대응 실패가 아니며, 시스템은 실패 사유를 기록하고 Evidence Bundle / Ephemeral Container Live Forensics 경로로 fallback한다.

### 설계 원칙

| 원칙 | 설명 |
|------|------|
| 선택 실행 | CRIU checkpoint는 항상 명시적 승인 후 실행한다. 자동 삭제/격리 경로의 필수 조건으로 만들지 않는다. |
| 호환성 감지 | 노드가 checkpoint API, CRIU, containerd 지원을 제공하는지 먼저 확인한다. |
| 안전한 실패 | 미지원 노드에서는 `status=unsupported`와 원인을 반환하고 live forensics로 fallback한다. |
| 원본 보존 | checkpoint tarball과 metadata는 Object Lock이 걸린 S3 forensics bucket에 저장한다. |
| 복원 비필수 | MVP는 생성과 보존까지로 제한한다. 복원 분석은 별도 sandbox 기능으로 다룬다. |
| 민감정보 주의 | checkpoint는 메모리와 secret을 포함할 수 있으므로 저장, 접근, 공개 샘플을 엄격히 제한한다. |

### 호환 노드 준비

```yaml
# k8s/base/node-config/kubelet-config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
featureGates:
  ContainerCheckpoint: true
containerRuntimeEndpoint: unix:///run/containerd/containerd.sock
```

EKS 관리형 노드 그룹에서 시도하는 경우 별도 forensics-enabled 노드 그룹을 둔다. 일반 워크로드 노드 그룹을 직접 변경하지 않고, taint/toleration으로 테스트 워크로드만 스케줄링한다.

```bash
#!/bin/bash
/etc/eks/bootstrap.sh atdr \
  --kubelet-extra-args '--feature-gates=ContainerCheckpoint=true'
```

### 체크포인트 생성 및 S3 저장

체크포인트는 호환 노드에서만 kubelet checkpoint API를 통해 생성한다. 생성된 체크포인트 파일은 노드의 `/var/lib/kubelet/checkpoints/` 에 저장된다. 운영 경로에서는 Lambda가 kubelet이나 Kubernetes API를 직접 호출하지 않으며, 요청은 반드시 EKS MCP 서버를 경유한다.

```python
# apps/forensics-agent/checkpoint.py
import boto3
import hashlib
import json
import os
import requests
import tarfile
from datetime import datetime, timezone
from pathlib import Path

KUBELET_API = "https://localhost:10250"
CHECKPOINT_DIR = Path("/var/lib/kubelet/checkpoints")
  S3_BUCKET = "atdr-forensics-{account_id}"

def create_checkpoint(namespace: str, pod: str, container: str, incident_id: str) -> dict:
    """의심 컨테이너 체크포인트 생성 후 S3에 저장"""

    # 1. kubelet API로 체크포인트 생성
    url = f"{KUBELET_API}/checkpoint/{namespace}/{pod}/{container}"
    resp = requests.post(
        url,
        verify="/var/lib/kubelet/pki/kubelet-client-current.pem",
        cert=(
            "/var/lib/kubelet/pki/kubelet-client-current.pem",
            "/var/lib/kubelet/pki/kubelet-client-current.pem"
        )
    )
    resp.raise_for_status()

    checkpoint_path = resp.json().get("items", [None])[0]
    if not checkpoint_path:
        raise RuntimeError("체크포인트 경로를 찾을 수 없음")

    # 2. SHA-256 해시 계산 (무결성 증명)
    sha256 = hashlib.sha256()
    with open(checkpoint_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    # 3. S3에 업로드 (Object Lock 버킷)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key = f"checkpoints/{incident_id}/{namespace}/{pod}/{container}/{timestamp}.tar"

    s3 = boto3.client("s3")
    s3.upload_file(
        checkpoint_path,
        S3_BUCKET,
        s3_key,
        ExtraArgs={
            "ServerSideEncryption": "aws:kms",
            "Metadata": {
                "incident-id": incident_id,
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "sha256": file_hash,
                "captured-at": timestamp
            }
        }
    )

    # 4. 메타데이터 기록
    metadata = {
        "incident_id": incident_id,
        "namespace": namespace,
        "pod": pod,
        "container": container,
        "checkpoint_s3_key": s3_key,
        "sha256": file_hash,
        "captured_at": timestamp,
        "node": os.environ.get("NODE_NAME", "unknown")
    }

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=f"checkpoints/{incident_id}/{namespace}/{pod}/{container}/{timestamp}.json",
        Body=json.dumps(metadata, indent=2),
        ServerSideEncryption="aws:kms"
    )

    return metadata
```

### 샌드박스에서 복원 분석

체크포인트를 격리된 환경에서 복원해 분석한다:

```bash
# 1. S3에서 체크포인트 다운로드
aws s3 cp \
  s3://atdr-forensics/checkpoints/inc-001/production/payment-service/app/20260504T100000Z.tar \
  /tmp/checkpoint.tar

# 2. 체크포인트 무결성 검증
sha256sum /tmp/checkpoint.tar
# 기록된 해시와 비교

# 3. 격리된 네임스페이스에서 복원 (네트워크 없음)
kubectl create namespace forensics-sandbox
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: forensics-sandbox
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
EOF

# 4. crictl로 체크포인트 복원
crictl create \
  --checkpoint /tmp/checkpoint.tar \
  sandbox-config.json \
  container-config.json

# 5. 복원된 컨테이너에서 프로세스/파일 분석
crictl exec <container-id> ps aux
crictl exec <container-id> netstat -an
crictl exec <container-id> find /tmp -newer /etc/passwd -type f
```

### Falco 연동: 의심 이벤트 시 체크포인트 후보 생성

Falco 이벤트가 발생하면 즉시 체크포인트를 생성하지 않는다. 대신 이벤트를 기반으로 `checkpoint_container_experimental` 실행 후보를 만들고 Slack 승인 또는 정책 승인을 기다린다. CRIU checkpoint는 노드 호환성과 민감정보 위험이 크기 때문에 자동 실행 기본값으로 두지 않는다.

```yaml
# k8s/base/falco/falcosidekick-values.yaml (추가)
config:
  webhook:
    address: "http://forensics-agent.atdr.svc.cluster.local:8080/checkpoint"
    minimumpriority: "critical"
    customHeaders: "X-Source:falco"
```

```python
# apps/forensics-agent/webhook.py
from fastapi import FastAPI, Request
import asyncio

app = FastAPI()

CHECKPOINT_TRIGGERS = {
    "Terminal shell in container",
    "Outbound Connection to C2 Servers",
    "Container Drift Detected",
    "Privilege Escalation via Sudo",
    "Write below binary dir"
}

@app.post("/checkpoint")
async def handle_falco_event(request: Request):
    event = await request.json()

    rule = event.get("rule", "")
    if rule not in CHECKPOINT_TRIGGERS:
        return {"status": "skipped", "reason": "rule not in trigger list"}

    output_fields = event.get("output_fields", {})
    namespace = output_fields.get("k8s.ns.name")
    pod = output_fields.get("k8s.pod.name")
    container = output_fields.get("container.name")
    incident_id = f"inc-{event.get('time', '')[:10].replace('-', '')}-auto"

    if not all([namespace, pod, container]):
        return {"status": "skipped", "reason": "missing pod info"}

    # 비동기로 체크포인트 후보 생성 (Falco 응답 블로킹 방지)
    asyncio.create_task(
        propose_checkpoint_async(namespace, pod, container, incident_id)
    )

    return {"status": "checkpoint_proposed", "incident_id": incident_id}
```

---

## 5. Hubble 네트워크 포렌식

### 네트워크 플로우 기록 및 내보내기

Hubble은 Cilium이 처리하는 모든 네트워크 플로우를 기록한다. 인시던트 발생 시 해당 시간대의 플로우를 추출해 S3에 보존한다.

```bash
# Hubble CLI로 플로우 조회 및 내보내기
# 특정 파드의 모든 플로우 (인시던트 시간대)
hubble observe \
  --pod production/payment-service-7d9f8b-xk2p9 \
  --since 2026-05-04T09:00:00Z \
  --until 2026-05-04T11:00:00Z \
  --output json \
  > /tmp/flows-incident-001.json

# 차단된 트래픽만 조회
hubble observe \
  --namespace production \
  --verdict DROPPED \
  --since 2026-05-04T09:00:00Z \
  --output json \
  > /tmp/dropped-flows.json

# 외부 IP 연결 조회 (RFC1918 제외)
hubble observe \
  --namespace production \
  --since 2026-05-04T09:00:00Z \
  --output json \
  | jq 'select(.destination.ip | test("^(?!10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"))' \
  > /tmp/external-connections.json

# S3에 보존
aws s3 cp /tmp/flows-incident-001.json \
  s3://atdr-forensics/hubble/inc-20260504-001/flows.json \
  --sse aws:kms
```

### 포렌식 분석용 필터링

```bash
# verdict별 플로우 집계
hubble observe \
  --namespace production \
  --since 2026-05-04T09:00:00Z \
  --output json \
  | jq -r '.verdict' \
  | sort | uniq -c | sort -rn

# 목적지 포트별 연결 수
hubble observe \
  --pod production/payment-service-7d9f8b-xk2p9 \
  --since 2026-05-04T09:00:00Z \
  --output json \
  | jq -r '.destination.port' \
  | sort | uniq -c | sort -rn

# DNS 쿼리 목록 (의심 도메인 확인)
hubble observe \
  --namespace production \
  --protocol DNS \
  --since 2026-05-04T09:00:00Z \
  --output json \
  | jq -r '.l7.dns.query' \
  | sort -u

# 네임스페이스 간 lateral movement 탐지
hubble observe \
  --since 2026-05-04T09:00:00Z \
  --output json \
  | jq 'select(
      .source.namespace != .destination.namespace
      and .source.namespace != null
      and .destination.namespace != null
    )' \
  | jq -r '[.source.namespace, .destination.namespace, .destination.port] | @tsv' \
  | sort | uniq -c | sort -rn
```

### Hubble Relay gRPC 스트리밍

장기 포렌식 보존을 위해 Hubble Relay에서 플로우를 실시간으로 스트리밍해 S3에 저장하는 파이프라인을 구성한다.

```python
# apps/forensics-agent/hubble_exporter.py
import grpc
import json
import boto3
import gzip
from datetime import datetime, timezone
from observer_pb2_grpc import ObserverStub
from flow_pb2 import FlowFilter

HUBBLE_RELAY = "hubble-relay.kube-system.svc.cluster.local:4245"
  S3_BUCKET = "atdr-forensics"

def stream_flows_to_s3():
    channel = grpc.insecure_channel(HUBBLE_RELAY)
    stub = ObserverStub(channel)

    buffer = []
    batch_size = 1000

    for flow in stub.GetFlows(FlowFilter()):
        buffer.append({
            "time": flow.time.ToJsonString(),
            "source": {
                "namespace": flow.source.namespace,
                "pod_name": flow.source.pod_name,
                "ip": flow.IP.source
            },
            "destination": {
                "namespace": flow.destination.namespace,
                "pod_name": flow.destination.pod_name,
                "ip": flow.IP.destination,
                "port": flow.l4.TCP.destination_port if flow.l4.HasField("TCP") else None
            },
            "verdict": flow.verdict,
            "drop_reason": flow.drop_reason_desc
        })

        if len(buffer) >= batch_size:
            flush_to_s3(buffer)
            buffer = []

def flush_to_s3(flows: list):
    timestamp = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%S")
    key = f"hubble/flows/{timestamp}.json.gz"

    s3 = boto3.client("s3")
    compressed = gzip.compress(
        json.dumps(flows, ensure_ascii=False).encode("utf-8")
    )
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=compressed,
        ContentEncoding="gzip",
        ServerSideEncryption="aws:kms"
    )
```

---

## 6. Security Lake 연동

### 개요

Amazon Security Lake는 여러 보안 데이터 소스를 OCSF(Open Cybersecurity Schema Framework) 포맷으로 정규화해 단일 데이터 레이크에 저장한다. Athena로 SQL 쿼리를 실행할 수 있어 멀티소스 포렌식 분석에 적합하다.

```hcl
# terraform/forensics/security-lake.tf

resource "aws_securitylake_data_lake" "main" {
  meta_store_manager_role_arn = aws_iam_role.security_lake_manager.arn

  configuration {
    region = var.aws_region

    encryption_configuration {
      kms_key_id = aws_kms_key.forensics.arn
    }

    lifecycle_configuration {
      expiration {
        days = 2555  # 7년
      }
      transition {
        days          = 365
        storage_class = "ONEZONE_IA"
      }
    }
  }
}

# 기본 AWS 소스 활성화
resource "aws_securitylake_aws_log_source" "sources" {
  for_each = toset([
    "ROUTE53",
    "VPC_FLOW",
    "SH_FINDINGS",
    "CLOUD_TRAIL_MGMT",
    "EKS_AUDIT"
  ])

  source {
    accounts    = [var.account_id]
    regions     = [var.aws_region]
    source_name = each.value
  }
}
```

### OCSF 포맷 정규화

Falco 이벤트를 OCSF 포맷으로 변환해 Security Lake에 저장한다:

```python
# apps/forensics-agent/ocsf_normalizer.py
from datetime import datetime, timezone
import json

OCSF_CLASS_PROCESS_ACTIVITY = 1007
OCSF_CLASS_NETWORK_ACTIVITY = 4001

def falco_to_ocsf(falco_event: dict) -> dict:
    """Falco 이벤트를 OCSF Process Activity 포맷으로 변환"""

    output_fields = falco_event.get("output_fields", {})
    timestamp_ms = int(
        datetime.fromisoformat(
            falco_event["time"].replace("Z", "+00:00")
        ).timestamp() * 1000
    )

    return {
        "class_uid": OCSF_CLASS_PROCESS_ACTIVITY,
        "class_name": "Process Activity",
        "category_uid": 1,
        "category_name": "System Activity",
        "activity_id": 1,
        "activity_name": "Launch",
        "severity_id": _map_severity(falco_event.get("priority", "INFO")),
        "severity": falco_event.get("priority", "INFO"),
        "status_id": 1,
        "time": timestamp_ms,
        "message": falco_event.get("output", ""),
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "Falco",
                "vendor_name": "Falco",
                "version": "0.38"
            },
            "original_time": falco_event.get("time")
        },
        "process": {
            "name": output_fields.get("proc.name"),
            "pid": output_fields.get("proc.pid"),
            "cmd_line": output_fields.get("proc.cmdline"),
            "parent_process": {
                "name": output_fields.get("proc.pname"),
                "pid": output_fields.get("proc.ppid")
            }
        },
        "container": {
            "name": output_fields.get("container.name"),
            "uid": output_fields.get("container.id"),
            "image": {
                "name": output_fields.get("container.image.repository"),
                "tag": output_fields.get("container.image.tag")
            }
        },
        "kubernetes": {
            "namespace_name": output_fields.get("k8s.ns.name"),
            "pod_name": output_fields.get("k8s.pod.name"),
            "node_name": output_fields.get("k8s.node.name")
        },
        "unmapped": {
            "falco_rule": falco_event.get("rule"),
            "falco_tags": falco_event.get("tags", [])
        }
    }

def _map_severity(priority: str) -> int:
    mapping = {
        "EMERGENCY": 6, "ALERT": 6, "CRITICAL": 5,
        "ERROR": 4, "WARNING": 3, "NOTICE": 2,
        "INFO": 1, "DEBUG": 0
    }
    return mapping.get(priority.upper(), 1)
```

### Athena 쿼리

```sql
-- 인시던트 기간 동안 모든 소스의 이벤트 통합 조회
SELECT
  time,
  class_name,
  severity,
  message,
  actor.user.name AS user,
  src_endpoint.ip AS source_ip,
  dst_endpoint.ip AS dest_ip
FROM security_lake_db.amazon_security_lake_table_ap_northeast_2_sh_findings_1_0
WHERE
  time BETWEEN 1746345600000 AND 1746352800000  -- 인시던트 시간대 (ms)
  AND severity IN ('Critical', 'High')
ORDER BY time ASC;

-- EKS 감사 로그에서 비정상 API 호출 패턴
SELECT
  time,
  api.operation AS operation,
  actor.user.name AS user,
  src_endpoint.ip AS source_ip,
  http_request.user_agent,
  COUNT(*) AS call_count
FROM security_lake_db.amazon_security_lake_table_ap_northeast_2_eks_audit_1_0
WHERE
  time >= (UNIX_TIMESTAMP() - 86400) * 1000  -- 최근 24시간
  AND api.operation IN ('exec', 'portforward', 'attach')
GROUP BY 1, 2, 3, 4, 5
ORDER BY call_count DESC
LIMIT 20;

-- VPC Flow Logs와 EKS 감사 로그 조인 (IP 기반 상관관계)
SELECT
  f.time AS flow_time,
  f.src_endpoint.ip AS source_ip,
  f.dst_endpoint.ip AS dest_ip,
  f.dst_endpoint.port AS dest_port,
  a.api.operation AS k8s_operation,
  a.actor.user.name AS k8s_user
FROM security_lake_db.amazon_security_lake_table_ap_northeast_2_vpc_flow_1_0 f
JOIN security_lake_db.amazon_security_lake_table_ap_northeast_2_eks_audit_1_0 a
  ON f.src_endpoint.ip = a.src_endpoint.ip
  AND ABS(f.time - a.time) < 60000  -- 1분 이내 이벤트
WHERE
  f.time BETWEEN 1746345600000 AND 1746352800000
  AND f.dst_endpoint.port NOT IN (80, 443, 53)
ORDER BY f.time ASC;
```

---

## 7. 포렌식 워크플로우

### 인시던트 발생부터 보고서까지

```
인시던트 탐지 (GuardDuty / Falco)
    │
    ▼
[1단계] 즉시 증거 수집 (자동)
    ├── 컨테이너 체크포인트 생성 → S3
    ├── Hubble 플로우 스냅샷 → S3
    ├── 관련 파드 로그 수집 → S3
    └── 인시던트 타임스탬프 기록
    │
    ▼
[2단계] 증거 보전 (자동)
    ├── S3 Object Lock 확인
    ├── SHA-256 해시 기록
    └── Chain of Custody 문서 생성
    │
    ▼
[3단계] 분석 (반자동)
    ├── CloudTrail Lake SQL 쿼리
    ├── Security Lake Athena 쿼리
    ├── Hubble 플로우 분석
    └── AI 에이전트 상관관계 분석
    │
    ▼
[4단계] 보고서 생성 (자동)
    ├── 타임라인 재구성
    ├── 영향 범위 정리
    ├── 증거 목록 (S3 경로 + 해시)
    └── 권고 사항
```

### 각 단계의 자동화 포인트

**1단계: 즉시 증거 수집**

Falco Critical 이벤트 또는 GuardDuty High/Critical Finding 발생 시 forensics-agent가 자동으로 실행된다.

```python
# apps/forensics-agent/incident_handler.py
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass
class ForensicsContext:
    incident_id: str
    namespace: str
    pod_name: str
    container_name: str
    node_name: str
    triggered_at: str
    trigger_source: str  # "falco" | "guardduty"
    trigger_rule: str

async def collect_evidence(ctx: ForensicsContext) -> dict:
    """인시던트 발생 시 병렬로 증거 수집"""

    tasks = [
        create_checkpoint(ctx.namespace, ctx.pod_name, ctx.container_name, ctx.incident_id),
        export_hubble_flows(ctx.namespace, ctx.pod_name, ctx.incident_id),
        collect_pod_logs(ctx.namespace, ctx.pod_name, ctx.incident_id),
        snapshot_pod_state(ctx.namespace, ctx.pod_name, ctx.incident_id)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    evidence_manifest = {
        "incident_id": ctx.incident_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "trigger": {
            "source": ctx.trigger_source,
            "rule": ctx.trigger_rule,
            "triggered_at": ctx.triggered_at
        },
        "evidence": {
            "checkpoint": results[0] if not isinstance(results[0], Exception) else None,
            "hubble_flows": results[1] if not isinstance(results[1], Exception) else None,
            "pod_logs": results[2] if not isinstance(results[2], Exception) else None,
            "pod_state": results[3] if not isinstance(results[3], Exception) else None
        },
        "errors": [str(r) for r in results if isinstance(r, Exception)]
    }

    # 증거 목록을 S3에 저장
    save_evidence_manifest(evidence_manifest)
    return evidence_manifest

async def snapshot_pod_state(namespace: str, pod: str, incident_id: str) -> dict:
    """파드 현재 상태 스냅샷 (kubectl describe 결과)"""
    import subprocess

    result = subprocess.run(
        ["kubectl", "get", "pod", pod, "-n", namespace, "-o", "json"],
        capture_output=True, text=True
    )

    s3_key = f"pod-state/{incident_id}/{namespace}/{pod}/state.json"
    upload_to_forensics_s3(result.stdout.encode(), s3_key)

    return {"s3_key": s3_key, "exit_code": result.returncode}
```

**2단계: 증거 보전**

```python
# apps/forensics-agent/custody.py
import boto3
import json
from datetime import datetime, timezone

def create_custody_record(incident_id: str, evidence_manifest: dict) -> str:
    """Chain of Custody 문서 생성"""

    s3 = boto3.client("s3")

    # 각 증거 파일의 현재 S3 Object Lock 상태 확인
    evidence_status = []
    for evidence_type, evidence_info in evidence_manifest["evidence"].items():
        if evidence_info and "s3_key" in evidence_info:
            try:
                retention = s3.get_object_retention(
  Bucket="atdr-forensics",
                    Key=evidence_info["s3_key"]
                )
                evidence_status.append({
                    "type": evidence_type,
                    "s3_key": evidence_info["s3_key"],
                    "sha256": evidence_info.get("sha256"),
                    "object_lock_mode": retention["Retention"]["Mode"],
                    "retain_until": retention["Retention"]["RetainUntilDate"].isoformat(),
                    "verified_at": datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                evidence_status.append({
                    "type": evidence_type,
                    "error": str(e)
                })

    custody_record = {
        "incident_id": incident_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "forensics-agent-auto",
        "evidence_items": evidence_status,
        "access_log": []  # 이후 접근 시 추가
    }

    s3.put_object(
  Bucket="atdr-forensics",
        Key=f"custody/{incident_id}/chain-of-custody.json",
        Body=json.dumps(custody_record, indent=2, default=str),
        ServerSideEncryption="aws:kms"
    )

    return f"custody/{incident_id}/chain-of-custody.json"
```

**3단계: AI 에이전트 분석**

Solution Agent가 수집된 증거를 바탕으로 CloudTrail Lake와 Security Lake를 쿼리해 공격 타임라인을 재구성한다. 분석 결과는 인시던트 리포트 초안으로 저장된다.

**4단계: 보고서 생성**

```python
# apps/forensics-agent/report.py
def generate_forensics_report(incident_id: str, analysis_result: dict) -> str:
    """포렌식 분석 보고서 생성"""

    report = f"""# 포렌식 분석 보고서

## 인시던트 정보
- ID: {incident_id}
- 탐지 시각: {analysis_result['detected_at']}
- 영향 리소스: {', '.join(analysis_result['affected_resources'])}
- 공격 유형: {analysis_result['threat_type']}

## 공격 타임라인
{format_timeline(analysis_result['timeline'])}

## 증거 목록
| 유형 | S3 경로 | SHA-256 | Object Lock |
|------|---------|---------|-------------|
{format_evidence_table(analysis_result['evidence'])}

## 영향 범위
{analysis_result['impact_summary']}

## 권고 사항
{format_recommendations(analysis_result['recommendations'])}

## 증거 무결성 확인
모든 증거 파일은 S3 Object Lock(GOVERNANCE, 7년)으로 보호됩니다.
Chain of Custody: s3://atdr-forensics/custody/{incident_id}/chain-of-custody.json
"""

    # 보고서를 S3에 저장
    s3_key = f"reports/{incident_id}/forensics-report.md"
    upload_to_forensics_s3(report.encode("utf-8"), s3_key)

    return s3_key
```

---
