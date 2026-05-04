# 02. 탐지 레이어 설계

> 관련 문서: [01-architecture.md](./01-architecture.md) | [03-correlation.md](./03-correlation.md)

---

## 1. 탐지 전략 개요

ATDR의 탐지 레이어는 단일 도구에 의존하지 않는다. AWS 네이티브 서비스, 오픈소스 런타임 모니터, 커널 레벨 정책 엔진을 조합해 서로 다른 관찰 지점에서 동시에 신호를 수집한다.

세 도구의 역할은 다음과 같이 구분된다.

| 도구 | 관찰 지점 | 탐지 방식 | 차단 가능 여부 |
|---|---|---|---|
| Amazon GuardDuty | AWS API, EKS Audit Log, 런타임 | 관리형 위협 인텔리전스 + ML | 없음 (Finding 생성) |
| Falco | syscall, Kubernetes 이벤트 | 규칙 기반 실시간 탐지 | 없음 (Alert 생성) |
| Tetragon | 커널 eBPF hook | TracingPolicy 기반 탐지 | 있음 (Sigkill) |

GuardDuty는 AWS 계정 수준의 가시성을 제공하고, Falco는 컨테이너 내부 syscall을 실시간으로 감시하며, Tetragon은 커널에서 직접 프로세스를 차단할 수 있다. 세 도구가 같은 인시던트를 서로 다른 각도에서 포착하면 상관관계 엔진이 이를 하나의 사건으로 묶는다.

---

## 2. Amazon GuardDuty

### 2.1 EKS Protection 구성

GuardDuty EKS Protection은 두 가지 모니터링 채널로 구성된다.

**EKS Audit Log Monitoring**은 Kubernetes control plane이 생성하는 audit log를 분석한다. 비정상적인 API 호출 패턴, 권한 상승 시도, 의심스러운 ServiceAccount 사용 등을 탐지한다. 별도 에이전트 없이 활성화할 수 있다.

**EKS Runtime Monitoring**은 노드에 GuardDuty Runtime Agent를 배포해 컨테이너 내부의 런타임 행위를 관찰한다. eBPF 기반으로 동작하며 EKS managed add-on으로 설치된다.

### 2.2 GuardDuty Runtime Agent

Runtime Agent는 EKS add-on `aws-guardduty-agent`로 배포된다. 각 노드에 DaemonSet 형태로 실행되며 eBPF를 통해 syscall 이벤트를 수집한다. 수집된 이벤트는 GuardDuty 백엔드로 전송되어 위협 인텔리전스와 대조된다.

에이전트가 관찰하는 주요 이벤트 유형:
- 프로세스 실행 및 네트워크 연결
- 파일 시스템 접근 (민감 경로 포함)
- DNS 쿼리
- 컨테이너 탈출 시도

### 2.3 Extended Threat Detection

GuardDuty의 Extended Threat Detection은 단일 이벤트가 아닌 다단계 공격 시퀀스를 상관분석한다. 예를 들어 IAM 자격증명 탈취 후 EKS 클러스터 접근, 이후 크립토마이닝 바이너리 실행으로 이어지는 흐름을 하나의 공격 체인으로 인식한다.

이 기능은 별도 설정 없이 GuardDuty EKS Protection 활성화 시 자동으로 동작한다.

### 2.4 주요 EKS Finding 유형

ATDR 시나리오에서 주로 발생하는 Finding 유형과 MITRE ATT&CK 매핑은 다음과 같다.

| Finding 유형 | 설명 | MITRE ATT&CK |
|---|---|---|
| `CryptoCurrency:EKS/BitcoinTool.B!DNS` | 알려진 크립토마이닝 풀 도메인으로의 DNS 쿼리 | T1496 Resource Hijacking |
| `Backdoor:EKS/MaliciousFile.Binary` | 컨테이너 내 악성 바이너리 실행 | T1059 Command and Scripting Interpreter |
| `UnauthorizedAccess:EKS/ExfiltratedData.Suspicious` | 비정상적인 외부 데이터 전송 | T1041 Exfiltration Over C2 Channel |
| `Trojan:EKS/DockerLayerInjection.B` | 컨테이너 이미지 레이어에 악성 코드 삽입 | T1610 Deploy Container |
| `PrivilegeEscalation:EKS/PrivilegedContainer` | 권한 있는 컨테이너에서의 권한 상승 시도 | T1611 Escape to Host |
| `Execution:EKS/ExecInPod` | 실행 중인 pod에 대한 kubectl exec | T1609 Container Administration Command |

### 2.5 Terraform 설정 예시

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Project = "atdr"
    Env     = var.environment
  }
}

resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}
```

`EKS_ADDON_MANAGEMENT`를 `ENABLED`로 설정하면 GuardDuty가 Runtime Agent add-on을 자동으로 관리한다. 수동 설치 없이 클러스터에 에이전트가 배포된다.

---

## 3. Falco

### 3.1 eBPF 기반 syscall 모니터링

Falco는 Linux 커널의 syscall을 실시간으로 감시한다. eBPF probe를 커널에 삽입해 프로세스 실행, 파일 접근, 네트워크 연결 등의 이벤트를 캡처하고, 사전 정의된 규칙과 대조해 위협을 탐지한다.

ATDR에서는 `modern_bpf` 드라이버를 사용한다. 커널 모듈 방식보다 안정적이고 커널 버전 의존성이 낮다.

### 3.2 Helm 배포

```yaml
# values-atdr.yaml
driver:
  kind: modern_bpf

collectors:
  enabled: true
  docker:
    enabled: false
  containerd:
    enabled: true
    socket: /run/containerd/containerd.sock

falcosidekick:
  enabled: true
  config:
    aws:
      sns:
        topicarn: "arn:aws:sns:ap-northeast-2:ACCOUNT_ID:atdr-falco-alerts"
        region: "ap-northeast-2"
        minimumpriority: "warning"

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --values values-atdr.yaml
```

### 3.3 커스텀 룰

#### 크립토마이닝 탐지

```yaml
- rule: Cryptomining Stratum Protocol Detected
  desc: 컨테이너에서 stratum 프로토콜을 사용하는 네트워크 연결 탐지
  condition: >
    evt.type in (connect, sendto) and
    container and
    (fd.sport in (3333, 4444, 5555, 7777, 14444, 45700) or
     fd.l4proto = tcp and fd.rport in (3333, 4444, 5555, 7777, 14444, 45700))
  output: >
    Cryptomining stratum connection detected
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     src=%fd.cip sport=%fd.sport dst=%fd.rip dport=%fd.rport)
  priority: CRITICAL
  tags: [cryptomining, network, mitre_resource_hijacking]

- rule: Known Cryptominer Binary Executed
  desc: 알려진 크립토마이닝 바이너리 실행 탐지
  condition: >
    spawned_process and
    container and
    proc.name in (xmrig, xmrig-notls, minerd, cpuminer, ethminer,
                  nbminer, t-rex, gminer, lolminer, phoenixminer)
  output: >
    Known cryptominer binary executed
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     binary=%proc.name cmdline=%proc.cmdline parent=%proc.pname)
  priority: CRITICAL
  tags: [cryptomining, execution, mitre_resource_hijacking]
```

#### 권한 상승 탐지

```yaml
- rule: Privilege Escalation via setresuid
  desc: setresuid syscall을 통한 권한 상승 시도 탐지
  condition: >
    evt.type = setresuid and
    container and
    evt.arg.ruid = 0 and
    not proc.name in (runc, containerd-shim)
  output: >
    Privilege escalation via setresuid
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.name
     uid=%user.uid ruid=%evt.arg.ruid)
  priority: HIGH
  tags: [privilege_escalation, mitre_privilege_escalation]

- rule: Privileged Container Spawned
  desc: 권한 있는 컨테이너 내에서 셸 실행 탐지
  condition: >
    spawned_process and
    container and
    container.privileged = true and
    proc.name in (bash, sh, zsh, dash, ksh)
  output: >
    Shell spawned in privileged container
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     shell=%proc.name cmdline=%proc.cmdline)
  priority: HIGH
  tags: [privilege_escalation, container_escape, mitre_privilege_escalation]
```

#### ServiceAccount 토큰 접근 탐지

```yaml
- rule: ServiceAccount Token Read by Unexpected Process
  desc: 예상치 못한 프로세스가 ServiceAccount 토큰을 읽는 행위 탐지
  condition: >
    open_read and
    container and
    fd.name startswith "/var/run/secrets/kubernetes.io/serviceaccount" and
    not proc.name in (java, python, python3, node, ruby, dotnet, curl, wget)
  output: >
    ServiceAccount token accessed by unexpected process
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.name
     file=%fd.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [credential_access, mitre_credential_access]
```

#### 컨테이너 내 셸 실행 탐지

```yaml
- rule: Shell Spawned in Container
  desc: 컨테이너 내에서 인터랙티브 셸 실행 탐지
  condition: >
    spawned_process and
    container and
    proc.name in (bash, sh, zsh, dash, ksh, fish) and
    proc.tty != 0 and
    not container.image.repository in (
      "bitnami/kubectl",
      "amazon/aws-cli"
    )
  output: >
    Interactive shell spawned in container
    (pod=%k8s.pod.name ns=%k8s.ns.name image=%container.image.repository
     shell=%proc.name tty=%proc.tty parent=%proc.pname)
  priority: WARNING
  tags: [execution, mitre_execution]
```

#### 민감 파일 접근 탐지

```yaml
- rule: Sensitive File Access in Container
  desc: 컨테이너 내에서 민감한 시스템 파일 접근 탐지
  condition: >
    open_read and
    container and
    fd.name in (/etc/shadow, /etc/passwd, /etc/sudoers,
                /root/.ssh/authorized_keys, /root/.ssh/id_rsa,
                /proc/1/environ) and
    not proc.name in (passwd, shadow, useradd, usermod)
  output: >
    Sensitive file accessed in container
    (pod=%k8s.pod.name ns=%k8s.ns.name proc=%proc.name
     file=%fd.name cmdline=%proc.cmdline)
  priority: HIGH
  tags: [credential_access, discovery, mitre_credential_access]
```

### 3.4 Falcosidekick SNS 출력 설정

Falcosidekick은 Falco Alert를 다양한 외부 시스템으로 전달하는 팬아웃 컴포넌트다. ATDR에서는 SNS를 통해 Lambda 상관관계 엔진으로 이벤트를 전달한다.

```yaml
# falcosidekick-config.yaml
config:
  aws:
    sns:
      topicarn: "arn:aws:sns:ap-northeast-2:ACCOUNT_ID:atdr-falco-alerts"
      region: "ap-northeast-2"
      minimumpriority: "warning"
      checkcert: true

  customfields:
    cluster: "atdr-eks-cluster"
    environment: "production"

  outputfieldformat: "json"
```

SNS 토픽 구독자로 SQS 큐를 추가하면 Lambda가 배치로 이벤트를 처리할 수 있다. 상관관계 엔진 설계는 `03-correlation.md`에서 다룬다.

---

## 4. Tetragon

### 4.1 Falco와의 차이

Falco와 Tetragon은 모두 eBPF를 사용하지만 목적이 다르다.

Falco는 이벤트를 관찰하고 Alert를 생성한다. 탐지 후 외부 시스템이 대응을 결정한다. Tetragon은 커널 레벨에서 직접 프로세스를 차단할 수 있다. TracingPolicy에 `Sigkill` 액션을 정의하면 조건에 맞는 프로세스가 실행되는 즉시 커널이 종료한다. 사용자 공간으로 이벤트가 올라오기 전에 차단이 완료된다.

| 항목 | Falco | Tetragon |
|---|---|---|
| 탐지 | 가능 | 가능 |
| 차단 | 불가 | 가능 (Sigkill) |
| 정책 언어 | YAML 규칙 | TracingPolicy CRD |
| 네트워크 정책 연동 | 없음 | Hubble 연동 |
| 오버헤드 | 낮음 | 낮음 |

### 4.2 TracingPolicy CRD 예시

#### 크립토마이닝 바이너리 즉시 차단

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-cryptominer-binaries
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/xmrig"
        - "/minerd"
        - "/cpuminer"
        - "/ethminer"
        - "/nbminer"
      matchActions:
      - action: Sigkill
```

#### 권한 있는 컨테이너에서의 호스트 마운트 차단

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-host-path-write
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/host/"
      - index: 2
        operator: "Mask"
        values:
        - "2"  # O_WRONLY
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_pid"
      matchActions:
      - action: Sigkill
```

### 4.3 Hubble 연동

Tetragon은 Cilium의 Hubble 관찰 플랫폼과 통합된다. Hubble은 네트워크 흐름, DNS 쿼리, HTTP 요청을 pod 단위로 기록한다. Tetragon 이벤트와 Hubble 네트워크 이벤트를 결합하면 프로세스 실행과 네트워크 연결을 하나의 타임라인으로 볼 수 있다.

```bash
# Hubble CLI로 특정 pod의 네트워크 흐름 조회
hubble observe --pod atdr/suspicious-pod --follow

# Tetragon 이벤트 스트림 조회
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --pods suspicious-pod
```

---

## 5. 탐지 소스 간 상관관계

### 5.1 동일 인시던트를 가리키는 다중 신호

크립토마이닝 공격이 발생하면 세 도구가 각각 다른 신호를 생성한다.

```
T+0s   Tetragon: xmrig 바이너리 execve 이벤트 (차단 전 로깅)
T+0s   Falco:    Known Cryptominer Binary Executed (CRITICAL)
T+30s  GuardDuty: CryptoCurrency:EKS/BitcoinTool.B!DNS (stratum DNS 쿼리)
T+60s  GuardDuty: Extended Threat Detection - 다단계 공격 체인 인식
```

이 신호들은 서로 다른 채널로 전달된다. GuardDuty Finding은 EventBridge를 통해, Falco Alert는 Falcosidekick을 통해 SNS로, Tetragon 이벤트는 직접 Kafka 또는 SNS로 전달된다. 상관관계 엔진은 이 신호들을 시간 윈도우와 공통 필드로 묶는다.

### 5.2 이벤트 정규화 스키마

세 소스의 이벤트를 하나의 스키마로 정규화한다.

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2025-05-04T12:34:56.789Z",
  "source": "falco | guardduty | tetragon",
  "severity": "critical | high | medium | low | info",
  "cluster": "atdr-eks-cluster",
  "namespace": "production",
  "pod": "web-deployment-7d9f8b-xk2p9",
  "node": "ip-10-0-1-42.ap-northeast-2.compute.internal",
  "container": "web-app",
  "image": "nginx:1.25.3",
  "process": {
    "name": "xmrig",
    "pid": 12345,
    "cmdline": "xmrig --pool stratum+tcp://pool.minexmr.com:4444"
  },
  "network": {
    "dst_ip": "45.33.32.156",
    "dst_port": 4444,
    "protocol": "tcp"
  },
  "rule": "Known Cryptominer Binary Executed",
  "mitre_tactic": "TA0040",
  "mitre_technique": "T1496",
  "raw": {}
}
```

`source`, `timestamp`, `pod`, `namespace`, `node`, `severity`는 모든 이벤트에 필수 필드다. 상관관계 엔진은 동일한 `pod`와 `namespace`를 가진 이벤트를 시간 윈도우(기본 5분) 내에서 그룹화한다.

---

## 6. 탐지 성능 고려사항

### 6.1 eBPF 오버헤드

GuardDuty Runtime Agent, Falco(modern_bpf), Tetragon은 모두 eBPF 기반이다. 세 에이전트가 동시에 실행될 때 예상 오버헤드는 다음과 같다.

| 에이전트 | CPU 오버헤드 | 메모리 | 레이턴시 영향 |
|---|---|---|---|
| GuardDuty Runtime Agent | ~0.5% | ~100Mi | <1μs |
| Falco (modern_bpf) | ~1% | ~256Mi | <2μs |
| Tetragon | ~0.5% | ~128Mi | <2μs |
| 합계 (최악) | <2% | ~484Mi | <5μs |

실제 오버헤드는 워크로드 특성에 따라 달라진다. syscall 집약적인 워크로드(파일 I/O 다수)에서는 더 높게 측정될 수 있다. 프로덕션 배포 전 부하 테스트로 실측값을 확인해야 한다.

### 6.2 노이즈 감소 전략

탐지 도구를 여러 개 운영하면 동일한 이벤트에 대해 중복 Alert가 발생한다. 노이즈를 줄이는 방법은 두 가지다.

**중복 제거**: 상관관계 엔진에서 동일한 `pod`, `rule`, `mitre_technique` 조합이 5분 내에 반복되면 첫 번째 이벤트만 인시던트로 승격한다. 이후 이벤트는 기존 인시던트에 증거로 추가된다.

**심각도 필터링**: Falcosidekick의 `minimumpriority: warning` 설정으로 `notice` 이하 이벤트는 SNS로 전달하지 않는다. GuardDuty Finding은 `MEDIUM` 이상만 EventBridge 규칙으로 처리한다.

```hcl
# EventBridge 규칙: GuardDuty MEDIUM 이상만 처리
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "atdr-guardduty-findings"
  description = "GuardDuty findings with severity >= MEDIUM"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })
}
```

GuardDuty severity 4.0은 MEDIUM에 해당한다. LOW(1.0~3.9) Finding은 로그로만 보관하고 실시간 처리 파이프라인에서 제외한다.

---

## 7. 참고

- [Amazon GuardDuty EKS Protection](https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html)
- [Falco Rules Reference](https://falco.org/docs/rules/)
- [Tetragon TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [03-correlation.md](./03-correlation.md) - 탐지 신호 상관관계 엔진
- [04-response.md](./04-response.md) - 대응 및 복구 워크플로
