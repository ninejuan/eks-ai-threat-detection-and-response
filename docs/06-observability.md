# 06. 관측성 스택 (Observability)

> Prometheus + Grafana + Loki + Hubble 기반 모니터링 설계

---

## 1. 관측성 스택 개요

ATDR의 관측성 스택은 네 가지 컴포넌트로 구성된다.

| 컴포넌트 | 역할 | 배포 방식 |
|----------|------|----------|
| Prometheus | 메트릭 수집 및 저장 | kube-prometheus-stack Helm |
| Grafana | 시각화 및 알림 | kube-prometheus-stack 포함 |
| Loki | 로그 수집 및 쿼리 | Helm (grafana/loki-stack) |
| Hubble | Cilium 네트워크 플로우 가시성 | Cilium 내장 |

```
클러스터 내 컴포넌트
├── Falco          → Falcosidekick → Loki
├── 애플리케이션    → Prometheus (ServiceMonitor)
├── Cilium/Hubble  → Prometheus (네트워크 메트릭)
└── 모든 소스       → Grafana (단일 대시보드)
```

각 컴포넌트는 `monitoring` 네임스페이스에 배포한다. Grafana는 Prometheus와 Loki를 데이터소스로 연결해 보안 이벤트, 인시던트 상태, 클러스터 상태, 네트워크 플로우를 단일 화면에서 확인할 수 있게 한다.

---

## 2. Prometheus 설정

### 2.1 kube-prometheus-stack Helm 배포

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --version 58.x \
  -f k8s/base/monitoring/prometheus-values.yaml
```

`prometheus-values.yaml` 핵심 설정:

```yaml
prometheus:
  prometheusSpec:
    retention: 30d
    retentionSize: "50GB"
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: gp3
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
    # 모든 네임스페이스의 ServiceMonitor 수집
    serviceMonitorSelectorNilUsesHelmValues: false
    serviceMonitorNamespaceSelector: {}
    serviceMonitorSelector: {}
    # 추가 스크레이프 설정 (Falco, Hubble)
    additionalScrapeConfigs:
      - job_name: falco
        static_configs:
          - targets: ['falco-exporter.falco.svc.cluster.local:9376']
      - job_name: hubble
        static_configs:
          - targets: ['hubble-relay.kube-system.svc.cluster.local:9965']

grafana:
  enabled: true
  adminPassword: "${GRAFANA_ADMIN_PASSWORD}"
  persistence:
    enabled: true
    storageClassName: gp3
    size: 10Gi
  additionalDataSources:
    - name: Loki
      type: loki
      url: http://loki.monitoring.svc.cluster.local:3100
      access: proxy

alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          storageClassName: gp3
          resources:
            requests:
              storage: 10Gi
```

### 2.2 커스텀 메트릭

ATDR 전용 메트릭 세 가지를 정의한다. ai-detector, correlator, response-advisor 서비스가 `/metrics` 엔드포인트로 노출한다.

```python
# apps/ai-detector/metrics.py
from prometheus_client import Counter, Histogram, Gauge

# 탐지 이벤트 수 (소스별, 심각도별)
detection_events_total = Counter(
    'atdr_detection_events_total',
    'Total number of detection events',
    ['source', 'severity', 'threat_type']
)

# 대응 실행 수 (액션별, 결과별)
remediation_executions_total = Counter(
    'atdr_remediation_executions_total',
    'Total number of remediation executions',
    ['action', 'result', 'severity']
)

# 에이전트 응답 시간 (에이전트별)
agent_response_duration_seconds = Histogram(
    'atdr_agent_response_duration_seconds',
    'Agent response duration in seconds',
    ['agent_name'],
    buckets=[0.5, 1, 2, 5, 10, 30, 60, 120]
)

# 활성 인시던트 수
active_incidents_gauge = Gauge(
    'atdr_active_incidents',
    'Number of currently active incidents',
    ['severity']
)
```

### 2.3 ServiceMonitor 설정

```yaml
# k8s/base/monitoring/servicemonitor-atdr.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: atdr-services
  namespace: monitoring
  labels:
    release: kube-prometheus-stack
spec:
  namespaceSelector:
    matchNames:
      - atdr
      - falco
  selector:
    matchLabels:
      atdr.io/monitored: "true"
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
      scheme: http
```

대상 서비스에 레이블을 추가한다:

```yaml
# k8s/base/ai-detector/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: ai-detector
  namespace: atdr
  labels:
    app: ai-detector
    atdr.io/monitored: "true"
spec:
  ports:
    - name: metrics
      port: 8080
      targetPort: 8080
    - name: http
      port: 8000
      targetPort: 8000
  selector:
    app: ai-detector
```

---

## 3. Grafana 대시보드 설계

대시보드는 네 가지로 구성한다. 각각 독립적으로 사용할 수 있지만, 인시던트 조사 시에는 보안 이벤트 → 인시던트 → 네트워크 순서로 드릴다운한다.

### 3.1 보안 이벤트 대시보드 (Security Events)

**목적**: 탐지 이벤트의 전체 현황을 한눈에 파악

| 패널 | 타입 | 쿼리 |
|------|------|------|
| 시간별 이벤트 수 | Time series | `sum(rate(atdr_detection_events_total[5m])) by (severity)` |
| 심각도 분포 | Pie chart | `sum(atdr_detection_events_total) by (severity)` |
| 소스별 분포 | Bar chart | `sum(atdr_detection_events_total) by (source)` |
| 위협 유형 Top 10 | Table | `topk(10, sum(atdr_detection_events_total) by (threat_type))` |
| 최근 1시간 이벤트 수 | Stat | `sum(increase(atdr_detection_events_total[1h]))` |
| Critical 이벤트 수 | Stat (빨간색) | `sum(increase(atdr_detection_events_total{severity="critical"}[1h]))` |

패널 레이아웃:

```
┌─────────────────────────────────────────────────────────┐
│  [Stat] 전체  [Stat] Critical  [Stat] High  [Stat] MTTR │
├─────────────────────────────────────────────────────────┤
│  [Time series] 시간별 이벤트 수 (심각도별 스택)           │
├──────────────────────┬──────────────────────────────────┤
│  [Pie] 심각도 분포   │  [Bar] 소스별 분포               │
├──────────────────────┴──────────────────────────────────┤
│  [Table] 위협 유형 Top 10 (건수, 최근 발생, 추세)        │
└─────────────────────────────────────────────────────────┘
```

### 3.2 인시던트 대시보드 (Incidents)

**목적**: 진행 중인 인시던트 상태 추적 및 대응 현황 모니터링

| 패널 | 타입 | 쿼리 |
|------|------|------|
| 활성 인시던트 수 | Stat | `sum(atdr_active_incidents)` |
| 심각도별 활성 인시던트 | Bar gauge | `sum(atdr_active_incidents) by (severity)` |
| 대응 성공률 | Stat | `sum(atdr_remediation_executions_total{result="success"}) / sum(atdr_remediation_executions_total)` |
| MTTR (평균 대응 시간) | Stat | `avg(atdr_agent_response_duration_seconds_sum / atdr_agent_response_duration_seconds_count)` |
| 에이전트별 응답 시간 | Heatmap | `atdr_agent_response_duration_seconds_bucket` |
| 대응 액션 분포 | Bar chart | `sum(atdr_remediation_executions_total) by (action)` |
| 인시던트 타임라인 | Logs panel | Loki: `{job="atdr-incidents"}` |

패널 레이아웃:

```
┌─────────────────────────────────────────────────────────┐
│  [Stat] 활성  [Stat] 성공률  [Stat] MTTR  [Stat] 자동실행│
├──────────────────────┬──────────────────────────────────┤
│  [Bar gauge]         │  [Heatmap] 에이전트 응답 시간     │
│  심각도별 인시던트   │                                  │
├──────────────────────┴──────────────────────────────────┤
│  [Bar chart] 대응 액션 분포 (성공/실패/롤백)             │
├─────────────────────────────────────────────────────────┤
│  [Logs] 인시던트 타임라인 (실시간)                       │
└─────────────────────────────────────────────────────────┘
```

### 3.3 클러스터 상태 대시보드 (Cluster Health)

**목적**: EKS 클러스터 전반의 리소스 상태 및 이상 징후 감지

| 패널 | 타입 | 쿼리 |
|------|------|------|
| 노드 상태 | Table | `kube_node_status_condition{condition="Ready"}` |
| 파드 상태 분포 | Pie chart | `sum(kube_pod_status_phase) by (phase)` |
| CPU 사용률 | Time series | `sum(rate(container_cpu_usage_seconds_total[5m])) by (namespace)` |
| 메모리 사용률 | Time series | `sum(container_memory_working_set_bytes) by (namespace)` |
| 재시작 횟수 Top 10 | Table | `topk(10, sum(kube_pod_container_status_restarts_total) by (pod, namespace))` |
| 네임스페이스별 파드 수 | Bar chart | `sum(kube_pod_info) by (namespace)` |
| 노드 CPU 압박 | Gauge | `sum(kube_node_status_condition{condition="MemoryPressure",status="true"})` |

### 3.4 네트워크 대시보드 (Network / Hubble)

**목적**: Cilium/Hubble 기반 네트워크 플로우 가시성 및 이상 트래픽 탐지

| 패널 | 타입 | 쿼리 |
|------|------|------|
| 초당 플로우 수 | Time series | `sum(rate(hubble_flows_processed_total[1m]))` |
| 차단된 트래픽 | Time series | `sum(rate(hubble_drop_total[1m])) by (reason)` |
| DNS 쿼리 수 | Time series | `sum(rate(hubble_dns_queries_total[1m]))` |
| DNS 오류율 | Stat | `sum(rate(hubble_dns_responses_total{rcode!="No Error"}[5m])) / sum(rate(hubble_dns_responses_total[5m]))` |
| 네임스페이스 간 트래픽 | Heatmap | `sum(rate(hubble_flows_processed_total[1m])) by (source_namespace, destination_namespace)` |
| 외부 연결 Top 10 | Table | `topk(10, sum(rate(hubble_flows_processed_total{destination_ip!~"10.*|172.*|192.168.*"}[5m])) by (destination_ip))` |
| TCP 재전송률 | Time series | `sum(rate(hubble_tcp_flags_total{flag="SYN_ACK"}[1m]))` |

---

## 4. Loki 설정

### 4.1 Loki 배포

```bash
helm upgrade --install loki grafana/loki-stack \
  --namespace monitoring \
  --set loki.persistence.enabled=true \
  --set loki.persistence.storageClassName=gp3 \
  --set loki.persistence.size=50Gi \
  --set promtail.enabled=true \
  -f k8s/base/monitoring/loki-values.yaml
```

`loki-values.yaml`:

```yaml
loki:
  config:
    ingester:
      chunk_idle_period: 3m
      chunk_block_size: 262144
      chunk_retain_period: 1m
    limits_config:
      retention_period: 720h   # 30일
      ingestion_rate_mb: 16
      ingestion_burst_size_mb: 32
    storage_config:
      boltdb_shipper:
        active_index_directory: /data/loki/boltdb-shipper-active
        cache_location: /data/loki/boltdb-shipper-cache
        shared_store: s3
      aws:
        s3: s3://atdr-loki-logs/
        region: ap-northeast-2

promtail:
  config:
    snippets:
      extraScrapeConfigs: |
        - job_name: falco
          static_configs:
            - targets:
                - localhost
              labels:
                job: falco
                __path__: /var/log/falco/*.log
```

### 4.2 Falco 로그 수집 (Falcosidekick → Loki)

Falcosidekick을 Loki 출력으로 설정한다:

```yaml
# k8s/base/falco/falcosidekick-values.yaml
config:
  loki:
    hostport: "http://loki.monitoring.svc.cluster.local:3100"
    user: ""
    apikey: ""
    minimumpriority: "warning"
    tenant: ""
    extralabels: "source=falco,cluster=atdr"
    customHeaders: ""
    mutualtls: false
    checkcert: true
```

### 4.3 EKS 컨트롤 플레인 로그

EKS 컨트롤 플레인 로그는 CloudWatch Logs로 전송된 후 Lambda를 통해 Loki로 포워딩한다.

```python
# scripts/cloudwatch-to-loki/handler.py
import json
import gzip
import base64
import requests
from datetime import datetime

LOKI_URL = "http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push"

def handler(event, context):
    payload = base64.b64decode(event['awslogs']['data'])
    log_data = json.loads(gzip.decompress(payload))

    streams = []
    for log_event in log_data['logEvents']:
        streams.append({
            "stream": {
                "job": "eks-controlplane",
                "log_group": log_data['logGroup'],
                "log_stream": log_data['logStream'],
                "cluster": "atdr"
            },
            "values": [
                [str(log_event['timestamp'] * 1_000_000), log_event['message']]
            ]
        })

    requests.post(LOKI_URL, json={"streams": streams})
```

### 4.4 LogQL 쿼리 예시

```logql
# Falco Critical 이벤트 조회
{job="falco"} | json | priority="CRITICAL"

# 특정 파드의 런타임 이벤트
{job="falco"} | json | k8s_pod_name="payment-service-7d9f8b-xk2p9"

# 컨테이너 탈출 시도 탐지
{job="falco"} | json | rule=~".*container.*escape.*|.*privilege.*escalation.*"

# EKS 감사 로그에서 kubectl exec 조회
{job="eks-controlplane", log_stream=~".*kube-apiserver-audit.*"}
  | json
  | verb="create"
  | requestURI=~".*/exec"

# 지난 1시간 동안 Critical 이벤트 수 집계
sum(count_over_time({job="falco"} | json | priority="CRITICAL" [1h]))

# 네임스페이스별 Falco 이벤트 분포
sum by (k8s_ns_name) (
  count_over_time({job="falco"} | json [5m])
)
```

---

## 5. Hubble 네트워크 관측

### 5.1 Hubble Relay + UI 배포

Cilium 설치 시 Hubble을 함께 활성화한다:

```bash
helm upgrade --install cilium cilium/cilium \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,http}" \
  --set hubble.metrics.serviceMonitor.enabled=true \
  --set hubble.relay.prometheus.enabled=true \
  --set hubble.relay.prometheus.serviceMonitor.enabled=true
```

Hubble UI는 포트 포워딩으로 접근한다:

```bash
kubectl port-forward -n kube-system svc/hubble-ui 12000:80
# http://localhost:12000 에서 네트워크 플로우 시각화
```

### 5.2 네트워크 플로우 메트릭

Hubble이 노출하는 주요 메트릭:

| 메트릭 | 설명 |
|--------|------|
| `hubble_flows_processed_total` | 처리된 전체 플로우 수 (verdict, direction별) |
| `hubble_drop_total` | 차단된 패킷 수 (reason별) |
| `hubble_dns_queries_total` | DNS 쿼리 수 (type별) |
| `hubble_dns_responses_total` | DNS 응답 수 (rcode별) |
| `hubble_tcp_flags_total` | TCP 플래그별 패킷 수 |
| `hubble_http_requests_total` | HTTP 요청 수 (method, protocol별) |
| `hubble_http_response_duration_seconds` | HTTP 응답 시간 분포 |

### 5.3 Grafana 연동

Hubble ServiceMonitor가 자동으로 Prometheus 수집 대상에 포함된다. Grafana에서 Hubble 공식 대시보드를 임포트한다:

```bash
# Hubble 공식 대시보드 ID
# - Hubble L4 Metrics: 16611
# - Hubble DNS: 16612
# - Hubble HTTP: 16613
```

커스텀 패널 예시 (차단된 트래픽 원인 분석):

```promql
# 차단 이유별 트래픽 (상위 5개)
topk(5,
  sum(rate(hubble_drop_total[5m])) by (reason)
)

# 네임스페이스 간 차단된 연결
sum(rate(hubble_drop_total{
  source_namespace!="",
  destination_namespace!=""
}[5m])) by (source_namespace, destination_namespace, reason)

# 외부 IP로의 아웃바운드 플로우 (RFC1918 제외)
sum(rate(hubble_flows_processed_total{
  direction="EGRESS",
  destination_ip!~"10\\..*|172\\.(1[6-9]|2[0-9]|3[01])\\..*|192\\.168\\..*"
}[5m])) by (source_namespace, destination_ip)
```

---

## 6. 알림 규칙 (Grafana Alerting)

### 6.1 탐지 이벤트 급증 알림

```yaml
# k8s/base/monitoring/alert-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: atdr-alerts
  namespace: monitoring
  labels:
    release: kube-prometheus-stack
spec:
  groups:
    - name: atdr.detection
      interval: 30s
      rules:
        - alert: DetectionEventSpike
          expr: |
            sum(rate(atdr_detection_events_total[5m])) > 10
          for: 2m
          labels:
            severity: warning
            team: security
          annotations:
            summary: "탐지 이벤트 급증"
            description: "지난 5분간 탐지 이벤트가 분당 {{ $value | humanize }}건 발생 중"

        - alert: CriticalEventDetected
          expr: |
            sum(increase(atdr_detection_events_total{severity="critical"}[5m])) > 0
          for: 0m
          labels:
            severity: critical
            team: security
          annotations:
            summary: "Critical 보안 이벤트 탐지"
            description: "Critical 심각도 이벤트 {{ $value }}건 탐지됨"
```

### 6.2 에이전트 응답 지연 알림

```yaml
        - alert: AgentResponseSlow
          expr: |
            histogram_quantile(0.95,
              sum(rate(atdr_agent_response_duration_seconds_bucket[5m])) by (agent_name, le)
            ) > 30
          for: 5m
          labels:
            severity: warning
            team: platform
          annotations:
            summary: "에이전트 응답 지연"
            description: "{{ $labels.agent_name }} P95 응답 시간이 {{ $value | humanizeDuration }} 초과"

        - alert: AgentResponseTimeout
          expr: |
            histogram_quantile(0.99,
              sum(rate(atdr_agent_response_duration_seconds_bucket[5m])) by (agent_name, le)
            ) > 120
          for: 2m
          labels:
            severity: critical
            team: platform
          annotations:
            summary: "에이전트 응답 타임아웃 수준"
            description: "{{ $labels.agent_name }} P99 응답 시간이 {{ $value | humanizeDuration }} — 타임아웃 임박"
```

### 6.3 클러스터 이상 알림

```yaml
    - name: atdr.cluster
      interval: 60s
      rules:
        - alert: NodeNotReady
          expr: |
            kube_node_status_condition{condition="Ready", status="true"} == 0
          for: 5m
          labels:
            severity: critical
            team: platform
          annotations:
            summary: "노드 NotReady"
            description: "노드 {{ $labels.node }}가 5분 이상 NotReady 상태"

        - alert: PodCrashLooping
          expr: |
            rate(kube_pod_container_status_restarts_total[15m]) * 60 * 15 > 5
          for: 5m
          labels:
            severity: warning
            team: platform
          annotations:
            summary: "파드 CrashLoopBackOff"
            description: "{{ $labels.namespace }}/{{ $labels.pod }} 15분간 {{ $value | humanize }}회 재시작"

        - alert: HighNetworkDropRate
          expr: |
            sum(rate(hubble_drop_total[5m])) > 100
          for: 3m
          labels:
            severity: warning
            team: security
          annotations:
            summary: "네트워크 차단 급증"
            description: "초당 {{ $value | humanize }}개 패킷 차단 중 — NetworkPolicy 또는 공격 확인 필요"

        - alert: RemediationFailureRate
          expr: |
            sum(rate(atdr_remediation_executions_total{result="failure"}[10m]))
            /
            sum(rate(atdr_remediation_executions_total[10m])) > 0.2
          for: 5m
          labels:
            severity: warning
            team: security
          annotations:
            summary: "대응 실행 실패율 높음"
            description: "대응 실패율 {{ $value | humanizePercentage }} — EKS MCP 연결 또는 권한 확인 필요"
```

### 6.4 Alertmanager 라우팅

```yaml
# k8s/base/monitoring/alertmanager-config.yaml
apiVersion: monitoring.coreos.com/v1alpha1
kind: AlertmanagerConfig
metadata:
  name: atdr-alertmanager
  namespace: monitoring
spec:
  route:
    receiver: slack-security
    groupBy: ['alertname', 'severity']
    groupWait: 30s
    groupInterval: 5m
    repeatInterval: 4h
    routes:
      - matchers:
          - name: severity
            value: critical
        receiver: slack-security-critical
        repeatInterval: 1h
      - matchers:
          - name: team
            value: platform
        receiver: slack-platform

  receivers:
    - name: slack-security
      slackConfigs:
        - apiURL:
            name: slack-webhook-secret
            key: url
          channel: '#security-alerts'
          title: '[{{ .Status | toUpper }}] {{ .CommonAnnotations.summary }}'
          text: '{{ .CommonAnnotations.description }}'

    - name: slack-security-critical
      slackConfigs:
        - apiURL:
            name: slack-webhook-secret
            key: url
          channel: '#security-critical'
          title: ':rotating_light: CRITICAL: {{ .CommonAnnotations.summary }}'
          text: '{{ .CommonAnnotations.description }}'
          sendResolved: true
```
