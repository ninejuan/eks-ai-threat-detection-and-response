# ATDR: AI-Driven Threat Detection and Response for EKS

> 내부 설계 문서 v0.1 | 2026-05-04 | 팀 4인 | 8주 캡스톤

---

## 1. 프로젝트 개요

ATDR(AI-Driven Threat Detection and Response)은 AWS EKS 환경에서 발생하는 보안 위협을 AI로 탐지·분석·대응하는 시스템이다.

기존 보안 도구들은 각자의 시그널을 독립적으로 발생시킨다. GuardDuty는 Finding을 내고, Falco는 런타임 이벤트를 뱉고, VPC Flow Logs는 네트워크 흐름을 기록한다. 이 시그널들을 연결해서 "지금 무슨 일이 벌어지고 있는가"를 판단하는 건 결국 사람 몫이다.

ATDR은 그 판단 과정을 자동화한다. CloudTrail, DNS Logs, VPC Flow Logs, EKS Audit Logs, Falco 런타임 이벤트를 단일 파이프라인으로 수집하고, Bedrock 기반 AI 에이전트 체인이 요약→트리아지→해결책 탐색→대응 실행까지 처리한다. 사람은 Slack에서 승인 버튼 하나로 개입하거나, 자연어로 현황을 조회한다.

학교 캡스톤 프로젝트지만 실제 AWS 계정에 배포하고 실제 공격 시나리오를 돌린다.

---

## 2. 문제 정의

### 보안 시그널 파편화

EKS 환경에서 하나의 공격은 여러 레이어에 흔적을 남긴다.

```
crypto-miner 파드 실행 시나리오:

  CloudTrail    → 비정상 IAM API 호출
  EKS Audit     → 권한 없는 kubectl exec
  Falco         → 컨테이너 내 curl/wget 실행
  VPC Flow Logs → 외부 마이닝 풀로의 아웃바운드 트래픽
  DNS Logs      → 알 수 없는 도메인 쿼리
```

각 시그널은 단독으로는 노이즈처럼 보인다. 연결해야 공격이 보인다.

### 현재 운영 방식의 한계

- 보안 담당자가 GuardDuty 콘솔, CloudWatch Logs Insights, kubectl 명령어를 번갈아 확인
- 시그널 간 상관관계를 수동으로 추론
- 대응 액션(NetworkPolicy 적용, 파드 격리)을 직접 실행
- 인시던트 하나당 평균 수십 분 소요

ATDR이 목표로 하는 건 이 흐름을 5분 이내로 줄이는 것이다.

---

## 3. 핵심 목표

```
탐지 → 요약 → 트리아지 → 해결책 탐색 → 대응 실행 → 설명
```

각 단계를 AI 에이전트가 담당하고, 사람은 승인 지점에서만 개입한다.

| 목표 | 설명 |
|------|------|
| 멀티소스 탐지 | CloudTrail, DNS, VPC Flow, EKS Audit, Falco 통합 수집 |
| AI 요약 | GuardDuty Finding을 자연어 인시던트 리포트로 변환 |
| 자동 트리아지 | 심각도 분류, 영향 범위 추정, 우선순위 결정 |
| 지식 기반 해결책 | OpenSearch Serverless KB에서 관련 Runbook 검색 |
| 대응 실행 | EKS MCP를 통한 NetworkPolicy 적용, 파드 격리 |
| 감사 추적 | S3 Object Lock + CloudTrail Lake로 포렌식 보존 |

---

## 4. 전체 아키텍처

### 4.1 데이터 수집 레이어

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                             │
│                                                                 │
│  CloudTrail ──────────────────────────────┐                     │
│  DNS Logs ────────────────────────────────┼──► EventBridge      │
│                                           │                     │
│  VPC Flow Logs ───────────────────────────┐                     │
│  EKS Audit Logs ──────────────────────────┼──► GuardDuty        │
│  EKS (GuardDuty Agent) ───────────────────┘    │                │
│                                                │ Finding        │
│  Falco (eBPF) ──► Falcosidekick ──► SNS ──► SQS ──► Lambda     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

- CloudTrail, DNS Logs는 EventBridge Rule을 통해 Lambda로 라우팅
- VPC Flow Logs, EKS Audit Logs는 GuardDuty가 직접 분석 후 Finding 생성
- EKS 클러스터 내 GuardDuty Agent가 런타임 이벤트를 GuardDuty로 전송
- Falco는 eBPF 기반 런타임 탐지 → Falcosidekick → SNS → SQS → Lambda 체인

### 4.2 AI 처리 레이어

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI PROCESSING LAYER                          │
│                                                                 │
│  EventBridge ──────────────────────────────────────────────┐   │
│  GuardDuty Finding ────────────────────────────────────────┤   │
│  SQS (Falco) ──────────────────────────────────────────────┤   │
│                                                            ▼   │
│                    Lambda w/ Strands Agent                     │
│                    ┌───────────────────────────────────┐       │
│                    │                                   │       │
│                    │  [1] Summary Agent                │       │
│                    │      ↓                            │       │
│                    │  [2] Triage Agent                 │       │
│                    │      ↓                            │       │
│                    │  [3] Solution Agent ◄──► KB       │       │
│                    │      ↓              (OpenSearch   │       │
│                    │  [4] Remediation Agent  Serverless│       │
│                    │      ↓              + S3)         │       │
│                    │   EKS MCP                         │       │
│                    └───────────────────────────────────┘       │
│                            │                                   │
│                    Amazon Bedrock                              │
│                    ├── Claude Haiku 4.5  (Summary, Triage)     │
│                    └── Claude Sonnet 4.6 (Solution, Remediation│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 대응 및 알림 레이어

```
┌─────────────────────────────────────────────────────────────────┐
│                  RESPONSE & NOTIFICATION                        │
│                                                                 │
│  Lambda w/ Strands Agent                                        │
│       │                                                         │
│       ├──► API Gateway ──► Slack Bot Lambda                     │
│       │                        │                               │
│       │                        ├── 인시던트 알림 (자동)          │
│       │                        ├── 대응 승인 요청               │
│       │                        └── 자연어 조회 응답             │
│       │                                                         │
│       └──► EKS MCP ──► EKS Cluster                             │
│                            ├── NetworkPolicy 적용               │
│                            ├── 파드 격리 / 삭제                 │
│                            └── 네임스페이스 격리                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.4 전체 데이터 흐름 요약

```
CloudTrail ──────────────────────────────────────────────────────┐
DNS Logs ────────────────────────────────────────────────────────┤
                                                                 ▼
                                                         EventBridge
                                                                 │
VPC Flow Logs ───────────────────────────────────────────────────┐
EKS Audit Logs ──────────────────────────────────────────────────┤
EKS (GuardDuty Agent) ───────────────────────────────────────────┤
                                                                 ▼
                                                          GuardDuty
                                                          (Finding)
                                                                 │
Falco (eBPF) ──► Falcosidekick ──► SNS ──► SQS ─────────────────┤
                                                                 │
                                                                 ▼
                                              Lambda w/ Strands Agent
                                                                 │
                                              ┌──────────────────┤
                                              │                  │
                                              ▼                  ▼
                                        Bedrock              API Gateway
                                   (Haiku 4.5 /              │
                                    Sonnet 4.6)           Slack Bot
                                              │
                              ┌───────────────┤
                              │               │
                              ▼               ▼
                     OpenSearch          EKS MCP
                     Serverless KB    (kubectl 실행)
                     (+ S3 Runbook)
```

### 4.5 4개 에이전트 체인

```
이벤트 수신
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Summary Agent  (Claude Haiku 4.5)                  │
│  - GuardDuty Finding / Falco 이벤트 자연어 요약      │
│  - 영향 받는 리소스, 타임라인 정리                   │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Triage Agent  (Claude Haiku 4.5)                   │
│  - 심각도 분류 (Critical / High / Medium / Low)      │
│  - 공격 유형 분류 (lateral movement, crypto-mining…) │
│  - 즉각 대응 필요 여부 판단                          │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Solution Agent  (Claude Sonnet 4.6)                │
│  - OpenSearch Serverless KB에서 관련 Runbook 검색    │
│  - 대응 옵션 생성 및 우선순위 결정                   │
│  - 예상 영향도 분석                                  │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Remediation Agent  (Claude Sonnet 4.6)             │
│  - EKS MCP를 통해 kubectl 명령 실행                  │
│  - NetworkPolicy 생성, 파드 격리, 네임스페이스 잠금  │
│  - 실행 결과 검증 및 보고                            │
└─────────────────────────────────────────────────────┘
```

### 4.6 Slack Bot 인터페이스

Lambda + API Gateway 조합으로 구현한다.

- 인시던트 발생 시 자동 알림 (요약 + 심각도 + 영향 리소스)
- 대응 액션 승인 요청 (버튼 클릭으로 승인/거부)
- 자연어 조회: "지난 1시간 동안 Critical 인시던트 있었어?" 같은 질문에 응답

### 4.7 모니터링 스택

```
Prometheus ──► Grafana   (메트릭 시각화)
Loki                     (로그 집계)
Hubble                   (Cilium 네트워크 흐름 가시성)
```

### 4.8 포렌식 및 감사

```
S3 Object Lock           (이벤트 원본 불변 보존)
CloudTrail Lake          (SQL 기반 이벤트 쿼리)
Container Checkpoint     (의심 컨테이너 메모리 스냅샷)
Hubble                   (네트워크 흐름 기록)
```

### 4.9 보안 레이어

```
Cilium CNI               (eBPF 기반 네트워크 정책)
Tetragon                 (eBPF 런타임 보안 관찰)
ValidatingAdmissionPolicy (파드 스펙 검증)
WireGuard                (노드 간 암호화 통신, Cilium 통합)
```

---

## 5. 기술 스택

| 카테고리 | 기술 | 버전 / 비고 |
|----------|------|-------------|
| 컨테이너 오케스트레이션 | Amazon EKS | 1.35 |
| CNI | Cilium | Access Entry API mode |
| 런타임 탐지 | Falco | eBPF 드라이버 |
| 런타임 보안 관찰 | Tetragon | Cilium 통합 |
| AI 오케스트레이션 | AWS Strands Agents | Lambda 내 실행 |
| LLM (요약/트리아지) | Claude Haiku 4.5 | Amazon Bedrock |
| LLM (해결책/대응) | Claude Sonnet 4.6 | Amazon Bedrock |
| 지식 베이스 | Amazon OpenSearch Serverless | Bedrock KB 연동 |
| 위협 탐지 | Amazon GuardDuty | EKS Runtime Monitoring 포함 |
| 이벤트 라우팅 | Amazon EventBridge | Rule 기반 필터링 |
| 알림 파이프라인 | Amazon SNS + SQS | Falco 이벤트 버퍼링 |
| 서버리스 실행 | AWS Lambda | Python 3.12 |
| API | Amazon API Gateway | Slack Bot 엔드포인트 |
| 메시징 | Slack | Bolt SDK |
| EKS 제어 | EKS MCP | kubectl 추상화 |
| 인프라 코드 | Terraform | EKS, VPC, IAM, Bedrock |
| K8s 매니페스트 | Kustomize | base + overlays |
| 메트릭 | Prometheus + Grafana | 클러스터 내 배포 |
| 로그 집계 | Loki | Grafana 연동 |
| 네트워크 가시성 | Hubble | Cilium 내장 |
| 포렌식 저장소 | S3 Object Lock | WORM 설정 |
| 감사 쿼리 | CloudTrail Lake | SQL 인터페이스 |
| 노드 타입 | t3.medium, t3.large, c5.large | 워크로드별 분리 |

---

## 6. 프로젝트 범위

### In Scope

- AWS EKS 1.35 기반 실제 배포 환경
- CloudTrail, DNS Logs, VPC Flow Logs, EKS Audit Logs, Falco 수집
- GuardDuty Finding 기반 AI 에이전트 파이프라인
- Bedrock 기반 4단계 에이전트 체인 (Summary → Triage → Solution → Remediation)
- OpenSearch Serverless 지식 베이스 + Runbook 관리
- Slack Bot 알림 및 승인 워크플로
- EKS MCP를 통한 반자동 대응 실행
- Prometheus + Grafana + Loki 모니터링
- S3 Object Lock + CloudTrail Lake 포렌식
- Cilium CNI + Tetragon + WireGuard 보안 레이어
- Terraform IaC + Kustomize 매니페스트
- 통제된 공격 시나리오 (crypto-mining, lateral movement, privilege escalation 등)

### Out of Scope

- 상용 SIEM 대체 (Splunk, Elastic SIEM 등)
- 프로덕션 SOC 통합
- LLM 파인튜닝 또는 커스텀 모델 학습
- 멀티클라우드 지원 (GKE, AKS)
- 오펜시브 익스플로잇 개발
- 실시간 패킷 캡처 기반 IDS

---

## 7. 팀 구성 및 타임라인

### 팀

4인 올라운더 구성. 별도 역할 분리 없이 주차별 태스크 단위로 협업한다.

### 8주 타임라인

| 주차 | 주요 작업 |
|------|-----------|
| 1주 | 인프라 설계 확정, Terraform EKS 클러스터 구축, Cilium 설치 |
| 2주 | 데이터 수집 파이프라인 (EventBridge, GuardDuty, Falco→SQS) |
| 3주 | Lambda + Strands Agent 기본 구조, Bedrock 연동 |
| 4주 | 4개 에이전트 체인 구현, OpenSearch KB 구축 |
| 5주 | EKS MCP 연동, Remediation Agent 구현, Slack Bot |
| 6주 | 공격 시나리오 실행 및 엔드투엔드 테스트 |
| 7주 | 모니터링 스택 (Prometheus/Grafana/Loki), 포렌식 파이프라인 |
| 8주 | 성능 측정, 문서 정리, 발표 준비 |

---

## 8. 문서 구조

```
docs/
├── 00-overview.md          ← 이 문서
├── 01-architecture.md      전체 아키텍처 상세 (컴포넌트별 설계)
├── 02-data-pipeline.md     데이터 수집 파이프라인 (EventBridge, GuardDuty, Falco)
├── 03-ai-agents.md         4개 에이전트 체인 설계 및 프롬프트
├── 04-knowledge-base.md    OpenSearch Serverless KB + Runbook 관리
├── 05-remediation.md       EKS MCP 연동 및 대응 액션 목록
├── 06-slack-bot.md         Slack Bot 구현 (알림, 승인, 조회)
├── 07-security-layer.md    Cilium, Tetragon, WireGuard, VAP 설정
├── 08-monitoring.md        Prometheus, Grafana, Loki, Hubble
├── 09-forensics.md         S3 Object Lock, CloudTrail Lake, Container Checkpoint
├── 10-attack-scenarios.md  테스트 시나리오 및 실행 방법
└── 11-runbooks/            대응 Runbook 원본 (KB 업로드용)
```

각 문서는 해당 컴포넌트의 설계 결정, 구현 세부사항, 운영 절차를 다룬다.
