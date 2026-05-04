# 프로젝트 계획서

## 프로젝트 개요

ATDR(AI-driven Threat Detection and Response)은 AWS EKS 환경에서 런타임 및 네트워크 위협을 자동으로 탐지하고 AI 에이전트가 분석과 대응까지 수행하는 시스템이다. 4명이 8주 동안 학교 캡스톤 프로젝트로 진행하며, 최종 발표는 슬라이드 자료와 라이브 데모로 구성한다.

팀원 모두 특정 역할에 고정되지 않고 전 영역을 함께 다루는 올라운더 구조로 운영한다. 다만 각자 주 담당 영역을 정해 책임 소재를 명확히 한다.

---

## 8주 타임라인

### 1주차: 인프라 기반

Terraform 모듈을 작성해 VPC, EKS, IAM 리소스를 코드로 관리한다. EKS 1.35 클러스터를 배포하고 Cilium CNI와 WireGuard 암호화를 설정한다. Access Entry로 클러스터 접근 권한을 구성하고, GuardDuty와 Security Hub를 활성화해 AWS 네이티브 탐지 기반을 마련한다.

**주요 산출물**
- Terraform 모듈 (VPC, EKS, IAM)
- EKS 1.35 클러스터 (Cilium CNI + WireGuard)
- GuardDuty, Security Hub 활성화 확인

### 2주차: 탐지 레이어

Falco와 Falcosidekick을 배포하고 Tetragon을 활성화해 런타임 이벤트를 수집한다. 프로젝트 시나리오에 맞는 Falco 커스텀 룰을 작성하고, ValidatingAdmissionPolicy로 워크로드 입장 제어를 설정한다. EventBridge 규칙을 구성하고 SNS → SQS → Lambda 파이프라인을 연결해 이벤트가 AI 에이전트까지 흐르는 경로를 완성한다.

**주요 산출물**
- Falco + Falcosidekick + Tetragon 배포
- 커스텀 Falco 룰
- SNS → SQS → Lambda 파이프라인

### 3주차: AI 에이전트 (1)

Strands Agent SDK를 설정하고 Summary Agent와 Triage Agent를 구현한다. Bedrock Claude Haiku 4.5 모델을 연동해 이벤트 요약과 위협 분류를 처리한다. Lambda 함수로 배포해 파이프라인과 연결한다.

**주요 산출물**
- Summary Agent, Triage Agent 구현
- Bedrock Haiku 4.5 연동
- Lambda 배포

### 4주차: AI 에이전트 (2) + 지식 베이스

Solution Agent를 Bedrock Claude Sonnet 4.6으로 구현한다. OpenSearch Serverless 기반 Knowledge Base를 설정하고 런북을 작성해 인덱싱한다. RAG 파이프라인을 구성해 에이전트가 런북을 참조해 대응 방안을 생성하도록 한다. Remediation Agent도 이 주차에 구현한다.

**주요 산출물**
- Solution Agent (Sonnet 4.6)
- OpenSearch Serverless KB + 런북 인덱싱
- RAG 파이프라인
- Remediation Agent 구현

### 5주차: 대응 + Slack 연동

EKS MCP를 연동해 에이전트가 클러스터에 직접 명령을 내릴 수 있도록 한다. NetworkPolicy 생성, Pod 격리, 재시작 등 대응 액션을 구현한다. Slack Bot을 구현해 알림 전송, 승인 요청, 상태 조회 기능을 제공한다. Human Approval 워크플로우를 구성해 위험도 높은 대응은 사람이 승인한 뒤 실행되도록 한다.

**주요 산출물**
- EKS MCP 연동
- 대응 액션 구현 (NetworkPolicy, Pod 제어)
- Slack Bot (알림, 승인, 조회)
- Human Approval 워크플로우

### 6주차: 공격 시뮬레이션 + 테스트

Stratus Red Team을 설정하고 5개 공격 시나리오를 구현한다. 탐지부터 분석, 대응까지 전체 파이프라인을 End-to-end로 테스트한다. 발견된 버그를 수정하고 각 시나리오별 탐지 결과를 기록한다.

**공격 시나리오 목록**
1. 컨테이너 내 권한 상승 시도
2. 비정상 외부 통신 (C2 비콘 패턴)
3. 네임스페이스 간 비정상 횡이동
4. 크립토마이닝 유사 CPU/네트워크 패턴
5. Kubernetes API 비정상 접근

**주요 산출물**
- Stratus Red Team 설정
- 5개 시나리오 E2E 테스트 결과
- 버그 수정 완료

### 7주차: 관측성 + 포렌식

Prometheus, Grafana, Loki를 배포하고 Grafana 대시보드를 구성한다. S3 Object Lock과 CloudTrail Lake로 포렌식 스택을 구성해 증거 보존 체계를 마련한다. Hubble로 네트워크 흐름을 시각화한다.

**주요 산출물**
- Prometheus + Grafana + Loki 배포
- Grafana 대시보드 (탐지, 대응, 시스템 메트릭)
- 포렌식 스택 (S3 Object Lock, CloudTrail Lake)
- Hubble 네트워크 관측 설정

### 8주차: 마무리 + 발표 준비

라이브 데모 리허설을 반복해 안정성을 확인한다. 발표 자료를 작성하고 문서를 정리한다. AWS 비용을 정리하고 발표 후 리소스를 삭제할 계획을 수립한다.

**주요 산출물**
- 라이브 데모 리허설 완료
- 발표 슬라이드
- 문서 최종 정리
- 비용 정리 + 리소스 삭제 계획

---

## 팀 역할 분담

4명 모두 전 영역에 참여하되, 아래와 같이 주 담당 영역을 나눈다.

| 멤버 | 주 담당 영역 |
|------|-------------|
| 멤버 A | 인프라, Terraform, EKS 클러스터 |
| 멤버 B | 탐지 레이어, Falco, GuardDuty |
| 멤버 C | AI 에이전트, Bedrock, Strands SDK |
| 멤버 D | Slack Bot, 관측성, Grafana 대시보드 |

공격 시뮬레이션, E2E 테스트, 문서 작성, 발표 준비는 4명이 함께 진행한다.

---

## 마일스톤

**M1 (2주차 끝): 인프라 + 탐지 동작 확인**
EKS 클러스터가 정상 동작하고 Falco 이벤트가 SNS → SQS → Lambda 파이프라인을 통해 전달되는 것을 확인한다.

**M2 (4주차 끝): AI 에이전트 + KB 동작 확인**
Summary, Triage, Solution, Remediation Agent가 모두 동작하고 RAG 파이프라인이 런북을 참조해 대응 방안을 생성하는 것을 확인한다.

**M3 (6주차 끝): 전체 파이프라인 E2E 동작**
5개 공격 시나리오 모두 탐지되고 Slack 알림 전송, Human Approval, 자동 대응 실행까지 전체 흐름이 동작하는 것을 확인한다.

**M4 (8주차 끝): 라이브 데모 준비 완료**
리허설에서 오류 없이 데모가 진행되고 발표 자료가 완성된 상태다.

---

## 리스크 관리

**AWS 크레딧 소진**
AWS Budgets로 비용 알림을 설정하고 주차별 예상 비용을 추적한다. EKS 노드 그룹은 데모 외 시간에 스케일 다운한다.

**Bedrock 모델 접근 제한**
모델 접근 권한은 1주차에 미리 신청한다. 특정 리전에서 접근이 안 될 경우 us-east-1 또는 us-west-2로 전환한다. Haiku 4.5나 Sonnet 4.6이 불가할 경우 대체 모델을 사전에 확인해둔다.

**타임라인 지연**
6주차 공격 시나리오는 5개가 기본이지만, 일정이 밀릴 경우 3개로 축소한다. 핵심 파이프라인(탐지 → 분석 → 대응)이 동작하는 것을 우선순위로 둔다.

**EKS 1.35 호환성**
Cilium, Falco, Tetragon의 EKS 1.35 지원 여부를 1주차 시작 전에 확인한다. 호환 문제가 있으면 1.30 또는 1.32로 다운그레이드한다.

---

## 평가 기준 (자체)

| 항목 | 목표 |
|------|------|
| 탐지 정확도 | 5개 시나리오 모두 탐지 |
| 대응 성공률 | 자동 대응 실행 후 위협 상태 해소 확인 |
| MTTR | 탐지 이벤트 발생부터 대응 완료까지 측정 |
| 라이브 데모 안정성 | 리허설 3회 이상, 오류 없이 완주 |

탐지 정확도와 대응 성공률은 각 시나리오 실행 로그와 Slack 알림 기록으로 검증한다. MTTR은 Falco 이벤트 타임스탬프부터 Remediation Agent 실행 완료 시각까지를 기준으로 측정한다.
