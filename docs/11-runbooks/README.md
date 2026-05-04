# ATDR 런북 인덱스

이 디렉터리의 런북은 S3에 저장되고 OpenSearch Serverless로 인덱싱된다. Solution Agent가 인시던트 분석 중 RAG로 검색해 대응 절차를 참조한다.

각 런북은 탐지 시그널, 초기 분석, 단계별 대응 절차, 자동 대응 액션, 검증, 에스컬레이션 순서로 구성된다.

---

## 런북 목록

| 위협 유형 | 심각도 | MITRE Technique | 파일 |
|---|---|---|---|
| 크립토마이닝 | P2 | T1496 Resource Hijacking | [cryptomining.md](./cryptomining.md) |
| 권한 상승 | P1 | T1611 Escape to Host / T1548 Abuse Elevation Control Mechanism | [privilege-escalation.md](./privilege-escalation.md) |
| 시크릿 탈취 | P1 | T1552 Unsecured Credentials | [secret-exfiltration.md](./secret-exfiltration.md) |
| DNS 이상 | P3 | T1071.004 Application Layer Protocol: DNS | [dns-anomaly.md](./dns-anomaly.md) |
| 횡적 이동 | P2 | T1210 Exploitation of Remote Services | [lateral-movement.md](./lateral-movement.md) |
| 리버스 셸 | P1 | T1059 Command and Scripting Interpreter | [reverse-shell.md](./reverse-shell.md) |
| 컨테이너 탈출 | P1 | T1611 Escape to Host | [container-escape.md](./container-escape.md) |
| RBAC 남용 | P2 | T1078 Valid Accounts | [rbac-abuse.md](./rbac-abuse.md) |
| 이미지 변조 | P2 | T1610 Deploy Container | [image-tampering.md](./image-tampering.md) |
| 데이터 유출 | P1 | T1041 Exfiltration Over C2 Channel | [data-exfiltration.md](./data-exfiltration.md) |

---

## 심각도 기준

| 등급 | 설명 | 자동 대응 | 승인 |
|---|---|---|---|
| P1 (Critical) | 즉각적인 서비스 영향 또는 데이터 침해 가능성 | 격리 자동 실행, 5분 타임아웃 후 | 필요 |
| P2 (High) | 공격 진행 중, 확산 가능성 있음 | 15분 타임아웃 후 에스컬레이션 | 필요 |
| P3 (Medium) | 의심 행위, 즉각 위협 없음 | 자동 실행 | 불필요 |
| P4 (Low) | 정책 위반, 낮은 위험 | 자동 실행 + 로그 | 불필요 |

---

## 관련 문서

- [02-detection.md](../02-detection.md) - GuardDuty, Falco, Tetragon 탐지 레이어
- [03-ai-agents.md](../03-ai-agents.md) - Solution Agent, Remediation Agent 설계
- [04-remediation.md](../04-remediation.md) - 자동 대응 액션 상세
