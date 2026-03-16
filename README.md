# eks-ai-threat-detection-and-response
[인공지능과미래사회1학기프젝-대괄호부분삭제필요] AI-driven threat detection, correlation, and remediation for runtime and network security events in AWS EKS environments.

## 1. Project Summary

KubeSentinel-AI is a security research and engineering project that detects, analyzes, and responds to threats in Kubernetes workloads running on AWS EKS.

The system collects security and operational telemetry from cloud, Kubernetes, runtime, and network layers, then uses AI/ML-based analysis to:

- detect abnormal behavior
- classify threat types
- correlate events across multiple signals
- infer likely attack paths or root causes
- recommend or execute remediation actions

This project is designed as a graduate capstone/final project and focuses on the intersection of:

- **Artificial Intelligence**: anomaly detection, classification, correlation, explanation, and response recommendation
- **Kubernetes**: workload orchestration, policy enforcement, remediation execution, and EKS-native operations
- **Network/Security**: east-west traffic analysis, egress anomaly detection, runtime threat detection, and containment

---

## 2. Problem Statement

Modern Kubernetes environments generate many fragmented security signals:

- cloud-level events
- Kubernetes audit events
- container/runtime activity
- network flows
- DNS activity
- application metrics and traces

Security operators often need to manually inspect multiple dashboards, logs, and alerts to understand:

- whether a threat is real
- what kind of threat it is
- which workload is affected
- how the threat is spreading
- what remediation action should be taken

KubeSentinel-AI aims to reduce that burden by building an AI-driven analysis and response layer on top of AWS and Kubernetes telemetry.

---

## 3. Core Objective

The core objective of this project is:

> Build an AI-powered security system for AWS EKS that can detect, correlate, explain, and respond to runtime and network threats in Kubernetes environments.

---

## 4. Scope

### In Scope

- AWS EKS-based deployment
- Security telemetry collection from AWS and Kubernetes
- Runtime and network threat analysis
- AI/ML-based anomaly detection and threat classification
- Event correlation across multiple data sources
- Remediation recommendation
- Optional semi-automatic or automatic remediation
- Infrastructure as Code using Terraform
- Kubernetes manifests managed with Kustomize
- Reproducible workflows via Makefile

### Out of Scope

- Full-scale commercial SIEM replacement
- Production-grade SOC integration
- Advanced malware development or offensive exploitation
- Large-scale LLM fine-tuning
- Multi-cloud support in the first version

---

## 5. Example Threat Scenarios

The initial version of the project focuses on realistic but controlled scenarios such as:

- abnormal outbound traffic from a pod
- suspicious east-west communication between namespaces
- privilege misuse or suspicious Kubernetes API activity
- unusual runtime behavior inside a container
- possible lateral movement patterns
- crypto-mining-like CPU/network behavior
- DNS anomalies or external beaconing-like behavior

These scenarios are used to generate labeled or semi-labeled datasets for training and evaluation.

---

## 6. High-Level Architecture

### Data Sources
- AWS CloudTrail
- VPC Flow Logs
- DNS logs
- EKS audit logs
- runtime/container events
- application metrics and traces

### Analysis Layer
- anomaly detection model
- threat classification model
- multi-source correlation engine
- root-cause / attack-path inference
- remediation recommendation engine
- optional LLM-based explanation layer

### Control / Response Layer
- NetworkPolicy generation or update
- pod isolation / quarantine
- namespace-level containment
- restart / rollback / scale actions
- approval-based remediation workflow

### User Interface / Outputs
- incident summary
- threat type classification
- affected resources
- recommended remediation actions
- before/after response status

---

## 7. AI Role in This Project

AI is the primary intelligence layer of this system.

It is not only used for text summarization.  
Its main responsibilities include:

1. **Anomaly Detection**
   - determine whether current behavior is normal or suspicious

2. **Threat Classification**
   - classify the likely threat type from observed telemetry

3. **Event Correlation**
   - connect signals from AWS, Kubernetes, runtime, and network sources

4. **Root Cause / Attack Path Inference**
   - estimate where the incident started and how it propagated

5. **Response Recommendation**
   - rank the most appropriate remediation actions

6. **Human-Readable Explanation**
   - explain why the system reached a decision

---

## 8. Why Kubernetes and AWS Matter

This project is not a generic AI security tool.

It is specifically designed for **AWS-native Kubernetes security operations**, with AWS EKS as the primary platform.

### Why Kubernetes
- workloads are dynamic and distributed
- incidents may propagate across pods, services, and namespaces
- remediation can be executed as Kubernetes-native actions

### Why AWS
- EKS is the execution environment
- AWS services provide rich telemetry and event sources
- AWS-native security data can be combined with Kubernetes-native signals

---

## 9. Repository Structure

```text
.
├── apps/
│   ├── demo-app/               # Sample workloads deployed on EKS
│   ├── attack-simulator/       # Controlled threat / anomaly scenario generator
│   ├── ai-detector/            # Anomaly detection and threat classification service
│   ├── correlator/             # Multi-source event correlation engine
│   ├── response-advisor/       # Remediation recommendation service
│   └── dashboard/              # UI or API for results and review
│
├── terraform/
│   ├── eks/                    # EKS cluster and node groups
│   ├── network/                # VPC, subnets, security groups
│   ├── iam/                    # IAM roles and policies
│   └── observability/          # Supporting AWS resources
│
├── k8s/
│   ├── base/
│   │   ├── demo-app/
│   │   ├── ai-detector/
│   │   ├── correlator/
│   │   ├── response-advisor/
│   │   ├── dashboard/
│   │   └── policies/
│   └── overlays/
│       ├── dev/
│       ├── demo/
│       ├── attack-scenarios/
│       └── quarantine/
│
├── data/
│   ├── raw/                    # Collected logs, flows, traces, findings
│   ├── processed/              # Feature-engineered datasets
│   └── labeled/                # Training / evaluation labels
│
├── models/
│   ├── anomaly/
│   ├── classification/
│   └── response-ranking/
│
├── notebooks/                  # Exploration and experiment notebooks
├── scripts/                    # Utilities, ingestion jobs, data prep
├── reports/                    # Figures, screenshots, evaluation assets
├── Makefile
└── README.md
```

---

## 10. Main Workflow

Deploy workloads and observability/security stack on AWS EKS

Generate normal and suspicious runtime/network behavior

Collect telemetry from cloud, Kubernetes, and runtime layers

Convert telemetry into features and structured events

Run AI models for anomaly detection and threat classification

Correlate findings into a higher-level incident view

Recommend remediation actions

Optionally apply remediation to the cluster

Measure detection quality, response quality, and recovery results

---

## 11. Research / Evaluation Questions

This project aims to evaluate questions such as:

Can AI detect security-relevant anomalies in EKS more accurately than simple threshold-based rules?

Can multi-source correlation improve threat understanding over single-source alerts?

Can AI produce useful remediation recommendations for Kubernetes-native response actions?

Does the system reduce time-to-detect and time-to-respond in controlled experiments?

---

## 12. Evaluation Metrics

Possible evaluation metrics include:

anomaly detection precision / recall / F1

threat classification accuracy

Top-k root cause accuracy

remediation recommendation accuracy or relevance

false positive rate

mean time to detect

mean time to recommend response

service recovery time after remediation

workload impact before and after response

---

## 13. Expected Outputs

This repository is expected to produce:

application source code

AI analysis services

Terraform infrastructure code

Kubernetes Kustomize manifests

reproducible Makefile workflows

experiment data and evaluation results

screenshots and report assets

final project report materials

---

## 14. Technology Stack
Cloud / Infra

AWS

Amazon EKS

Terraform

Kubernetes

Kustomize

NetworkPolicy

RBAC / namespace isolation

Data / Observability

CloudTrail

VPC Flow Logs

DNS logs

EKS audit logs

Prometheus / Grafana

optional tracing pipeline

AI / Backend

Python

scikit-learn / XGBoost / LightGBM

optional LLM integration for explanation

FastAPI or similar API layer

Automation

Makefile

CI/CD pipeline (optional)

GitHub Actions (optional)

---

## 15. Non-Goals

To keep the project achievable within the capstone timeline, the following are not primary goals:

building a commercial security product

supporting every Kubernetes distribution

replacing enterprise SOC tooling

implementing advanced offensive techniques

training large foundation models from scratch

---

## 16. Project Status

Current status: Planning / Design

Planned milestones:

infrastructure setup

telemetry ingestion

scenario generation

feature engineering

model development

remediation workflow

evaluation and final report

---

## 17. One-Sentence Definition

KubeSentinel-AI is an AI-driven security system for AWS EKS that detects, correlates, explains, and responds to runtime and network threats in Kubernetes environments.
