import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    project: str = field(default_factory=lambda: os.environ.get("PROJECT", "atdr"))
    region: str = field(default_factory=lambda: os.environ.get("AWS_REGION", "ap-northeast-2"))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))
    agent_type: str = field(default_factory=lambda: os.environ.get("AGENT_TYPE", ""))
    bedrock_model_id: str = field(default_factory=lambda: os.environ.get("BEDROCK_MODEL_ID", ""))
    opensearch_endpoint: str = field(default_factory=lambda: os.environ.get("OPENSEARCH_ENDPOINT", ""))
    knowledge_base_id: str = field(default_factory=lambda: os.environ.get("KNOWLEDGE_BASE_ID", ""))
    state_machine_arn: str = field(default_factory=lambda: os.environ.get("STATE_MACHINE_ARN", ""))
    dynamodb_table_name: str = field(default_factory=lambda: os.environ.get("DYNAMODB_TABLE_NAME", ""))
    eks_cluster_name: str = field(default_factory=lambda: os.environ.get("EKS_CLUSTER_NAME", "atdr-demo"))
