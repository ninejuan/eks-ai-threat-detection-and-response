resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = var.cluster_role_arn
  version  = "1.35"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.endpoint_public_access_cidrs
    security_group_ids      = [aws_security_group.cluster.id]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  tags = {
    Name = var.cluster_name
  }
}

resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-sg-cluster"
  description = "EKS cluster security group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.cluster_name}-sg-cluster"
  }
}

resource "aws_security_group_rule" "cluster_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster.id
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-ng-general"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids

  ami_type       = "AL2023_x86_64_STANDARD"
  instance_types = ["t3.large"]

  scaling_config {
    desired_size = 1
    min_size     = 0
    max_size     = 3
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    role = "general"
  }

  tags = {
    Name = "${var.cluster_name}-ng-general"
  }
}

resource "aws_eks_node_group" "compute" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-ng-compute"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids

  ami_type       = "AL2023_x86_64_STANDARD"
  instance_types = ["c5.large"]

  scaling_config {
    desired_size = 2
    min_size     = 0
    max_size     = 3
  }

  labels = {
    role = "compute"
  }

  tags = {
    Name = "${var.cluster_name}-ng-compute"
  }
}

resource "aws_eks_addon" "pod_identity_agent" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "coredns"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "kube-proxy"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "aws-ebs-csi-driver"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"

  pod_identity_association {
    service_account = "ebs-csi-controller-sa"
    role_arn        = var.ebs_csi_role_arn
  }

  depends_on = [aws_eks_addon.pod_identity_agent]
}

resource "aws_eks_access_entry" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = var.admin_role_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = var.admin_role_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}

resource "aws_eks_pod_identity_association" "falco" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "falco"
  service_account = "falco-falcosidekick"
  role_arn        = var.falco_pod_role_arn
}

resource "aws_eks_pod_identity_association" "falco_k8saudit" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "falco"
  service_account = "falco-k8saudit"
  role_arn        = var.falco_k8saudit_role_arn
}

resource "aws_eks_pod_identity_association" "external_secrets" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = var.external_secrets_role_arn
}

resource "aws_eks_pod_identity_association" "mcp_server" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "atdr"
  service_account = "eks-mcp-server"
  role_arn        = var.mcp_server_role_arn
}

resource "aws_eks_pod_identity_association" "aws_lb_controller" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = var.aws_lb_controller_role_arn
}

resource "aws_eks_pod_identity_association" "cilium_operator" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "kube-system"
  service_account = "cilium-operator"
  role_arn        = var.cilium_operator_role_arn
}

resource "aws_eks_pod_identity_association" "tetragon_forwarder" {
  cluster_name    = aws_eks_cluster.main.name
  namespace       = "tetragon"
  service_account = "tetragon-sns-forwarder"
  role_arn        = var.tetragon_forwarder_role_arn
}
