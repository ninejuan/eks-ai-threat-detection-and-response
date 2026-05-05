TF_DIR := terraform/envs/demo
CLUSTER := atdr-demo
REGION := ap-northeast-2
KUBE_CONTEXT := arn:aws:eks:$(REGION):$(shell aws sts get-caller-identity --query Account --output text 2>/dev/null):cluster/$(CLUSTER)
KUBECTL := kubectl --context=$(KUBE_CONTEXT)
HELM := helm --kube-context=$(KUBE_CONTEXT)
LAMBDA_MODULE := terraform/modules/lambda
LAYER_DIR := build/layer/python

.PHONY: init plan apply destroy fmt validate

init:
	cd $(TF_DIR) && terraform init

plan:
	cd $(TF_DIR) && terraform plan

apply:
	cd $(TF_DIR) && terraform apply

destroy:
	cd $(TF_DIR) && terraform destroy

fmt:
	terraform fmt -recursive terraform/

validate:
	cd $(TF_DIR) && terraform validate

.PHONY: lint test lint-fix

lint:
	ruff check app/
	ruff format --check app/
	yamllint -c .yamllint.yml kubernetes/
	terraform fmt -check -recursive terraform/

lint-fix:
	ruff check --fix app/
	ruff format app/
	terraform fmt -recursive terraform/

test:
	PYTHONPATH=. pytest tests/ -v --tb=short

.PHONY: build build-layer build-lambdas

build-layer:
	@echo "Building Lambda layer..."
	@rm -rf build/layer
	@mkdir -p $(LAYER_DIR)
	@pip install -r requirements.txt -t $(LAYER_DIR) --quiet
	@cd build/layer && zip -r ../../$(LAMBDA_MODULE)/layer.zip python -q
	@echo "Layer built: $(LAMBDA_MODULE)/layer.zip"

build-lambdas:
	@echo "Building Lambda deployment packages..."
	@for agent in summary triage solution remediation; do \
		echo "  Packaging $$agent agent..."; \
		cd app/agents/$$agent && zip -r ../../../$(LAMBDA_MODULE)/$$agent.zip *.py -q && cd ../../..; \
	done
	@cd app/ingestor && zip -r ../../$(LAMBDA_MODULE)/ingestor.zip *.py -q && cd ../..
	@cd app/degraded_notifier && zip -r ../../$(LAMBDA_MODULE)/degraded_notifier.zip *.py -q && cd ../..
	@cd app/slack_bot && zip -r ../../terraform/modules/slack/slack_bot.zip *.py -q && cd ../..
	@cd app/shared && zip -r ../../$(LAMBDA_MODULE)/shared.zip *.py -q && cd ../..
	@echo "Lambda packages built."

build: build-layer build-lambdas
	@echo "Build complete."

.PHONY: deploy deploy-infra deploy-k8s deploy-lambdas

deploy-infra: build
	cd $(TF_DIR) && terraform apply -auto-approve

deploy-lambdas: build-lambdas
	@echo "Deploying Lambda functions..."
	@for agent in summary triage solution remediation; do \
		echo "  Deploying $$agent agent..."; \
		aws lambda update-function-code \
			--function-name atdr-$$agent-agent \
			--zip-file fileb://$(LAMBDA_MODULE)/$$agent.zip \
			--region $(REGION) --no-cli-pager; \
	done
	@aws lambda update-function-code \
		--function-name atdr-ingestor \
		--zip-file fileb://$(LAMBDA_MODULE)/ingestor.zip \
		--region $(REGION) --no-cli-pager
	@aws lambda update-function-code \
		--function-name atdr-degraded-notifier \
		--zip-file fileb://$(LAMBDA_MODULE)/degraded_notifier.zip \
		--region $(REGION) --no-cli-pager
	@aws lambda update-function-code \
		--function-name atdr-slack-bot \
		--zip-file fileb://terraform/modules/slack/slack_bot.zip \
		--region $(REGION) --no-cli-pager
	@echo "Lambda deployment complete."

deploy-layer: build-layer
	@echo "Deploying Lambda layer..."
	@aws lambda publish-layer-version \
		--layer-name atdr-dependencies \
		--zip-file fileb://$(LAMBDA_MODULE)/layer.zip \
		--compatible-runtimes python3.12 \
		--region $(REGION) --no-cli-pager
	@echo "Layer deployed."

deploy-k8s: kubeconfig
	@echo "=== Deploying Kubernetes components (context: $(KUBE_CONTEXT)) ==="
	@echo "Installing AWS Load Balancer Controller..."
	helm repo add eks https://aws.github.io/eks-charts 2>/dev/null || true
	$(HELM) upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
		-n kube-system \
		--set clusterName=$(CLUSTER) \
		--set serviceAccount.create=true \
		--set serviceAccount.name=aws-load-balancer-controller \
		--set region=$(REGION) \
		--set vpcId=$$(aws eks describe-cluster --name $(CLUSTER) --region $(REGION) --query 'cluster.resourcesVpcConfig.vpcId' --output text)
	@echo "Installing Falco..."
	helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
	$(HELM) upgrade --install falco falcosecurity/falco \
		-n falco --create-namespace \
		-f kubernetes/falco/values.yaml
	@echo "Installing Tetragon..."
	helm repo add cilium https://helm.cilium.io 2>/dev/null || true
	$(HELM) upgrade --install tetragon cilium/tetragon \
		-n tetragon --create-namespace
	$(KUBECTL) apply -f kubernetes/tetragon/tracing-policies.yaml
	@echo "Installing kube-prometheus-stack..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	$(HELM) upgrade --install monitoring prometheus-community/kube-prometheus-stack \
		-n monitoring --create-namespace \
		-f kubernetes/monitoring/kube-prometheus-stack-values.yaml
	@echo "Installing Loki..."
	helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
	$(HELM) upgrade --install loki grafana/loki \
		-n monitoring \
		-f kubernetes/monitoring/loki-values.yaml
	@echo "Applying Grafana Ingress..."
	$(KUBECTL) apply -f kubernetes/monitoring/grafana-ingress.yaml
	@echo "Installing External Secrets Operator..."
	helm repo add external-secrets https://charts.external-secrets.io 2>/dev/null || true
	$(HELM) upgrade --install external-secrets external-secrets/external-secrets \
		-n external-secrets --create-namespace
	$(KUBECTL) apply -f kubernetes/external-secrets/external-secrets.yaml
	@echo "Applying admission policies..."
	$(KUBECTL) apply -f kubernetes/admission-policies/policies.yaml
	@echo "=== Kubernetes deployment complete ==="

deploy: deploy-infra deploy-k8s
	@echo "Full deployment complete."

.PHONY: kubeconfig

kubeconfig:
	@aws eks update-kubeconfig \
		--name $(CLUSTER) \
		--region $(REGION) \
		--alias $(CLUSTER)
	@echo "kubeconfig updated. Context: $(KUBE_CONTEXT)"

.PHONY: secrets secrets-slack secrets-mcp

secrets:
	@echo "=== ATDR Secrets Setup ==="
	@echo ""
	@read -p "Slack Bot Token (xoxb-...): " token && \
		read -p "Slack Webhook URL: " webhook && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/slack/bot-token \
			--secret-string "{\"token\":\"$$token\",\"webhook_url\":\"$$webhook\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/slack/bot-token: set"
	@echo ""
	@read -p "Slack Signing Secret: " secret && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/slack/signing-secret \
			--secret-string "{\"secret\":\"$$secret\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/slack/signing-secret: set"
	@echo ""
	@read -p "MCP Auth Token: " mcp_token && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/mcp/auth-token \
			--secret-string "{\"token\":\"$$mcp_token\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/mcp/auth-token: set"
	@echo ""
	@echo "=== All secrets configured ==="

secrets-slack:
	@read -p "Slack Bot Token (xoxb-...): " token && \
		read -p "Slack Webhook URL: " webhook && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/slack/bot-token \
			--secret-string "{\"token\":\"$$token\",\"webhook_url\":\"$$webhook\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "Done."

secrets-mcp:
	@read -p "MCP Auth Token: " mcp_token && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/mcp/auth-token \
			--secret-string "{\"token\":\"$$mcp_token\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "Done."

.PHONY: scale-down scale-up scale-status

scale-down:
	@echo "Scaling all node groups to 0..."
	@for ng in $$(aws eks list-nodegroups --cluster-name $(CLUSTER) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null); do \
		echo "  $$ng -> 0"; \
		aws eks update-nodegroup-config \
			--cluster-name $(CLUSTER) \
			--nodegroup-name $$ng \
			--region $(REGION) \
			--scaling-config minSize=0,maxSize=4,desiredSize=0; \
	done
	@echo "Done. Nodes will terminate in ~5 minutes."

scale-up:
	@echo "Scaling all node groups to desired size..."
	@for ng in $$(aws eks list-nodegroups --cluster-name $(CLUSTER) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null); do \
		echo "  $$ng -> 2"; \
		aws eks update-nodegroup-config \
			--cluster-name $(CLUSTER) \
			--nodegroup-name $$ng \
			--region $(REGION) \
			--scaling-config minSize=1,maxSize=4,desiredSize=2; \
	done
	@echo "Done. Nodes will be ready in ~5 minutes."

scale-status:
	@aws eks list-nodegroups --cluster-name $(CLUSTER) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null | \
		tr '\t' '\n' | while read ng; do \
			echo "$$ng:"; \
			aws eks describe-nodegroup \
				--cluster-name $(CLUSTER) \
				--nodegroup-name $$ng \
				--region $(REGION) \
				--query 'nodegroup.{desired:scalingConfig.desiredSize,min:scalingConfig.minSize,max:scalingConfig.maxSize,status:status}' \
				--output table 2>/dev/null; \
		done

.PHONY: backup-db

backup-db:
	@echo "Creating DynamoDB backups..."
	@aws dynamodb create-backup \
		--table-name atdr-incidents \
		--backup-name "atdr-incidents-$$(date +%Y%m%d-%H%M%S)" \
		--region $(REGION) 2>/dev/null && echo "  incidents: done" || echo "  incidents: skipped"
	@aws dynamodb create-backup \
		--table-name atdr-approval-audit \
		--backup-name "atdr-approval-audit-$$(date +%Y%m%d-%H%M%S)" \
		--region $(REGION) 2>/dev/null && echo "  approval-audit: done" || echo "  approval-audit: skipped"

.PHONY: status

status: kubeconfig
	@echo "=== ATDR Status ==="
	@echo ""
	@echo "--- EKS Cluster ---"
	@aws eks describe-cluster --name $(CLUSTER) --region $(REGION) \
		--query 'cluster.{status:status,version:version,endpoint:endpoint}' \
		--output table 2>/dev/null || echo "  Cluster not found"
	@echo ""
	@echo "--- Node Groups ---"
	@$(MAKE) -s scale-status
	@echo ""
	@echo "--- Pods (all namespaces) ---"
	@$(KUBECTL) get pods -A --no-headers 2>/dev/null | awk '{print $$1}' | sort | uniq -c | sort -rn || echo "  Cannot connect"
	@echo ""
	@echo "--- Grafana URL ---"
	@$(KUBECTL) get ingress grafana -n monitoring -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null && echo "" || echo "  Not available"

.PHONY: clean

clean:
	rm -rf build/
	rm -rf terraform/modules/lambda/*.zip
	rm -rf terraform/modules/slack/*.zip
	rm -rf terraform/envs/demo/.terraform
	rm -rf terraform/envs/demo/.terraform.lock.hcl
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
