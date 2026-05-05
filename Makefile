CLUSTER_NAME ?= atdr-demo
REGION       ?= ap-northeast-2
AWS_ACCOUNT  ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null)
TF_DIR       := terraform/envs/demo
KCTL         := kubectl --context $(CLUSTER_NAME)
HLM          := helm --kube-context $(CLUSTER_NAME)
LAMBDA_MOD   := terraform/modules/lambda
LAYER_DIR    := build/layer/python

.PHONY: infra-up infra-down platform-up platform-down deploy-lambdas deploy-layer \
        all-up all-down status lint lint-fix test build build-layer build-lambdas \
        secrets scale-down scale-up scale-status backup-db clean slack-manifest

## ─── Infrastructure ──────────────────────────────────────────────

infra-up: build
	cd $(TF_DIR) && terraform init && terraform apply -auto-approve
	aws eks update-kubeconfig --name $(CLUSTER_NAME) --region $(REGION) --alias $(CLUSTER_NAME)
	@echo "Context created: $(CLUSTER_NAME)"
	@$(MAKE) -s slack-manifest

infra-down:
	$(MAKE) platform-down || true
	cd $(TF_DIR) && terraform destroy -auto-approve

## ─── Platform (Kubernetes components) ────────────────────────────

platform-up:
	@echo "=== Installing platform components (context: $(CLUSTER_NAME)) ==="
	helm repo add eks https://aws.github.io/eks-charts 2>/dev/null || true
	helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
	helm repo add cilium https://helm.cilium.io 2>/dev/null || true
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
	helm repo add external-secrets https://charts.external-secrets.io 2>/dev/null || true
	helm repo update eks falcosecurity cilium prometheus-community grafana external-secrets
	@echo "--- AWS Load Balancer Controller ---"
	$(HLM) upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
		-n kube-system \
		--set clusterName=$(CLUSTER_NAME) \
		--set serviceAccount.create=true \
		--set serviceAccount.name=aws-load-balancer-controller \
		--set region=$(REGION) \
		--set vpcId=$$(aws eks describe-cluster --name $(CLUSTER_NAME) --region $(REGION) --query 'cluster.resourcesVpcConfig.vpcId' --output text)
	@echo "--- Falco ---"
	$(HLM) upgrade --install falco falcosecurity/falco \
		-n falco --create-namespace \
		-f kubernetes/falco/values.yaml
	@echo "--- Tetragon ---"
	$(HLM) upgrade --install tetragon cilium/tetragon \
		-n tetragon --create-namespace
	$(KCTL) apply -f kubernetes/tetragon/tracing-policies.yaml
	@echo "--- kube-prometheus-stack ---"
	$(HLM) upgrade --install monitoring prometheus-community/kube-prometheus-stack \
		-n monitoring --create-namespace \
		-f kubernetes/monitoring/kube-prometheus-stack-values.yaml
	@echo "--- Loki ---"
	$(HLM) upgrade --install loki grafana/loki \
		-n monitoring \
		-f kubernetes/monitoring/loki-values.yaml
	@echo "--- Grafana Ingress ---"
	$(KCTL) apply -f kubernetes/monitoring/grafana-ingress.yaml
	@echo "--- External Secrets Operator ---"
	$(HLM) upgrade --install external-secrets external-secrets/external-secrets \
		-n external-secrets --create-namespace
	$(KCTL) apply -f kubernetes/external-secrets/external-secrets.yaml
	@echo "--- Admission Policies ---"
	$(KCTL) apply -f kubernetes/admission-policies/policies.yaml
	@echo "=== Platform deployment complete ==="

platform-down:
	$(HLM) uninstall external-secrets -n external-secrets || true
	$(HLM) uninstall loki -n monitoring || true
	$(HLM) uninstall monitoring -n monitoring || true
	$(HLM) uninstall tetragon -n tetragon || true
	$(HLM) uninstall falco -n falco || true
	$(HLM) uninstall aws-load-balancer-controller -n kube-system || true
	$(KCTL) delete -f kubernetes/admission-policies/policies.yaml --ignore-not-found
	$(KCTL) delete -f kubernetes/tetragon/tracing-policies.yaml --ignore-not-found
	$(KCTL) delete -f kubernetes/external-secrets/external-secrets.yaml --ignore-not-found
	$(KCTL) delete -f kubernetes/monitoring/grafana-ingress.yaml --ignore-not-found

## ─── Lambda Deployment ───────────────────────────────────────────

deploy-lambdas: build-lambdas
	@echo "Deploying Lambda functions..."
	@for agent in summary triage solution remediation; do \
		echo "  $$agent-agent"; \
		aws lambda update-function-code \
			--function-name atdr-$$agent-agent \
			--zip-file fileb://$(LAMBDA_MOD)/$$agent.zip \
			--region $(REGION) --no-cli-pager; \
	done
	@aws lambda update-function-code \
		--function-name atdr-ingestor \
		--zip-file fileb://$(LAMBDA_MOD)/ingestor.zip \
		--region $(REGION) --no-cli-pager
	@aws lambda update-function-code \
		--function-name atdr-degraded-notifier \
		--zip-file fileb://$(LAMBDA_MOD)/degraded_notifier.zip \
		--region $(REGION) --no-cli-pager
	@aws lambda update-function-code \
		--function-name atdr-slack-bot \
		--zip-file fileb://terraform/modules/slack/slack_bot.zip \
		--region $(REGION) --no-cli-pager
	@echo "Done."

deploy-layer: build-layer
	@aws lambda publish-layer-version \
		--layer-name atdr-dependencies \
		--zip-file fileb://$(LAMBDA_MOD)/layer.zip \
		--compatible-runtimes python3.12 \
		--region $(REGION) --no-cli-pager
	@echo "Layer published."

## ─── Full Lifecycle ──────────────────────────────────────────────

all-up: infra-up platform-up
	@echo "Full deployment complete."

all-down:
	$(MAKE) platform-down || true
	$(MAKE) infra-down

## ─── Secrets ─────────────────────────────────────────────────────

secrets:
	@echo "=== ATDR Secrets Setup ==="
	@read -p "Slack Bot Token (xoxb-...): " token && \
		read -p "Slack Webhook URL: " webhook && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/slack/bot-token \
			--secret-string "{\"token\":\"$$token\",\"webhook_url\":\"$$webhook\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/slack/bot-token: done"
	@read -p "Slack Signing Secret: " secret && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/slack/signing-secret \
			--secret-string "{\"secret\":\"$$secret\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/slack/signing-secret: done"
	@read -p "MCP Auth Token: " mcp_token && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/mcp/auth-token \
			--secret-string "{\"token\":\"$$mcp_token\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/mcp/auth-token: done"
	@echo "=== All secrets configured ==="

## ─── Scaling ─────────────────────────────────────────────────────

scale-down:
	@for ng in $$(aws eks list-nodegroups --cluster-name $(CLUSTER_NAME) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null); do \
		echo "  $$ng -> 0"; \
		aws eks update-nodegroup-config \
			--cluster-name $(CLUSTER_NAME) \
			--nodegroup-name $$ng \
			--region $(REGION) \
			--scaling-config minSize=0,maxSize=4,desiredSize=0; \
	done
	@echo "Nodes will terminate in ~5 minutes."

scale-up:
	@for ng in $$(aws eks list-nodegroups --cluster-name $(CLUSTER_NAME) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null); do \
		echo "  $$ng -> 2"; \
		aws eks update-nodegroup-config \
			--cluster-name $(CLUSTER_NAME) \
			--nodegroup-name $$ng \
			--region $(REGION) \
			--scaling-config minSize=1,maxSize=4,desiredSize=2; \
	done
	@echo "Nodes will be ready in ~5 minutes."

scale-status:
	@aws eks list-nodegroups --cluster-name $(CLUSTER_NAME) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null | \
		tr '\t' '\n' | while read ng; do \
			echo "$$ng:"; \
			aws eks describe-nodegroup \
				--cluster-name $(CLUSTER_NAME) \
				--nodegroup-name $$ng \
				--region $(REGION) \
				--query 'nodegroup.{desired:scalingConfig.desiredSize,min:scalingConfig.minSize,max:scalingConfig.maxSize,status:status}' \
				--output table 2>/dev/null; \
		done

## ─── Build ───────────────────────────────────────────────────────

build: build-layer build-lambdas
	@echo "Build complete."

build-layer:
	@rm -rf build/layer
	@mkdir -p $(LAYER_DIR)
	@pip install -r requirements.txt -t $(LAYER_DIR) --quiet
	@cd build/layer && zip -r ../../$(LAMBDA_MOD)/layer.zip python -q
	@echo "Layer: $(LAMBDA_MOD)/layer.zip"

build-lambdas:
	@for agent in summary triage solution remediation; do \
		cd app/agents/$$agent && zip -r ../../../$(LAMBDA_MOD)/$$agent.zip *.py -q && cd ../../..; \
	done
	@cd app/ingestor && zip -r ../../$(LAMBDA_MOD)/ingestor.zip *.py -q && cd ../..
	@cd app/degraded_notifier && zip -r ../../$(LAMBDA_MOD)/degraded_notifier.zip *.py -q && cd ../..
	@cd app/slack_bot && zip -r ../../terraform/modules/slack/slack_bot.zip *.py -q && cd ../..
	@cd app/shared && zip -r ../../$(LAMBDA_MOD)/shared.zip *.py -q && cd ../..
	@echo "Lambdas packaged."

## ─── Quality ─────────────────────────────────────────────────────

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

## ─── Status ──────────────────────────────────────────────────────

status:
	@echo "=== Nodes ==="
	@$(KCTL) get nodes -o wide 2>/dev/null || echo "kubeconfig not set"
	@echo "\n=== Pods (non-Running) ==="
	@$(KCTL) get pods -A --field-selector=status.phase!=Running 2>/dev/null || true
	@echo "\n=== Grafana URL ==="
	@$(KCTL) get ingress grafana -n monitoring -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null && echo "" || echo "  not available"

## ─── Utilities ───────────────────────────────────────────────────

backup-db:
	@aws dynamodb create-backup \
		--table-name atdr-incidents \
		--backup-name "atdr-incidents-$$(date +%Y%m%d-%H%M%S)" \
		--region $(REGION) 2>/dev/null && echo "incidents: done" || echo "incidents: skipped"
	@aws dynamodb create-backup \
		--table-name atdr-approval-audit \
		--backup-name "atdr-approval-audit-$$(date +%Y%m%d-%H%M%S)" \
		--region $(REGION) 2>/dev/null && echo "approval-audit: done" || echo "approval-audit: skipped"

clean:
	rm -rf build/
	rm -rf $(LAMBDA_MOD)/*.zip
	rm -rf terraform/modules/slack/*.zip
	rm -rf terraform/envs/demo/.terraform
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

## ─── Slack ───────────────────────────────────────────────────────

slack-manifest:
	@SLACK_URL=$$(cd $(TF_DIR) && terraform output -raw slack_api_endpoint 2>/dev/null) && \
		if [ -z "$$SLACK_URL" ]; then echo "ERROR: slack_api_endpoint not found. Run make infra-up first."; exit 1; fi && \
		sed "s|\$${SLACK_API_URL}|$$SLACK_URL|g" slack/manifest.json.tpl > slack/manifest.json && \
		echo "" && \
		echo "=== Slack App Manifest Generated ===" && \
		echo "File: slack/manifest.json" && \
		echo "API URL: $$SLACK_URL" && \
		echo "" && \
		echo "Setup:" && \
		echo "  1. Go to https://api.slack.com/apps" && \
		echo "  2. Create New App → From an app manifest" && \
		echo "  3. Paste contents of slack/manifest.json" && \
		echo "  4. Install to Workspace" && \
		echo "  5. Run: make secrets" && \
		echo "==="
