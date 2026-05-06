CLUSTER_NAME ?= atdr-demo
REGION       ?= ap-northeast-2
AWS_ACCOUNT  ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null)
MCP_IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
TF_DIR       := terraform/envs/demo
KCTL         := kubectl --context $(CLUSTER_NAME)
HLM          := helm --kube-context $(CLUSTER_NAME)
LAMBDA_MOD   := terraform/modules/lambda
LAYER_DIR    := build/layer/python

.PHONY: infra-up infra-down platform-up platform-down deploy-lambdas deploy-layer \
        all-up all-down status lint lint-fix test build build-layer build-lambdas build-mcp \
        secrets scale-down scale-up scale-status backup-db clean slack-manifest

## ─── Infrastructure ──────────────────────────────────────────────

infra-up: build
	cd $(TF_DIR) && terraform init && terraform apply -auto-approve
	aws eks update-kubeconfig --name $(CLUSTER_NAME) --region $(REGION) --alias $(CLUSTER_NAME)
	@echo "Context created: $(CLUSTER_NAME)"
	@$(MAKE) -s slack-manifest

infra-down:
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
	@$(KCTL) delete mutatingwebhookconfigurations aws-load-balancer-webhook --ignore-not-found 2>/dev/null
	@$(KCTL) delete validatingwebhookconfigurations aws-load-balancer-webhook --ignore-not-found 2>/dev/null
	$(HLM) upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
		-n kube-system \
		--set clusterName=$(CLUSTER_NAME) \
		--set serviceAccount.create=true \
		--set serviceAccount.name=aws-load-balancer-controller \
		--set region=$(REGION) \
		--set vpcId=$$(aws eks describe-cluster --name $(CLUSTER_NAME) --region $(REGION) --query 'cluster.resourcesVpcConfig.vpcId' --output text)
	@echo "Waiting for LB Controller to be ready..."
	@$(KCTL) rollout status deployment/aws-load-balancer-controller -n kube-system --timeout=120s
	@echo "--- StorageClass (gp3) ---"
	$(KCTL) apply -f kubernetes/storage/gp3-storageclass.yaml
	@echo "--- Cilium + Hubble ---"
	$(HLM) upgrade --install cilium cilium/cilium \
		-n kube-system \
		--set cni.chainingMode=aws-cni \
		--set cni.exclusive=false \
		--set hubble.enabled=true \
		--set hubble.relay.enabled=true \
		--set hubble.ui.enabled=true \
		--set operator.replicas=1
	@$(KCTL) rollout status daemonset/cilium -n kube-system --timeout=180s
	@$(KCTL) rollout status deployment/hubble-relay -n kube-system --timeout=180s
	@echo "--- Falco ---"
	$(HLM) upgrade --install falco falcosecurity/falco \
		-n falco --create-namespace \
		-f kubernetes/falco/values.yaml \
		--set falcosidekick.config.aws.sns.topicarn=$$(cd $(TF_DIR) && terraform output -raw sns_topic_arn 2>/dev/null || echo "")
	@echo "--- Falco k8saudit (EKS CloudWatch) ---"
	$(HLM) upgrade --install falco-k8saudit falcosecurity/falco \
		-n falco \
		-f kubernetes/falco/values-k8saudit.yaml \
		--set "falco.plugins[0].open_params=$(CLUSTER_NAME)" \
		--set falcosidekick.config.aws.sns.topicarn=$$(cd $(TF_DIR) && terraform output -raw sns_topic_arn 2>/dev/null || echo "")
	@echo "--- Tetragon ---"
	$(HLM) upgrade --install tetragon cilium/tetragon \
		-n tetragon --create-namespace
	@echo "Waiting for Tetragon CRDs..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		$(KCTL) get crd tracingpolicies.cilium.io >/dev/null 2>&1 && break || sleep 5; \
	done
	@$(KCTL) wait --for=condition=Established crd/tracingpolicies.cilium.io --timeout=60s
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
	@echo "Waiting for ESO CRDs and webhook..."
	@$(KCTL) wait --for=condition=Established crd/clustersecretstores.external-secrets.io --timeout=60s
	@$(KCTL) wait --for=condition=Established crd/externalsecrets.external-secrets.io --timeout=60s
	@$(KCTL) rollout status deployment/external-secrets-webhook -n external-secrets --timeout=120s
	$(KCTL) create namespace atdr --dry-run=client -o yaml | $(KCTL) apply -f -
	@aws secretsmanager get-secret-value --secret-id atdr/mcp/auth-token --region $(REGION) --query SecretString --output text >/dev/null || \
		(echo "ERROR: atdr/mcp/auth-token is empty. Run make secrets before make platform-up."; exit 1)
	@python3 -c 'from pathlib import Path; import sys; print(Path("kubernetes/external-secrets/external-secrets.yaml").read_text().replace("$${AWS_REGION}", sys.argv[1]))' "$(REGION)" | $(KCTL) apply -f -
	@echo "Waiting for MCP auth token secret..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		$(KCTL) get secret mcp-auth-token -n atdr >/dev/null 2>&1 && exit 0; \
		sleep 5; \
	done; \
	echo "ERROR: mcp-auth-token was not synced by External Secrets"; exit 1
	@echo "--- EKS MCP Server ---"
	@$(MAKE) -s build-mcp
	@MCP_IMAGE=$$(cd $(TF_DIR) && terraform output -raw mcp_server_repository_url):$(MCP_IMAGE_TAG) && \
		FORENSICS_BUCKET=$$(cd $(TF_DIR) && terraform output -raw forensics_bucket_id) && \
		MCP_NLB_SG=$$(cd $(TF_DIR) && terraform output -raw mcp_nlb_security_group_id) && \
		VPC_CIDR=$$(cd $(TF_DIR) && terraform output -raw vpc_cidr) && \
		python3 -c 'from pathlib import Path; import sys; text=Path("kubernetes/mcp/eks-mcp-server.yaml").read_text(); print(text.replace("$${MCP_IMAGE}", sys.argv[1]).replace("$${FORENSICS_BUCKET}", sys.argv[2]).replace("$${MCP_NLB_SECURITY_GROUP_ID}", sys.argv[3]).replace("$${VPC_CIDR}", sys.argv[4]))' "$$MCP_IMAGE" "$$FORENSICS_BUCKET" "$$MCP_NLB_SG" "$$VPC_CIDR" | $(KCTL) apply -f -
	@$(KCTL) rollout status deployment/eks-mcp-server -n atdr --timeout=180s
	@echo "Waiting for EKS MCP internal load balancer..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
		MCP_HOST=$$($(KCTL) get svc eks-mcp-server -n atdr -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null); \
		if [ -n "$$MCP_HOST" ]; then \
			aws secretsmanager put-secret-value --secret-id atdr/mcp/server-url --secret-string "{\"url\":\"http://$$MCP_HOST/mcp\"}" --region $(REGION) --no-cli-pager >/dev/null; \
			echo "  atdr/mcp/server-url: http://$$MCP_HOST/mcp"; \
			exit 0; \
		fi; \
		sleep 10; \
	done; \
	echo "ERROR: EKS MCP load balancer hostname was not assigned"; exit 1
	@echo "--- Admission Policies ---"
	$(KCTL) apply -f kubernetes/admission-policies/policies.yaml
	@echo "=== Platform deployment complete ==="

platform-down:
	@echo "=== Removing platform components ==="
	@echo "--- Removing CRD resources (while controllers still running) ---"
	@python3 -c 'from pathlib import Path; text=Path("kubernetes/mcp/eks-mcp-server.yaml").read_text(); print(text.replace("$${MCP_IMAGE}", "unused").replace("$${FORENSICS_BUCKET}", "unused").replace("$${MCP_NLB_SECURITY_GROUP_ID}", "unused").replace("$${VPC_CIDR}", "10.0.0.0/16"))' | $(KCTL) delete -f - --ignore-not-found --timeout=30s 2>/dev/null || true
	@python3 -c 'from pathlib import Path; import sys; print(Path("kubernetes/external-secrets/external-secrets.yaml").read_text().replace("$${AWS_REGION}", sys.argv[1]))' "$(REGION)" | $(KCTL) delete -f - --ignore-not-found --timeout=30s 2>/dev/null || true
	@$(KCTL) delete -f kubernetes/tetragon/tracing-policies.yaml --ignore-not-found --timeout=30s 2>/dev/null || true
	@$(KCTL) delete -f kubernetes/admission-policies/policies.yaml --ignore-not-found --timeout=30s 2>/dev/null || true
	@$(KCTL) delete -f kubernetes/monitoring/grafana-ingress.yaml --ignore-not-found --timeout=30s 2>/dev/null || true
	@$(KCTL) delete -f kubernetes/storage/gp3-storageclass.yaml --ignore-not-found --timeout=30s 2>/dev/null || true
	@echo "--- Removing webhook configurations ---"
	@$(KCTL) delete mutatingwebhookconfigurations -l app.kubernetes.io/managed-by=Helm --ignore-not-found 2>/dev/null || true
	@$(KCTL) delete validatingwebhookconfigurations -l app.kubernetes.io/managed-by=Helm --ignore-not-found 2>/dev/null || true
	@echo "--- Uninstalling Helm releases ---"
	@$(HLM) uninstall aws-load-balancer-controller -n kube-system --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall external-secrets -n external-secrets --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall monitoring -n monitoring --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall loki -n monitoring --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall tetragon -n tetragon --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall cilium -n kube-system --no-hooks --timeout=60s 2>/dev/null || true
	@$(HLM) uninstall falco -n falco --no-hooks --timeout=60s 2>/dev/null || true
	@echo "--- Cleaning up namespaces ---"
	@for ns in falco tetragon monitoring external-secrets atdr; do \
		$(KCTL) delete ns $$ns --ignore-not-found --timeout=30s 2>/dev/null || \
		($(KCTL) get ns $$ns -o json 2>/dev/null | python3 -c 'import json,sys; ns=json.load(sys.stdin); ns["spec"]["finalizers"]=[]; print(json.dumps(ns))' | \
		$(KCTL) replace --raw "/api/v1/namespaces/$$ns/finalize" -f - 2>/dev/null) || true; \
	done
	@echo "=== Platform removed ==="

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
		--function-name atdr-approval-notifier \
		--zip-file fileb://$(LAMBDA_MOD)/approval_notifier.zip \
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

all-up: infra-up secrets platform-up deploy-lambdas
	@echo "Full deployment complete."

all-down:
	$(MAKE) platform-down || true
	$(MAKE) infra-down

## ─── Secrets ─────────────────────────────────────────────────────

secrets:
	@echo "=== ATDR Secrets Setup ==="
	@echo "Get these from https://api.slack.com/apps → Your App:"
	@echo "  - Bot Token: OAuth & Permissions → Bot User OAuth Token"
	@echo "  - Webhook URL: Incoming Webhooks → Webhook URL"
	@echo "  - Signing Secret: Basic Information → App Credentials → Signing Secret"
	@echo ""
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
	@read -p "MCP Auth Token (required): " mcp_token && \
		if [ -z "$$mcp_token" ]; then echo "ERROR: MCP Auth Token is required"; exit 1; fi && \
		aws secretsmanager put-secret-value \
			--secret-id atdr/mcp/auth-token \
			--secret-string "{\"token\":\"$$mcp_token\"}" \
			--region $(REGION) --no-cli-pager && \
		echo "  atdr/mcp/auth-token: done"
	@echo "=== Secrets configured ==="

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
	@rm -f $(LAMBDA_MOD)/layer.zip
	@mkdir -p $(LAYER_DIR)
	@pip install -r requirements.txt -t $(LAYER_DIR) --quiet
	@python3 -c 'from pathlib import Path; import zipfile; root=Path("build/layer"); out=Path("$(LAMBDA_MOD)/layer.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()'
	@echo "Layer: $(LAMBDA_MOD)/layer.zip"

build-lambdas:
	@rm -rf build/lambdas
	@rm -f $(LAMBDA_MOD)/summary.zip $(LAMBDA_MOD)/triage.zip $(LAMBDA_MOD)/solution.zip $(LAMBDA_MOD)/remediation.zip
	@rm -f $(LAMBDA_MOD)/ingestor.zip $(LAMBDA_MOD)/degraded_notifier.zip $(LAMBDA_MOD)/approval_notifier.zip
	@rm -f terraform/modules/slack/slack_bot.zip
	@for agent in summary triage solution remediation; do \
		mkdir -p build/lambdas/$$agent/app/agents && \
		cp app/agents/$$agent/*.py build/lambdas/$$agent/ && \
		cp -r app/agents/$$agent build/lambdas/$$agent/app/agents/$$agent && \
		cp -r app/shared build/lambdas/$$agent/app_shared && \
		cd build/lambdas/$$agent && \
		mkdir -p app/shared && mv app_shared/* app/shared/ && rmdir app_shared && \
		touch app/__init__.py app/agents/__init__.py app/agents/$$agent/__init__.py app/shared/__init__.py && \
		python3 -c 'from pathlib import Path; import zipfile; root=Path("."); out=Path("../../../$(LAMBDA_MOD)/'"$$agent"'.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()' && \
		cd ../../..; \
	done
	@mkdir -p build/lambdas/ingestor && \
		cp app/ingestor/*.py build/lambdas/ingestor/ && \
		cp -r app/shared build/lambdas/ingestor/app_shared && \
		cd build/lambdas/ingestor && \
		mkdir -p app/shared && mv app_shared/* app/shared/ && rmdir app_shared && \
		touch app/__init__.py app/shared/__init__.py && \
		python3 -c 'from pathlib import Path; import zipfile; root=Path("."); out=Path("../../../$(LAMBDA_MOD)/ingestor.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()' && \
		cd ../../..
	@mkdir -p build/lambdas/degraded_notifier && \
		cp app/degraded_notifier/*.py build/lambdas/degraded_notifier/ && \
		cp -r app/shared build/lambdas/degraded_notifier/app_shared && \
		cd build/lambdas/degraded_notifier && \
		mkdir -p app/shared && mv app_shared/* app/shared/ && rmdir app_shared && \
		touch app/__init__.py app/shared/__init__.py && \
		python3 -c 'from pathlib import Path; import zipfile; root=Path("."); out=Path("../../../$(LAMBDA_MOD)/degraded_notifier.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()' && \
		cd ../../..
	@mkdir -p build/lambdas/approval_notifier && \
		cp app/approval_notifier/*.py build/lambdas/approval_notifier/ && \
		cp -r app/shared build/lambdas/approval_notifier/app_shared && \
		cd build/lambdas/approval_notifier && \
		mkdir -p app/shared && mv app_shared/* app/shared/ && rmdir app_shared && \
		touch app/__init__.py app/shared/__init__.py && \
		python3 -c 'from pathlib import Path; import zipfile; root=Path("."); out=Path("../../../$(LAMBDA_MOD)/approval_notifier.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()' && \
		cd ../../..
	@mkdir -p build/lambdas/slack_bot && \
		cp app/slack_bot/*.py build/lambdas/slack_bot/ && \
		cp -r app/shared build/lambdas/slack_bot/app_shared && \
		cd build/lambdas/slack_bot && \
		mkdir -p app/shared && mv app_shared/* app/shared/ && rmdir app_shared && \
		touch app/__init__.py app/shared/__init__.py && \
		python3 -c 'from pathlib import Path; import zipfile; root=Path("."); out=Path("../../../terraform/modules/slack/slack_bot.zip"); z=zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED); [z.write(p,p.relative_to(root)) for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts]; z.close()' && \
		cd ../../..
	@echo "Lambdas packaged."

build-mcp:
	@MCP_REPO=$$(cd $(TF_DIR) && terraform output -raw mcp_server_repository_url) && \
		aws ecr get-login-password --region $(REGION) | docker login --username AWS --password-stdin $$(echo $$MCP_REPO | cut -d/ -f1) >/dev/null && \
		docker build --platform linux/amd64 -f mcp_server/Dockerfile -t $$MCP_REPO:$(MCP_IMAGE_TAG) . && \
		docker push $$MCP_REPO:$(MCP_IMAGE_TAG)
	@echo "EKS MCP image pushed: $(MCP_IMAGE_TAG)"

## ─── Quality ─────────────────────────────────────────────────────

lint:
	ruff check app tests mcp_server
	ruff format --check app tests mcp_server
	yamllint -c .yamllint.yml kubernetes/
	terraform fmt -check -recursive terraform/

lint-fix:
	ruff check --fix app tests mcp_server
	ruff format app tests mcp_server
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
