TF_DIR := terraform/envs/demo
CLUSTER := atdr-demo
REGION := ap-northeast-2
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

.PHONY: build build-layer build-lambdas build-all

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

.PHONY: deploy deploy-infra deploy-k8s

deploy-infra: build
	cd $(TF_DIR) && terraform apply -auto-approve

deploy-k8s:
	@echo "Installing AWS Load Balancer Controller..."
	helm repo add eks https://aws.github.io/eks-charts 2>/dev/null || true
	helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
		-n kube-system \
		--set clusterName=$(CLUSTER) \
		--set serviceAccount.create=true \
		--set serviceAccount.name=aws-load-balancer-controller \
		--set region=$(REGION) \
		--set vpcId=$$(aws eks describe-cluster --name $(CLUSTER) --region $(REGION) --query 'cluster.resourcesVpcConfig.vpcId' --output text)
	@echo "Installing Falco..."
	helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
	helm upgrade --install falco falcosecurity/falco \
		-n falco --create-namespace \
		-f kubernetes/falco/values.yaml
	@echo "Installing Tetragon..."
	helm repo add cilium https://helm.cilium.io 2>/dev/null || true
	helm upgrade --install tetragon cilium/tetragon \
		-n tetragon --create-namespace
	kubectl apply -f kubernetes/tetragon/tracing-policies.yaml
	@echo "Installing kube-prometheus-stack..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
	helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
		-n monitoring --create-namespace \
		-f kubernetes/monitoring/kube-prometheus-stack-values.yaml
	@echo "Installing Loki..."
	helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
	helm upgrade --install loki grafana/loki \
		-n monitoring \
		-f kubernetes/monitoring/loki-values.yaml
	@echo "Applying Grafana Ingress..."
	kubectl apply -f kubernetes/monitoring/grafana-ingress.yaml
	@echo "Installing External Secrets Operator..."
	helm repo add external-secrets https://charts.external-secrets.io 2>/dev/null || true
	helm upgrade --install external-secrets external-secrets/external-secrets \
		-n external-secrets --create-namespace
	kubectl apply -f kubernetes/external-secrets/external-secrets.yaml
	@echo "Applying admission policies..."
	kubectl apply -f kubernetes/admission-policies/policies.yaml
	@echo "Kubernetes deployment complete."

deploy: deploy-infra deploy-k8s
	@echo "Full deployment complete."

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

.PHONY: clean

clean:
	rm -rf build/
	rm -rf terraform/modules/lambda/*.zip
	rm -rf terraform/modules/slack/*.zip
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
