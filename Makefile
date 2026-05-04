TF_DIR := terraform/envs/demo
CLUSTER := atdr-demo
REGION := ap-northeast-2

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

.PHONY: scale-down scale-up scale-status

scale-down:
	@echo "Scaling all node groups to 0..."
	@for ng in $$(aws eks list-nodegroups --cluster-name $(CLUSTER) --region $(REGION) --query 'nodegroups[]' --output text 2>/dev/null); do \
		echo "  $$ng → 0"; \
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
		echo "  $$ng → 2"; \
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
