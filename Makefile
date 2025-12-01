CONTROLLER_TOOLS_VERSION := v0.16.5
ENVTEST_VERSION := release-0.19
ENVTEST_K8S_VERSION := 1.31.0
MOCKERY_VERSION := v3.3.4

CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
MOCKERY ?= go run github.com/vektra/mockery/v3@$(MOCKERY_VERSION)
HELM_SCHEMA ?= go run github.com/dadav/helm-schema/cmd/helm-schema@latest

GO_MOD_SRCS := go.mod go.sum
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOEXPERIMENT=jsonv2

ENVTEST_DIR ?= $(shell pwd)/.envtest

REGISTRY ?= ghcr.io
REPO ?= kubewarden/sbomscanner
TAG ?= latest

.PHONY: all
all: controller storage worker

.PHONY: test
test: vet ## Run tests.
	$(GO_BUILD_ENV) CGO_ENABLED=1 KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" go test $$(go list ./... | grep -v /e2e) -race -test.v -coverprofile coverage/cover.out -covermode=atomic

.PHONY: helm-unittest
helm-unittest:
	helm unittest charts/sbomscanner --file "tests/**/*_test.yaml"

.PHONY: test-e2e
test-e2e: controller-image storage-image worker-image
	$(GO_BUILD_ENV) go test ./test/e2e/ -v

.PHONY: fmt
fmt:
	$(GO_BUILD_ENV) go fmt ./...

.PHOHY: lint
lint: golangci-lint
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --verbose

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --fix

.PHOHY: vet
vet:
	$(GO_BUILD_ENV) go vet ./...

CONTROLLER_SRC_DIRS := cmd/controller api internal/controller
CONTROLLER_GO_SRCS := $(shell find $(CONTROLLER_SRC_DIRS) -type f -name '*.go')
CONTROLLER_SRCS := $(GO_MOD_SRCS) $(CONTROLLER_GO_SRCS)
.PHONY: controller
controller: $(CONTROLLER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/controller ./cmd/controller

.PHONY: controller-image
controller-image:
	docker build -f ./Dockerfile.controller \
		-t "$(REGISTRY)/$(REPO)/controller:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/controller:$(TAG)"

STORAGE_SRC_DIRS := cmd/storage api internal/apiserver internal/storage pkg
STORAGE_GO_SRCS := $(shell find $(STORAGE_SRC_DIRS) -type f -name '*.go')
STORAGE_SRCS := $(GO_MOD_SRCS) $(STORAGE_GO_SRCS)
.PHONY: storage
storage: $(STORAGE_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/storage ./cmd/storage

.PHONY: storage-image
storage-image:
	docker build -f ./Dockerfile.storage \
		-t "$(REGISTRY)/$(REPO)/storage:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/storage:$(TAG)"

WORKER_SRC_DIRS := cmd/worker api internal/messaging internal/handlers
WORKER_GO_SRCS := $(shell find $(WORKER_SRC_DIRS) -type f -name '*.go')
WORKER_SRCS := $(GO_MOD_SRCS) $(WORKER_GO_SRCS)
.PHONY: worker
worker: $(WORKER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/worker ./cmd/worker

.PHONY: worker-image
worker-image:
	docker build -f ./Dockerfile.worker \
		-t "$(REGISTRY)/$(REPO)/worker:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/worker:$(TAG)"

.PHONY: generate
generate: generate-controller generate-storage generate-chart generate-mocks

.PHONY: generate-controller
generate-controller: manifests  ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) object paths="./api/v1alpha1"

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects. We use yq to modify the generated files to match our naming and labels conventions.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) rbac:roleName=controller-role crd webhook paths="./api/v1alpha1"  paths="./internal/controller" output:crd:artifacts:config=charts/sbomscanner/templates/crd output:rbac:artifacts:config=charts/sbomscanner/templates/controller
	sed -i 's/controller-role/{{ include "sbomscanner.fullname" . }}-controller/' charts/sbomscanner/templates/controller/role.yaml
	sed -i '/metadata:/a\  labels:\n    {{ include "sbomscanner.labels" . | nindent 4 }}\n    app.kubernetes.io/component: controller' charts/sbomscanner/templates/controller/role.yaml
	for f in ./charts/sbomscanner/templates/crd/*.yaml; do \
		sed -i '/^[[:space:]]*annotations:/a\    helm.sh\/resource-policy: keep' "$$f"; \
	done

.PHONY: generate-storage-test-crd
generate-storage-test-crd: ## Generate CRD used by the controller tests to access the storage resources. This is needed since storage does not provide CRD, being an API server extension.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) crd paths="./api/storage/..." output:crd:artifacts:config=test/crd

.PHONY: generate-storage
generate-storage: generate-storage-test-crd ## Generate storage  code in pkg/generated and DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	go install ./hack/tools.go
	API_KNOWN_VIOLATIONS_DIR=. UPDATE_API_KNOWN_VIOLATIONS=true ./hack/update-codegen.sh

.PHONY: generate-chart
generate-chart: ## Generate Helm chart values schema.
	$(HELM_SCHEMA)

.PHONY: generate-mocks
generate-mocks: ## Generate mocks for testing.
	$(MOCKERY)

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.5.0

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef
