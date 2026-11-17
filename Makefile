GO ?= go
IMAGE ?= ovn-light:dev
VERSION ?= dev
KIND_CLUSTER ?= ovn
.PHONY: build test check demo image deploy-kind
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/ovn-light ./cmd/ovn-light
test:
	$(GO) test -race ./...
check:
	$(GO) vet ./...
	node --check internal/web/assets/app.js
demo:
	$(GO) run ./cmd/ovn-light --demo
image: build
	docker build -f Dockerfile.local -t $(IMAGE) .
deploy-kind:
	IMAGE=$(IMAGE) ./scripts/deploy-kind.sh $(KIND_CLUSTER)
