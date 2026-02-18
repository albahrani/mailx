.PHONY: test test-race vet ci

MODULES := server client

test:
	@set -e; for m in $(MODULES); do \
		echo "==> $$m: go test ./..."; \
		( cd $$m && go test ./... ); \
	done

test-race:
	@set -e; for m in $(MODULES); do \
		echo "==> $$m: go test -race ./..."; \
		( cd $$m && CGO_ENABLED=1 go test -race ./... ); \
	done

vet:
	@set -e; for m in $(MODULES); do \
		echo "==> $$m: go vet ./..."; \
		( cd $$m && go vet ./... ); \
	done

ci: vet test
	@echo "CI checks passed"
