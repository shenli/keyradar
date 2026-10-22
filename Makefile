.PHONY: build test race vet check fmt fmt-check schemas smoke
build:
	go build -trimpath -o bin/keyradar ./cmd/keyradar
test:
	go test ./...
race:
	go test -race ./...
vet:
	go vet ./...
check: fmt-check test race vet schemas
fmt:
	gofmt -w cmd internal templates
smoke: build
	python3 scripts/smoke.py bin/keyradar
fmt-check:
	@test -z "$$(gofmt -l cmd internal templates)" || (echo "Run make fmt"; exit 1)
schemas:
	python3 scripts/generate_schemas.py --check
