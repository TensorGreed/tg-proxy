BINARY := tg-proxy
PKG    := github.com/TensorGreed/tg-proxy
CMD    := ./cmd/$(BINARY)

GO          ?= go
GOFLAGS     ?=
COVER_OUT   := coverage.out
COVER_HTML  := coverage.html
COVER_MIN   ?= 80

.PHONY: all build run test test-short cover cover-html cover-check lint tidy proto clean

all: lint test build

build:
	$(GO) build $(GOFLAGS) -o bin/$(BINARY) $(CMD)

run:
	$(GO) run $(CMD) -config config.example.yaml

test:
	$(GO) test -race -coverprofile=$(COVER_OUT) ./...

test-short:
	$(GO) test -short ./...

cover: test
	$(GO) tool cover -func=$(COVER_OUT)

cover-html: test
	$(GO) tool cover -html=$(COVER_OUT) -o $(COVER_HTML)

cover-check: test
	@total=$$($(GO) tool cover -func=$(COVER_OUT) | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	echo "Total coverage: $$total%"; \
	awk -v t=$$total -v m=$(COVER_MIN) 'BEGIN { if (t+0 < m+0) { printf "coverage %s%% is below threshold %s%%\n", t, m; exit 1 } }'

lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

# Regenerate gRPC stubs from pkg/plugin/proto/plugin.proto.
# Requires: pip install grpcio-tools  +  protoc-gen-go and protoc-gen-go-grpc on PATH.
PROTO_DIR := pkg/plugin/proto
PY_PROTO_DIR := packaging/python-sdk-plugin/src/tgproxy_plugin/_proto
proto:
	python -m grpc_tools.protoc -I $(PROTO_DIR) \
	    --go_out=. --go_opt=module=github.com/TensorGreed/tg-proxy \
	    --go-grpc_out=. --go-grpc_opt=module=github.com/TensorGreed/tg-proxy \
	    $(PROTO_DIR)/plugin.proto
	python -m grpc_tools.protoc -I $(PROTO_DIR) \
	    --python_out=$(PY_PROTO_DIR) \
	    --grpc_python_out=$(PY_PROTO_DIR) \
	    --pyi_out=$(PY_PROTO_DIR) \
	    $(PROTO_DIR)/plugin.proto
	@python -c "import re, pathlib; p=pathlib.Path('$(PY_PROTO_DIR)/plugin_pb2_grpc.py'); p.write_text(re.sub(r'^import plugin_pb2 as plugin__pb2$$', 'from . import plugin_pb2 as plugin__pb2', p.read_text(), flags=re.M))"

clean:
	rm -rf bin dist $(COVER_OUT) $(COVER_HTML)
