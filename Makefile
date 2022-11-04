BLUE=\033[0;34m
NC=\033[0m # No Color

.PHONY: all test lint

godeps = go.mod go.sum

all: test lint

mock:
	@mockery --all
	@mockery --dir $(GOPATH)/pkg/mod/golang.org/x/crypto*/acme/autocert --name Cache
	@mockery --dir $(GOPATH)/pkg/mod/github.com/blocky/nsm*/ --name NSMSession

FUZZTIME=5s

fuzz:
	cd attestation && go test -fuzz=FuzzBaseAttesterHelper_MakeCOSEMessage -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_PemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_DerToPem -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_FullDerToPemThenPemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzMakeBasePrivilegedCert -fuzztime=$(FUZZTIME)
	cd server && go test -fuzz=FuzzParseSOCKSAddress -fuzztime=$(FUZZTIME)

lint:
	golangci-lint run

test-unit: $(godeps)
	@go test -cover `go list ./... | grep -v examples` -v -count=1

test-live:
	@echo -n "\n${BLUE}Starting server...${NC}"; \
	{ go run ./examples/main.go & }; \
	go_pid=$$!; \
	sleep 1; \
	main_pid=$$(lsof -t -i:8443); \
	echo "${BLUE}started with PID $$go_pid and $$main_pid${NC}"; \
	echo "${BLUE}Running tests...${NC}"; \
	go test -count=1 -v ./examples/...; \
	r=$$?; \
	echo -n "${BLUE}Tearing down server...${NC}"; \
	kill -9 $$main_pid; \
	kill -9 $$go_pid; \
	echo "${BLUE}success${NC}"; \
	exit $$r

test: test-unit

clean:
	go clean -fuzzcache
	rm -rf mocks

deep-clean: clean
	go clean -fuzzcache
