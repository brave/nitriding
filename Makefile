.PHONY: all test lint

godeps = go.mod go.sum

all: test lint

mock:
	@mockery --all

FUZZTIME=5s

fuzz:
	cd certificate && go test -fuzz=FuzzPemToDer_CannotParsePEM -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzEncodeToMemory_NeverFails -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzEncodeToMemoryThenPemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzMakeSelfSigCert -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzSelfSigCert_ToFile -parallel=1 -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzSelfSigCert_FromFile -parallel=1 -fuzztime=$(FUZZTIME)
	cd validation && go test -fuzz=FuzzFileValidator_Validate -parallel=1 -fuzztime=$(FUZZTIME)

lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./... -count=1

clean:
	go clean -fuzzcache
