.PHONY: all test lint

godeps = go.mod go.sum

all: test lint

mock:
	@mockery --dir certificate --name PrivilegedCert
	@mockery --dir certificate --name Converter
	@mockery --dir validation --name StringValidator

FUZZTIME=5s

fuzz:
	cd certificate && go test -fuzz=FuzzBaseConverter_PemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_DerToPem_NeverFails -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_DerToPemThenPemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzMakeBasePrivilegedCert -fuzztime=$(FUZZTIME)
	cd validation && go test -fuzz=FuzzFileValidator_Validate -parallel=1 -fuzztime=$(FUZZTIME)


lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./... -count=1

clean:
	go clean -fuzzcache
	rm -rf mocks
