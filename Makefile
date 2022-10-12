.PHONY: all test lint

godeps = go.mod go.sum

all: test lint

mock:
	@mockery --all
	@mockery --dir $(GOPATH)/pkg/mod/github.com/blocky/nsm*/ --name NSMSession

FUZZTIME=5s

fuzz:
	cd attestation && go test -fuzz=FuzzBaseAttesterHelper_MakeCOSEMessage -fuzztime=$(FUZZTIME)
	cd attestation/signature && go test -fuzz=FuzzNewBoxKeyFromSlice -fuzztime=$(FUZZTIME)
	cd attestation/signature && go test -fuzz=FuzzBoxSigner_Sign -fuzztime=$(FUZZTIME)
	cd attestation/signature && go test -fuzz=FuzzPSSSigner_Sign -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_PemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_DerToPem -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzBaseConverter_FullDerToPemThenPemToDer -fuzztime=$(FUZZTIME)
	cd certificate && go test -fuzz=FuzzMakeBasePrivilegedCert -fuzztime=$(FUZZTIME)
	cd validation && go test -fuzz=FuzzFileValidator_Validate -parallel=1 -fuzztime=$(FUZZTIME)


lint:
	golangci-lint run

test: $(godeps)
	@go test -cover ./... -count=1

clean:
	go clean -fuzzcache
	rm -rf mocks

deep-clean: clean
	go clean -fuzzcache
