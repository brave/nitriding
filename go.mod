module github.com/brave/nitriding

go 1.19

require (
	github.com/blocky/parlor v1.0.0
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/hf/nitrite v0.0.0
	github.com/hf/nsm v0.0.0
	github.com/stretchr/testify v1.8.0
	github.com/veraison/go-cose v1.0.0-rc.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/hf/nitrite => github.com/blocky/nitrite v0.0.2-0.20220831170244-e4b0083dd2fc

replace github.com/hf/nsm => github.com/blocky/nsm v0.0.0-20220902220237-de4e289e7f0c
