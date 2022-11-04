module github.com/brave/nitriding

go 1.19

require (
	github.com/blocky/parlor v1.0.0
	github.com/brave/viproxy v0.1.2
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-ping/ping v1.1.0
	github.com/go-playground/validator/v10 v10.11.1
	github.com/hf/nitrite v0.0.0
	github.com/hf/nsm v0.0.0
	github.com/mdlayher/vsock v1.1.1
	github.com/milosgajdos/tenus v0.0.3
	github.com/stretchr/testify v1.8.0
	github.com/veraison/go-cose v1.0.0-rc.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/libcontainer v2.2.1+incompatible // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/mdlayher/socket v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/hf/nitrite => github.com/blocky/nitrite v0.0.2-0.20221024173523-4c4be7073c6d

replace github.com/hf/nsm => github.com/blocky/nsm v0.0.0-20220902220237-de4e289e7f0c
