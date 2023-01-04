// Example demonstrates a [server.Server] running outside a Nitro Enclave.
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/blocky/nitriding/pkg/nitriding"
)

func main() {
	//Create a nitriding server to run outside a Nitro Enclave using a
	//standalone attester.
	srv, err := nitriding.NewStandaloneServer("github.com/blocky/nitriding", 8443)
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.AddRoute(
		http.MethodGet,
		"/",
		func(writer http.ResponseWriter, request *http.Request) {
			nitriding.IndexHandler(srv, writer, request)
		},
	)
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.AddRoute(
		http.MethodGet,
		"/attester",
		func(writer http.ResponseWriter, request *http.Request) {
			nitriding.GetAttesterHandler(srv, writer, request)
		},
	)
	if err != nil {
		log.Fatal(fmt.Errorf("could not create server: %w", err))
	}

	err = srv.Start()
	if err != nil {
		log.Fatal(fmt.Errorf("enclave unexpectedly terminated: %w", err))
	}
}
