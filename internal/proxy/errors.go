package proxy

import "errors"

// Sentinel errors for the proxy package.
var (
	// ErrCAGenerate indicates generation of a fresh root CA failed.
	ErrCAGenerate = errors.New("proxy: generate CA failed")

	// ErrCALoad indicates loading the CA cert or key from disk failed.
	ErrCALoad = errors.New("proxy: load CA failed")

	// ErrCABundle indicates building/writing the combined CA bundle failed.
	ErrCABundle = errors.New("proxy: build CA bundle failed")

	// ErrListen indicates the proxy could not bind its loopback listener.
	ErrListen = errors.New("proxy: listen failed")

	// ErrBodyRead indicates reading the outbound request body failed.
	ErrBodyRead = errors.New("proxy: body read failed")
)
