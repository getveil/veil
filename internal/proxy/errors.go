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

	// ErrPlaceholderLeak indicates the fail-closed guard detected a
	// placeholder sentinel in the final outbound bytes and refused to
	// forward the request.
	ErrPlaceholderLeak = errors.New("proxy: placeholder leak detected")

	// ErrCompressedBody indicates an outbound request body used a
	// Content-Encoding Veil cannot safely inject into, so the request was
	// rejected rather than forwarded with potentially-unreplaced placeholders.
	ErrCompressedBody = errors.New("proxy: compressed request body rejected")
)
