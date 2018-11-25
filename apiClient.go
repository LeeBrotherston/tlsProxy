package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
)

// TLS configuration used by the client
var myTLSConfig = tls.Config{
	MinVersion:         tls.VersionTLS12,
	InsecureSkipVerify: false, // Yeah, checking certs would be nice
	//VerifyPeerCertificate  //  <-  can do cert pinning
	SessionTicketsDisabled: false,
	// In line with Mozilla Modern Compatibility... will trim further
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	// Also in line with Moz modern compatibility
	CurvePreferences: []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	},
}

// Transport configuration for REST requests
var myTransportConfig = http.Transport{
	MaxIdleConns:       10,           // 10 is kinda arbirary right now, we can tune this
	IdleConnTimeout:    0,            // 0 is no limit.  We want to keep hold of and pipeline sessions as much as possible
	DisableCompression: true,         // I *think* this will be a waste of CPU cycles, but we can test that thinking
	DisableKeepAlives:  false,        // We want keepalives in line with no idletimeout, let's keep it rolling :)
	TLSClientConfig:    &myTLSConfig, // Separate TLS configuration for the connection
}

// createTransport sets up the transport in line with the config (above)
func createTransport() *http.Client {
	// Clients and Transports are safe for concurrent use by multiple goroutines and for efficiency should only be created once and re-used.
	if developer == true {
		myTLSConfig.InsecureSkipVerify = true
	}
	tr := &myTransportConfig
	client := &http.Client{Transport: tr}
	return client
}

// restPOST will be used to POST to the defined REST endpoint
func restPOST(endpoint string, buf []byte) {
	fmt.Printf("restPOST called\n%v\n", buf)
	resp, err := restClient.Post(endpoint, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		if resp != nil {
			fmt.Printf("Got a response\n")
		} else {
			fmt.Printf("No Response?\n")
		}
		return
	}

	fmt.Printf("restPOST error: %s\n", err)

	return

}

// restGET will be used to GET from the defined REST endpoint
func restGET(client *http.Client) {
	//client := createTransport()
	resp, err := client.Get("https://www.google.com")
	if err != nil {
		return
	}

	if resp != nil {
		print("Got a response")
	}
	if err != nil {
		print("oops")
		print(err)
	}
	print(resp.Body)
}

// APIWorker is go func that listens on a channel for new events to send to the API
// this is a separate process to save other processes from having to wait for the
// completion of API calls
func APIWorker(event chan Event) {

}
