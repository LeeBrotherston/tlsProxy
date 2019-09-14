package main

import (
	"os"
	"time"
)

// Event structs are used to express events via the API
type Event struct {
	//EventID    [32]string `json:"event_id"`		// Generated serverside
	Event     string    `json:"event"`
	FPHash    string    `json:"fp_hash,omitempty"`
	IPVersion string    `json:"ip_version"`
	IPDst     string    `json:"ipv4_dst"`
	IPSrc     string    `json:"ipv4_src"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	TimeStamp time.Time `json:"timestamp"`
	//	TLSVersion  uint16    `json:"tls_version"`  // Part of the fingerprint, doesn't need to be stored here
	SNI string `json:"server_name"`
	//Fingerprint `json:"fingerprint,omitempty"`
}

type userConfig struct {
	MinTLS    string   `json:"min_TLS_ver"`
	Timeout   int64    `json:"timeout"`
	AppLog    string   `json:"appLog"`
	apFile    *os.File // Accompanying file descriptor
	NewFPFile string   `json:"new_fingerprint_file"`
	fpFile    *os.File // Accompanying file descriptor
	EventLog  string   `json:"eventLog"`
	eventFile *os.File // Accompanying file descriptor
}
