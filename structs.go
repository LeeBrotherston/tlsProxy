package main

import "os"

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

// Type for json fingerprint in the fingerprints JSON file
// Names much be uppercase to make this work and the `json:"name"`
// maps them back to the names contained in the file for compatibility
// with fingerprintls.
type fingerprintFile struct {
	ID                float64 `json:"id"`
	Desc              string  `json:"desc"`
	RecordTLSVersion  string  `json:"record_tls_version"`
	TLSVersion        string  `json:"tls_version"`
	CiphersuiteLength string  `json:"ciphersuite_length"`
	Ciphersuite       string  `json:"ciphersuite"`
	CompressionLength string  `json:"compression_length"`
	Compression       string  `json:"compression"`
	Extensions        string  `json:"extensions"`
	ECurves           string  `json:"e_curves"`
	SigAlg            string  `json:"sig_alg"`
	ECPointFmt        string  `json:"ec_point_fmt"`
	Grease            bool    `json:"grease"`
}

// Internal fingerprint management... almost the same as fingerprintFile.  maybe
// they can be combined in the future.
type fingerprint struct {
	id               float64 //`json:"id"`
	desc             string  //`json:"desc"`
	recordTLSVersion []byte  //`json:"record_tls_version"`
	TLSVersion       []byte  //`json:"tls_version"`
	ciphersuite      []byte  //`json:"ciphersuite"`
	compression      []byte  //`json:"compression"`
	extensions       []byte  //`json:"extensions"`
	eCurves          []byte  //`json:"e_curves"`
	sigAlg           []byte  //`json:"sig_alg"`
	ecPointFmt       []byte  //`json:"ec_point_fmt"`
	grease           bool
}

// fingerprintOutput contains data generated by the fingerprinTLS() func
type fingerprintOutput struct {
	fingerprintName string // The human readable name for the fingerprint, intended for log output, etc
	hostname        []byte // Destination hostname as taken from the SNI
	destination     []byte
}
