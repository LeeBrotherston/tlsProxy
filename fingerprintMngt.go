package main

import "encoding/hex"

// Adds a fingerprint (myPrint) to the fingerprint database (myDB)
func addPrint(myPrint fingerprintFile, myDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) bool {
	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))] = map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))] = map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))] = map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))] = map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))] = map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))] = map[string]map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))] = map[string]map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))][HexNormalise(string(myPrint.ECPointFmt))]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))][HexNormalise(string(myPrint.ECPointFmt))] = map[bool]string{}
	}

	if len(myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))][HexNormalise(string(myPrint.ECPointFmt))][myPrint.Grease]) == 0 {
		myDB[HexNormalise(string(myPrint.RecordTLSVersion))][HexNormalise(string(myPrint.TLSVersion))][HexNormalise(string(myPrint.Ciphersuite))][HexNormalise(string(myPrint.Compression))][HexNormalise(string(myPrint.Extensions))][HexNormalise(string(myPrint.ECurves))][HexNormalise(string(myPrint.SigAlg))][HexNormalise(string(myPrint.ECPointFmt))][myPrint.Grease] = myPrint.Desc
	}

	return true
}

// Adds a fingerprint (myPrint) to the fingerprint database (myDB)
func addPrintInt(myPrint fingerprint, myDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) bool {
	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))] = map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))] = map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))] = map[string]map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))] = map[string]map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))] = map[string]map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))] = map[string]map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))] = map[string]map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))][hex.EncodeToString([]byte(myPrint.ecPointFmt))]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))][hex.EncodeToString([]byte(myPrint.ecPointFmt))] = map[bool]string{}
	}

	if len(myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))][hex.EncodeToString([]byte(myPrint.ecPointFmt))][myPrint.grease]) == 0 {
		myDB[hex.EncodeToString([]byte(myPrint.recordTLSVersion))][hex.EncodeToString([]byte(myPrint.TLSVersion))][hex.EncodeToString([]byte(myPrint.ciphersuite))][hex.EncodeToString([]byte(myPrint.compression))][hex.EncodeToString([]byte(myPrint.extensions))][hex.EncodeToString([]byte(myPrint.eCurves))][hex.EncodeToString([]byte(myPrint.sigAlg))][hex.EncodeToString([]byte(myPrint.ecPointFmt))][myPrint.grease] = myPrint.desc
	}

	return true
}
