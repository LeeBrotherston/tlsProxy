package main

import (
	"fmt"
	"log"
	"strconv"
)

// tlsFingerprint finds the fingerprint that is matched by the provided packet
func tlsFingerprint(buf []byte, proxyDest string, fingerprintDBNew map[uint64]string) (fingerprintOutput, fingerprint) {
	//log.Printf("Started tlsFingerprint function")
	var output fingerprintOutput
	var thisFingerprint fingerprint
	if buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3 {
		// This is the Lee acid test for is this a TLS client hello packet
		// The "science" behind it is here:
		// https://speakerdeck.com/leebrotherston/stealthier-attacks-and-smarter-defending-with-tls-fingerprinting?slide=31

		// buf[0] == TLS Handshake
		// buf[5] == Client Hello
		// buf[1] == Record TLS Version
		// buf[9] == TLS Version

		// Sweet, looks like a client hello, let's do some pre-processing

		var sessionIDLength byte
		var ciphersuiteLength uint16
		//var chLen uint16
		var i uint16
		destination := ""

		thisFingerprint.recordTLSVersion = make([]byte, 2)
		copy(thisFingerprint.recordTLSVersion, buf[1:3])

		//chLen = uint16(buf[3])<<8 + uint16(buf[4])

		//thisFingerprint.TLSVersion = make([]byte, 2)
		//copy(thisFingerprint.TLSVersion, buf[9:11])
		thisFingerprint.TLSVersion = buf[9:11]

		// Length of the session id changes to offset for the next bits
		sessionIDLength = buf[43]

		// ciphersuite Length also determines some offsets
		// This doesn't feel like a very GO'y way of doing this!
		ciphersuiteLength = uint16(buf[44+sessionIDLength]) << 8
		ciphersuiteLength += uint16(buf[45+sessionIDLength])

		// OK let's get dem ciphersuites, yo...
		tempCiphersuite := make([]byte, uint16(ciphersuiteLength))
		if uint16(copy(tempCiphersuite, buf[(46+uint16(sessionIDLength)):(46+uint16(sessionIDLength)+ciphersuiteLength)])) != ciphersuiteLength {
			log.Printf("Debug: Ciphersuite copy lengths seem wrong\n")
		}

		// Get degreasing info
		shrinkBy, otherTempCiphersuite := deGrease(tempCiphersuite)
		if shrinkBy > 0 {
			thisFingerprint.grease = true
		}

		greaseCiphersuiteLength := ciphersuiteLength - uint16(shrinkBy*2)
		thisFingerprint.ciphersuite = make([]byte, uint16(greaseCiphersuiteLength))
		copy(thisFingerprint.ciphersuite, otherTempCiphersuite)

		// Let's take a lookie see at the compression settings, which are always the same ;)
		var compressionMethodsLen byte
		compressionMethodsLen = buf[46+uint16(sessionIDLength)+uint16(ciphersuiteLength)]

		// XXX move to using copy like ciphersuites
		thisFingerprint.compression = make([]byte, uint16(compressionMethodsLen))
		for i = 0; i < uint16(compressionMethodsLen); i++ {
			thisFingerprint.compression[i] = buf[47+uint16(sessionIDLength)+ciphersuiteLength]
		}

		// And now to the really exciting world of extensions.... extensions!!!
		// Get me them thar extensions!!!!
		var extensionsLength uint16
		extensionsLength = uint16(uint16(buf[47+uint16(sessionIDLength)+uint16(ciphersuiteLength)+uint16(compressionMethodsLen)]) << 8)
		extensionsLength += uint16(buf[48+uint16(sessionIDLength)+uint16(ciphersuiteLength)+uint16(compressionMethodsLen)])

		offset := 49 + uint16(sessionIDLength) + uint16(ciphersuiteLength) + uint16(compressionMethodsLen)
		for i = 0; i < extensionsLength; i++ {
			var extensionType uint16
			//var increment uint16

			extensionType = uint16(buf[offset+i]) << 8
			extensionType += uint16(buf[offset+i+1])

			// This is the extensionType again, but to add to the extensions var for fingerprinting
			switch uint16(extensionType) {
			// Lets not add grease to the extension list....
			case 0x0A0A:
			case 0x1A1A:
			case 0x2A2A:
			case 0x3A3A:
			case 0x4A4A:
			case 0x5A5A:
			case 0x6A6A:
			case 0x7A7A:
			case 0x8A8A:
			case 0x9A9A:
			case 0xAAAA:
			case 0xBABA:
			case 0xCACA:
			case 0xDADA:
			case 0xEAEA:
			case 0xFAFA:
				thisFingerprint.grease = true
			// Or padding.....
			case 0x0015:
			// But everything else is fine
			default:
				thisFingerprint.extensions = append(thisFingerprint.extensions, buf[offset+i], buf[offset+i+1])
			}
			//if extensionType != 0x0015 {
			// Yay it's not padding
			//	thisFingerprint.extensions = append(thisFingerprint.extensions, buf[offset+i], buf[offset+i+1])
			//}

			// Move counter to start of extension
			i += 2

			switch uint16(extensionType) {

			case 0x0000:
				// Server Name Indication (SNI) extension
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])

				// Check internal length pointer
				if (uint16(buf[offset+i+2])<<8 + uint16(buf[offset+i+3])) != (extLength - 2) {
					log.Printf("Problem: Internal servername pointer length incorrect %v %v %v %v\n", extLength, i, buf[offset+i+2], buf[offset+i+3])
					//log.Printf("Problematic PACKETDUMP >>>> %#x", buf)
				}
				// Check this is "hostname" type
				if buf[offset+i+4] != 0 {
					fmt.Printf("Problem: Not hostname based SNI... or something... wat?\n")
				}
				// And the internal internal yadda yadda length check (W T A F ?)
				if (uint16(buf[offset+i+5])<<8 + uint16(buf[offset+i+6])) != (extLength - 5) {
					log.Printf("Problem: Other internal servername pointer length incorrect %v %v\n", extLength, i)
				}

				hostnameLength := uint16(buf[offset+i+5])<<8 + uint16(buf[offset+i+6])

				hostname := make([]byte, hostnameLength)

				if hostnameLength != uint16(copy(hostname, buf[offset+i+7:offset+i+7+hostnameLength])) {
					log.Printf("Problem: failed to copy hostname: %v - %v - %v\n", hostnameLength,
						copy(hostname, buf[offset+i+7:offset+i+7+hostnameLength]),
						hostname)
				}

				destination = string(hostname) + ":" + "443"

				output.destination = []byte(destination)
				output.hostname = hostname

				//log.Printf("Destination set to: %v", output.destination)

				// XXX This is to get around transparent proxies where this isn't already set.
				// Will make this neater in future

				// Currently this will serve to only use SNS when there is no proxy setting
				if len(proxyDest) == 0 {
					proxyDest = destination
				}

				// Set the i pointer
				i += extLength + 1

			case 0x0015:
				// This is padding, we ignore padding.
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])
				i += extLength + 1

			case 0x000a:
				/* ellipticCurves */
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])

				// Check internal Length
				if (uint16(buf[offset+i+2])<<8 + uint16(buf[offset+i+3])) != (extLength - 2) {
					log.Printf("Problem: Internal servername pointer length incorrect\n")
				}

				ellipticCurvesLength := uint16(buf[offset+i+2])<<8 + uint16(buf[offset+i+3])
				tempeCurves := make([]byte, ellipticCurvesLength)

				copy(tempeCurves, buf[offset+i+4:offset+i+4+ellipticCurvesLength])
				shrinkBy, otherTempeCurves := deGrease(tempeCurves)
				if shrinkBy > 0 {
					thisFingerprint.grease = true
				}
				greaseeCurvesLength := ellipticCurvesLength - uint16(shrinkBy*2)

				thisFingerprint.eCurves = make([]byte, greaseeCurvesLength)
				if greaseeCurvesLength != uint16(copy(thisFingerprint.eCurves, otherTempeCurves)) {
					log.Printf("Problem: failed to copy ellipticCurves\n")
				}

				// Set the i pointer
				i += extLength + 1

			case 0x000b:
				/* ecPoint formats */
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])

				// ecPoint is only an 8bit length, stored at uint16 to make comparison easier
				ecPointLength := uint16(uint8(buf[offset+i+2]))

				thisFingerprint.ecPointFmt = make([]byte, ecPointLength)
				if ecPointLength != uint16(copy(thisFingerprint.ecPointFmt, buf[offset+i+3:offset+i+3+ecPointLength])) {
					log.Printf("Problem: failed to copy ecPoint\n")
				}

				// Set the i pointer
				i += extLength + 1

			case 0x000d:
				/* Signature algorithms */
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])

				sigAlgLength := uint16(buf[offset+i+2])<<8 + uint16(buf[offset+i+3])

				thisFingerprint.sigAlg = make([]byte, sigAlgLength)

				if sigAlgLength != uint16(copy(thisFingerprint.sigAlg, buf[(offset+i+4):(offset+i+4+sigAlgLength)])) {
					log.Printf("Problem: failed to copy sigAlg\n")
				} else {
					//log.Printf("sigAlg: %#x\n", sigAlg)
				}

				i += extLength + 1

			default:
				// Move i to the extension
				// Special cases will have to place i themselves for $reasons :)
				extLength := uint16(buf[offset+i])<<8 + uint16(buf[offset+i+1])
				i += extLength + 1

			}

		}

		fingerprintName, fpExist := lookupFingerprint(thisFingerprint, fingerprintDBNew)
		output.fingerprintName = fingerprintName

		if fpExist {
			log.Printf("Client Fingerprint: %v\n", fingerprintName)
		} else {
			// Add the fingerprint
			tempFPCounter++
			thisFingerprint.desc = "Temp fingerprint " + strconv.Itoa(tempFPCounter)
			addPrintNew(thisFingerprint, fingerprintDBNew)

			log.Printf("Unidentified client fingerprint.\n")

			log.Printf("New Fingerprint added to: %v\n", globalConfig.NewFPFile)

			// Add to the new fingerprints file
			fmt.Fprintf(globalConfig.fpFile, "{\"id\": %v, \"desc\": \"%v\",  \"record_tls_version\": \"%#x\", \"tls_version\": \"%#x\",  \"ciphersuite_length\": \"%#x\",  \"ciphersuite\": \"%#x\",  \"compression_length\": \"%v\",  \"compression\": \"%#x\",  \"extensions\": \"%#x\" , \"e_curves\": \"%#x\" , \"sig_alg\": \"%#x\" , \"ec_point_fmt\": \"%#x\", \"grease\": %v }\n",
				strconv.Itoa(tempFPCounter), "Temp fingerprint connection: "+destination, thisFingerprint.recordTLSVersion,
				thisFingerprint.TLSVersion, ciphersuiteLength,
				thisFingerprint.ciphersuite, compressionMethodsLen,
				thisFingerprint.compression, thisFingerprint.extensions,
				thisFingerprint.eCurves, thisFingerprint.sigAlg,
				thisFingerprint.ecPointFmt, thisFingerprint.grease)

		}

	}
	//log.Printf("Ending tlsFingerprint function: %v", output)
	return output, thisFingerprint
}
