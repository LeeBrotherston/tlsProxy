// Copyright (c) 2017, Lee Brotherston <lee@squarelemon.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the <organization> nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Fingerprints can totally be converted using jq -scM ''
// WWWWHHHHHAAAAAAATTTTT?!



type userConfig struct {
	MinTLS		string	`json:"min_TLS_ver"`
	Timeout		int64	`json:"timeout"`
	AppLog		string	`json:"appLog"`
	NewFPFile	string	`json:"new_fingerprint_file"`
	fpFile		*os.File	// Accompanying file descriptor
	EventLog	string	`json:"eventLog"`
	eventFile	*os.File	// Accompanying file descriptor
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
	id					float64 //`json:"id"`
	desc				string  //`json:"desc"`
	recordTLSVersion	[]byte  //`json:"record_tls_version"`
	TLSVersion			[]byte  //`json:"tls_version"`
	ciphersuite			[]byte  //`json:"ciphersuite"`
	compression			[]byte  //`json:"compression"`
	extensions			[]byte  //`json:"extensions"`
	eCurves				[]byte  //`json:"e_curves"`
	sigAlg				[]byte  //`json:"sig_alg"`
	ecPointFmt			[]byte  //`json:"ec_point_fmt"`
	grease				bool
}


// G-G-G-G-GLOBAL VARS ..... probably bad.... whateevveeerrr

// Global blocklist map (temp)
var blocklist = map[string]bool{}

// Global counter for new fingerprints
var tempFPCounter int
var globalConfig userConfig
	// { "timestamp": "2016-08-09 15:09:08", "event": "fingerprint_match", "ip_version": "ipv6", "ipv6_src": "2607:fea8:705f:fd86::105a", "ipv6_dst": "2607:f8b0:400b:80b::2007", "src_port": 51948, "dst_port": 443, "tls_version": "TLSv1.2", "fingerprint_desc": "Chrome 51.0.2704.84 6", "server_name": "chatenabled.mail.google.com" }




func check(e error) {
    if e != nil {
        panic(e)
    }
}

// StrToByte is for converting 0x00 to byte slice
func StrToByte(s string) []byte {
	var output []byte
	something := strings.Split(s, " ")

	for arse, stuff := range something {
		temp, _ := hex.DecodeString(strings.TrimLeft(stuff, "0x"))
		output = append(output, temp[0])
		fmt.Printf("%q\n", arse)
	}

	return output
}

// HexNormalise is for converting 0x00 to 00FFAABB44, etc.  Also yes normalise, English :)
func HexNormalise(s string) string {
	var output string
	something := strings.Split(s, " ")

	for _, stuff := range something {
		if len(stuff) > 2 && stuff[0:2] == "0x" {
			temp := stuff[2:]
			output = output + string(temp)
		} else {
 			output = s
		}
	}

	return strings.ToLower(output)
}

// UnpadStr removes pairs of '15' at even spacing from a str
func UnpadStr(s string) string {
	var output string
	var i = 0

	for ; i < len(s); i += 2 {
		if s[i] == 0x31 && s[i+1] == 0x35 {
			fmt.Printf("Unpadding...\n")
		} else {
			output = output + string(s[i]) + string(s[i+1])
		}
	}
	return output
}

// deGrease will remove grease from the provided input and will return the
// number of times it was degreased as well as the degreased bytes
func deGrease(s []byte) (int, []byte) {
	// Grease values (which are actually doubled)
	greaseValues := map[uint8]bool{
		0x0A: true,
		0x1A: true,
		0x2A: true,
		0x3A: true,
		0x4A: true,
		0x5A: true,
		0x6A: true,
		0x7A: true,
		0x8A: true,
		0x9A: true,
		0xAA: true,
		0xBA: true,
		0xCA: true,
		0xDA: true,
		0xEA: true,
		0xFA: true,
	}

	greaseCount := 0;
	for count := 0 ; count < len(s) ; count += 2 {
		if s[count] == s[count+1] {
			// So it's a duplicate, but is it the *right* duplicate?!
			if greaseValues[s[count]] {
				greaseCount ++
			}
		}
	}

	// OK let's construct the new version of the string (if needed)
	// did not do this above on the assumption that this is rare'ish
	// and so constructing after is more resource-efficient
	greaseless := make([]byte, len(s) - (greaseCount * 2))

	if greaseCount > 0 {
		// count is safe to reuse now
		x := 0
		for count := 0 ; count < len(s) ; count +=2 {
			if s[count] == s[count+1] {
				if greaseValues[s[count]] {
					// Nothing right now
				} else {
					greaseless[x] = s[count]
					greaseless[x+1] = s[count+1]
					x +=2
				}
			} else {
				greaseless[x] = s[count]
				greaseless[x+1] = s[count+1]
				x +=2
			}
		}
		return greaseCount, greaseless
	}
	return 0, s
}

// forward handles an individual connection
func forward(conn net.Conn, fingerprintDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) {

	destination := ""
	proxyDest := ""
	buf := make([]byte, 1024)
	var chLen uint16

	var sessionIDLength byte
	var ciphersuiteLength uint16
	var i uint16

	var thisFingerprint fingerprint

	// Loop until the destination is determined, then connect to it
	// XXX does not account for getting stuck in a shitty loop pre-connect
	// Need to de-loop this
	for destination == "" {
		// Grab some data in the buffer
		reqLen, err := conn.Read(buf)

		if err != nil {
			// Most likely an EOF because something disconnected.
			fmt.Println("Error reading a socket: ", err.Error())
			// There has been an error, let's kill this
			conn.Close()
			return
		}

		if strings.Compare(string(buf[0:7]), "CONNECT") == 0 {
			// Test for "CONNECT" type proxies
			// For now we wil blindly accept and move on to the next packet
			proxyHost := strings.SplitN(string(buf[8:]), ":", 2)[0]
			proxyPort := strings.SplitN(string(buf[9+len(proxyHost):]), " ", 2)[0]

			// Connection close is (for now), to prevent reuse, it makes it all
			// so much easier
			conn.Write([]byte("HTTP/1.1 200 OK\nConnection: close\n\n"))
			proxyDest = proxyHost + ":" + proxyPort

			// XXX fill buffer here and continue instead of the loop
			//reqLen, err = conn.Read(buf)

		} else if buf[0] == 0x05 && (buf[1] == (byte)(reqLen-0x2)) {
			// Testing for a SOCKS proxy connection
			// buf[0] == VERSION .. 0x5 is socks 5
			// buf[1] == The length of auth types
			//log.Printf("SOCKS5\n")

			// Hey, we're developing, let's go for no auth for now
			response := make([]byte, 2)
			response[0] = 0x05
			response[1] = 0x00
			conn.Write([]byte(response))

			//reqLen, err = conn.Read(buf)
			_, err = conn.Read(buf)


			if buf[0] == 0x05 && buf[1] == 0x01 && buf[2] == 0x00 {
				// buf[0] == 0x05 socks version
				// buf[1] == 0x01 make a TCP connection
				// buf[2] == 0x00 reserved byte, must be zero
				if buf[3] == 0x01 {
					// IPv4
					proxyHost := string(net.IP.String(buf[4:8]))
					proxyPort := int((uint64(buf[8]) * 256) + uint64(buf[9]))
					proxyDest = string(proxyHost) + string(":") + strconv.Itoa(proxyPort)

					//log.Printf("SOCKS5 IPv4 dest: %s : %v\n", proxyHost, proxyPort)

					// Craft up a SOCKS response, which is almost the request
					response := make([]byte, 10)
					response[0] = 0x05 // version
					response[1] = 0x00 // status (0x00 == granted)
					response[2] = 0x00 // reserved, must be 0x00
					response[3] = 0x01 // address type, 0x01 == IPv4
					copy(response[3:9], buf[3:9])
					conn.Write([]byte(response))

				} else if buf[3] == 0x03 {
					// FQDN
					// buf[4] is the length buf[5] is the start of the FQDN

					proxyHost := buf[5 : buf[4]+5]
					proxyPort := int((uint64(buf[buf[4]+5]) * 256) + uint64(buf[buf[4]+6]))
					proxyDest = string(proxyHost) + string(":") + strconv.Itoa(proxyPort)

					//log.Printf("SOCKS5 FQDN: %s : %v\n", proxyHost, proxyPort)
					//log.Printf("SOCKS5 DEBUG: %v %v\n", buf[buf[4]+5], buf[buf[4]+6])

					// Craft a response
					response := make([]byte, (7 + buf[4]))
					response[0] = 0x05                          // version
					response[1] = 0x00                          // status (0x00 == granted)
					response[2] = 0x00                          // reserved, must be 0x00
					response[3] = 0x03                          // address type, 0x03 == Domain name
					response[4] = buf[4]                        // Length of FQDN
					copy(response[5:buf[4]+5], buf[5:buf[4]+5]) // Copy FQDN
					response[buf[4]+5] = buf[buf[4]+5]          // proxyPort
					response[buf[4]+6] = buf[buf[4]+6]          // proxyPort

					conn.Write([]byte(response))

				} else if buf[3] == 0x04 {
					// IPv6
					proxyHost := string(net.IP.String(buf[4:20]))
					//log.Printf("SOCKS5 IPv6 dest: %s\n", proxyHost)

					proxyPort := int((uint64(buf[20]) * 256) + uint64(buf[21]))
					proxyDest = "[" + string(proxyHost) + string("]:") + strconv.Itoa(proxyPort)

					// Craft up a SOCKS response, which is almost the request
					response := make([]byte, 22)
					response[0] = 0x05 // version
					response[1] = 0x00 // status (0x00 == granted)
					response[2] = 0x00 // reserved, must be 0x00
					response[3] = 0x01 // address type, 0x01 == IPv4
					copy(response[3:21], buf[3:21])

					conn.Write([]byte(response))

				} else {
					// Not valid (or supported) socks request
					log.Printf("Problem: Well that doesn't seem to be SOCKS\n")
					conn.Close()
				}

			} else {
				// Not a valid SOCK5 request
			}

		} else if buf[0] == 22 && buf[5] == 1 && buf[1] == 3 && buf[9] == 3 {
			// This is the Lee acid test for is this a TLS client hello packet
			// The "science" behind it is here:
			// https://speakerdeck.com/leebrotherston/stealthier-attacks-and-smarter-defending-with-tls-fingerprinting?slide=31

			// buf[0] == TLS Handshake
			// buf[5] == Client Hello
			// buf[1] == Record TLS Version
			// buf[9] == TLS Version

			// Sweet, looks like a client hello, let's do some pre-processing

			thisFingerprint.recordTLSVersion = make([]byte, 2)
			copy(thisFingerprint.recordTLSVersion, buf[1:3])
			//thisFingerprint.recordTLSVersion[0] = buf[1]
			//thisFingerprint.recordTLSVersion[1] = buf[2]

			chLen = uint16(buf[3])<<8 + uint16(buf[4])

			thisFingerprint.TLSVersion = make([]byte, 2)
			copy(thisFingerprint.TLSVersion, buf[9:11])
			//thisFingerprint.TLSVersion[0] = buf[9]
			//thisFingerprint.TLSVersion[1] = buf[10]

			// Length of the session id changes to offset for the next bits
			sessionIDLength = buf[43]

			// ciphersuite Length also determines some offsets
			// This doesn't feel like a very GO'y way of doing this!
			ciphersuiteLength = uint16(buf[44+sessionIDLength]) << 8
			ciphersuiteLength += uint16(buf[45+sessionIDLength])

			// OK let's get dem ciphersuites, yo...
			tempCiphersuite := make([]byte, uint16(ciphersuiteLength))
			if (uint16(copy(tempCiphersuite, buf[(46+uint16(sessionIDLength)):(46+uint16(sessionIDLength)+ciphersuiteLength)])) != ciphersuiteLength) {
				log.Printf("Debug: Ciphersuite copy lengths seem wrong\n")
			}

			// Get degreasing info
			shrinkBy, otherTempCiphersuite := deGrease(tempCiphersuite)
			if shrinkBy > 0 {
				thisFingerprint.grease = true
			}

			greaseCiphersuiteLength := ciphersuiteLength - uint16(shrinkBy * 2)
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
					// Lets not add grease the extension list....
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
					if ( uint16(buf[offset+i+2])<<8 + uint16(buf[offset+i+3]) ) != (extLength - 2) {
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

					hostnameLength := (uint16(buf[offset+i+5])<<8 + uint16(buf[offset+i+6]))

					hostname := make([]byte, hostnameLength)

					if hostnameLength != uint16(copy(hostname, buf[offset+i+7:offset+i+7+hostnameLength])) {
						log.Printf("Problem: failed to copy hostname\n")
					}

					destination = string(hostname) + ":" + "443"

					// XXX This is to get around transparent proxies where this isn't already set.
					// Will make this neater in future
					proxyDest = destination


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
					greaseeCurvesLength := ellipticCurvesLength - uint16(shrinkBy * 2)

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
						log.Printf("Problem: failed to copy sigAlg\n");
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

			fingerprintName, fpExist := fingerprintDB[hex.EncodeToString(thisFingerprint.recordTLSVersion)][hex.EncodeToString(thisFingerprint.TLSVersion)][hex.EncodeToString(thisFingerprint.ciphersuite)][hex.EncodeToString(thisFingerprint.compression)][UnpadStr(hex.EncodeToString(thisFingerprint.extensions))][hex.EncodeToString(thisFingerprint.eCurves)][hex.EncodeToString(thisFingerprint.sigAlg)][hex.EncodeToString(thisFingerprint.ecPointFmt)][bool(thisFingerprint.grease)]

			if fpExist {
				log.Printf("Client Fingerprint: %v\n", fingerprintName)
			} else {
				// Add the fingerprint
				thisFingerprint.desc = "Temp fingerprint "+strconv.Itoa(tempFPCounter)
				tempFPCounter ++
				addPrintInt(thisFingerprint, fingerprintDB)

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

			// Check if the host is in the blocklist or not...
			t := time.Now()
			hostname := string(strings.SplitN(destination, ":", 2)[0])
			_, ok := blocklist[hostname]
			if ok == true {
				log.Printf("%v is on the blocklist!  DROPPING!\n", hostname)
				fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"block\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintName, hostname)
				conn.Close()
			} else {
				// Not on the blocklist - woo!
				// XXX DO THIS!
				log.Printf("%v is *not* on the blocklist.  Permitting\n", hostname)
			}

		} else {
			defer conn.Close()
			//log.Printf("%s Disconnected\n", conn.RemoteAddr())
			return
		}

	}

	// OK Destination is determined, let's do some connecting!
	client, err := net.DialTimeout("tcp", proxyDest, time.Duration(globalConfig.Timeout))

	if err != nil {
		// Could not connect, burn it all down!!!
		defer conn.Close()
		log.Printf("Dial to '%v' failed: %v", proxyDest, err)
		return
	}

	// Actually route some packets (ok proxy them), yo!
	// ... and transmit the buffer that we already processed (or a reconstructed one)
	client.Write(buf[0 : chLen+5])

	// Default buffer is 32K...  This lets us play with different sizes
	forwardBuf := make([]byte, 65535)

	go func() {
		defer client.Close()
		defer conn.Close()
		//log.Printf("Packet: %x", client)
		io.CopyBuffer(client, conn, forwardBuf)

	}()
	go func() {
		defer client.Close()
		defer conn.Close()
		io.CopyBuffer(conn, client, forwardBuf)

	}()

}

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

func main() {
	// Check commandline config options
	var blocklistFile = flag.String("blocklist", "./blocklist", "the blocklist file")
	var fpJSON = flag.String("fingerprint", "./tlsproxy.json", "the fingerprint file")
	var listenAddress = flag.String("listen", "127.0.0.1:8080", "address for proxy to listen to")
	var config = flag.String("config", "./config.json", "location of config file")
	//var reverseCfg = flag.String("reversecfg", "./reverse", "file storing reverse proxy config")
	flag.Parse()

	var appLog *os.File	// Alternative output for log.thing

	// Open 'blocklist' file - bad bad hardcoded Lee XXX
	f, err := os.Open(*blocklistFile)

	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		blocklist[string(scanner.Text())] = true
	}

	check(err)

	log.Printf("Loaded %v blocklist items\n", len(blocklist))

	// Open JSON file tlsproxy.json
	file, err := ioutil.ReadFile(*fpJSON)
	if err != nil {
		log.Printf("Problem: File error opening fingerprint file: %v\n", err)
		log.Printf("You may wish to try: cat fingerprints.json | jq -scM '' > tlsProxy.json to update\n")
		os.Exit(1)
	}

	// Parse that JSON file
	var jsontype []fingerprintFile
	err = json.Unmarshal(file, &jsontype)
	if err != nil {
		log.Fatalf("JSON error: %v", err)
		os.Exit(1)
	}

	// Create the bare fingerprintDB map structure
	fingerprintDB := make(map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string)


	// populate the fingerprintDB map
	for k := range jsontype {
		addPrint(jsontype[k], fingerprintDB)
	}

	log.Printf("Loaded %v fingerprints\n", len(jsontype))

	// Load the config file config.json
	// Open JSON file
	fileConfig, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Printf("Problem: File error opening config file: %v\n", err)
		os.Exit(1)
	}

	// Parse that JSON file
	err = json.Unmarshal(fileConfig, &globalConfig)
	if err != nil {
		log.Fatalf("JSON error: %v", err)
		os.Exit(1)
	}

	// Set temp FP counter past the number of FP's ... maybe ?!
	tempFPCounter = int(len(jsontype)) + 1

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("Failed to setup listener: %v", err)
		os.Exit(1)
	}

	// Open event log and set as output
	appLog, err = os.OpenFile(globalConfig.AppLog, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	check(err)
	defer appLog.Close()

	log.SetOutput(appLog)


	// Open the file to write new fingerprints to
	globalConfig.fpFile, err = os.OpenFile(globalConfig.NewFPFile, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	check(err)
	defer globalConfig.fpFile.Close()

	// Open the file to write event output
	globalConfig.eventFile, err = os.OpenFile(globalConfig.EventLog, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	check(err)
	defer globalConfig.eventFile.Close()


	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("ERROR: failed to accept listener: %v", err)
			os.Exit(1)
		}
		go forward(conn, fingerprintDB)
	}

}