package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// forward handles an individual connection
func forward(conn net.Conn, fingerprintDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) {

	buf := make([]byte, 1024)
	proxyDest := ""
	var destination []byte
	var chLen uint16

	log.Printf("Starting forward function")
	// Loop until the destination is determined, then connect to it
	// XXX does not account for getting stuck in a shitty loop pre-connect
	// Need to de-loop this
	for len(destination) == 0 {
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
			log.Printf("SOCKS5\n")

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

					log.Printf("SOCKS5 IPv4 dest: %s : %v\n", proxyHost, proxyPort)

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

					log.Printf("SOCKS5 FQDN: %s : %v\n", proxyHost, proxyPort)
					log.Printf("SOCKS5 DEBUG: %v %v\n", buf[buf[4]+5], buf[buf[4]+6])

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
					log.Printf("SOCKS5 IPv6 dest: %s\n", proxyHost)

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
			log.Printf("About to call tlsFingerprint")
			fingerprintOutput, _ := tlsFingerprint(buf, proxyDest, fingerprintDB)
			log.Printf("Fingerptintoutoutoutout: %v", fingerprintOutput)
			destination = fingerprintOutput.destination
			chLen = uint16(buf[3])<<8 + uint16(buf[4])
			// Check if the host is in the blocklist or not...
			t := time.Now()
			hostname := string(strings.SplitN(string(destination), ":", 2)[0])
			_, ok := blocklist[hostname]
			if ok == true {
				log.Printf("%v is on the blocklist!  DROPPING!\n", hostname)
				fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"block\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.fingerprintName, hostname)
				conn.Close()
			} else {
				// Not on the blocklist - woo!
				// XXX DO THIS!
				log.Printf("%v is *not* on the blocklist.  Permitting\n", hostname)
				fmt.Fprintf(globalConfig.eventFile, "{ \"timestamp\": \"%v\", \"event\": \"permit\", \"fingerprint_desc\": \"%v\", \"server_name\": \"%v\" }\n", t.Format(time.RFC3339), fingerprintOutput.fingerprintName, hostname)
			}

		} else {
			defer conn.Close()
			//log.Printf("%s Disconnected\n", conn.RemoteAddr())
			return
		}
		log.Printf("Say what? %v - %v", destination, proxyDest)
	}

	log.Printf("Time to connect?")
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
		io.CopyBuffer(client, conn, forwardBuf)

	}()
	go func() {
		defer client.Close()
		defer conn.Close()
		io.CopyBuffer(conn, client, forwardBuf)

	}()

}
