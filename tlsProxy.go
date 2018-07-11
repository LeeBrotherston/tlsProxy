/*
Exciting Licence Info.....

This file is part of tlsProxy.

tlsProxy is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tlsProxy is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with tlsProxy.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

tlsProxy is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

// Fingerprints can totally be converted using jq -scM ''
// WWWWHHHHHAAAAAAATTTTT?!

// G-G-G-G-GLOBAL VARS ..... probably bad.... whateevveeerrr

// Global blocklist map (temp)
var blocklist = map[string]bool{}

// Global counter for new fingerprints
var tempFPCounter int
var globalConfig userConfig

// Event structs are used to express events via the API
type Event struct {
	EventID    [32]string `json:"event_id"`
	Event      [16]string `json:"event"`
	FPHash     [64]string `json:"fp_hash"`
	IPVersion  uint8      `json:"ip_version"`
	IPDst      string     `json:"ipv4_dst"`
	IPSrc      string     `json:"ipv4_src"`
	SrcPort    uint16     `json:"src_port"`
	DstPort    uint16     `json:"dst_port"`
	TimeStamp  time.Time  `json:"timestamp"`
	TLSVersion uint16     `json:"tls_version"`
	SNI        []string   `json:"server_name"`
}

// { "timestamp": "2016-08-09 15:09:08", "event": "fingerprint_match", "ip_version": "ipv6", "ipv6_src": "2607:fea8:705f:fd86::105a", "ipv6_dst": "2607:f8b0:400b:80b::2007", "src_port": 51948, "dst_port": 443, "tls_version": "TLSv1.2", "fingerprint_desc": "Chrome 51.0.2704.84 6", "server_name": "chatenabled.mail.google.com" }

func main() {
	// Check commandline config options
	var blocklistFile = flag.String("blocklist", "./blocklist", "the blocklist file")
	var fpJSON = flag.String("fingerprint", "./tlsproxy.json", "the fingerprint file")
	var listenAddress = flag.String("listen", "127.0.0.1:8080", "address for proxy to listen to")
	var config = flag.String("config", "./config.json", "location of config file")
	var interfaceName = flag.String("interface", "", "Specify the interface")
	var sniff = flag.Bool("sniff", false, "Set true to use sniffing mode (default proxy)")
	flag.Parse()

	//var appLog *os.File	// Alternative output for log.thing

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

	if *sniff == true {
		// Interface set, let's sniff
		doSniff(*interfaceName, fingerprintDB)

	} else {
		// No interface set for sniffing, so we're listening
		listener, err := net.Listen("tcp", *listenAddress)
		if err != nil {
			log.Fatalf("Failed to setup listener: %v", err)
			os.Exit(1)
		}

		// Open event log and set as output
		globalConfig.apFile, err = os.OpenFile(globalConfig.AppLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		check(err)
		defer globalConfig.apFile.Close()

		log.SetOutput(globalConfig.apFile)

		// Open the file to write new fingerprints to
		globalConfig.fpFile, err = os.OpenFile(globalConfig.NewFPFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		check(err)
		defer globalConfig.fpFile.Close()

		// Open the file to write event output
		globalConfig.eventFile, err = os.OpenFile(globalConfig.EventLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		check(err)
		defer globalConfig.eventFile.Close()

		for {
			log.Printf("Listener for loooooooop")
			conn, err := listener.Accept()
			if err != nil {
				log.Fatalf("ERROR: failed to accept listener: %v", err)
				os.Exit(1)
			}
			go forward(conn, fingerprintDB)
		}

	}

}
