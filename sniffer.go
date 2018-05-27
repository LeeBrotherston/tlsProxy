package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func doSniff(device string, fingerprintDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) {
	var snaplen int32
	var promisc bool

	snaplen = 0
	promisc = true

	// Open device
	handle, err := pcap.OpenLive(device, snaplen, promisc, pcap.BlockForever)
	check(err)
	// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
	err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
	check(err)
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		payload := packet.ApplicationLayer()
		fingerprintOutput := tlsFingerprint(payload.Payload(), "", fingerprintDB)
		fmt.Println(fingerprintOutput)
	}

}
