package main

import (
	"encoding/binary"
	"encoding/json"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func doSniff(device string, fingerprintDB map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[string]map[bool]string) {

	// Open device
	// the 0 and true refer to snaplen and promisc mode.  For now we always want these.
	handle, err := pcap.OpenLive(device, 0, true, pcap.BlockForever)
	check(err)
	// Yes yes, I know... But offsetting this to the kernel *drastically* reduces processing time
	err = handle.SetBPFFilter("(tcp[tcp[12]/16*4]=22 and (tcp[tcp[12]/16*4+5]=1) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)) or (ip6[(ip6[52]/16*4)+40]=22 and (ip6[(ip6[52]/16*4+5)+40]=1) and (ip6[(ip6[52]/16*4+9)+40]=3) and (ip6[(ip6[52]/16*4+1)+40]=3)) or ((udp[14] = 6 and udp[16] = 32 and udp[17] = 1) and ((udp[(udp[60]/16*4)+48]=22) and (udp[(udp[60]/16*4)+53]=1) and (udp[(udp[60]/16*4)+57]=3) and (udp[(udp[60]/16*4)+49]=3))) or (proto 41 and ip[26] = 6 and ip[(ip[72]/16*4)+60]=22 and (ip[(ip[72]/16*4+5)+60]=1) and (ip[(ip[72]/16*4+9)+60]=3) and (ip[(ip[72]/16*4+1)+60]=3))")
	check(err)
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Use netflow to obtain source and dest.  This will be useful in the future when tracking
		// data in multiple directinos
		netFlow := packet.NetworkLayer().NetworkFlow()
		src, dst := netFlow.Endpoints()

		// Locate the payload to send the the tlsFingerprint() function
		payload := packet.ApplicationLayer()
		fingerprintOutput, thatFingerprint := tlsFingerprint(payload.Payload(), "", fingerprintDB)

		// Populate an event struct
		var event Event

		// Because netflow is set to network layer src and dst will be IP addresses
		src, dst = netFlow.Endpoints()
		event.IPSrc = src.String()
		event.IPDst = dst.String()

		event.TimeStamp = packet.Metadata().Timestamp

		// Decode the TCP layer
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)

		event.SrcPort = uint16(tcp.SrcPort)
		event.DstPort = uint16(tcp.DstPort)

		event.IPVersion = src.EndpointType().String()

		event.SNI = string(fingerprintOutput.hostname)

		event.Event = "log"

		event.TLSVersion = binary.BigEndian.Uint16(thatFingerprint.TLSVersion)
		//event.Fingerprint = thatFingerprint
		//event.Fingerprint, _ = json.Marshal(thatFingerprint)
		//log.Printf("Debug output: %+v\n", event)

		jsonOut, _ := json.Marshal(event)

		// Some output....
		log.Printf("%s -> %s : %s : %s", src, dst, fingerprintOutput.fingerprintName, jsonOut)
	}

}

//////
// Event structs are used to express events via the API
/*type Event struct {
EventID    [32]string `json:"event_id"`
Event      [16]string `json:"event"`
FPHash     [64]string `json:"fp_hash"`
//IPVersion  uint8      `json:"ip_version"`
//IPv4Dst    [15]string `json:"ipv4_dst"`
//IPv4Src    [15]string `json:"ipv4_src"`
//IPv6Src    [39]string `json:"ipvt_src"`
//IPv6Dst    [39]string `json:"ipvt_dst"`
//SrcPort    uint16     `json:"src_port"`
//DstPort    uint16     `json:"dst_port"`
//TimeStamp  time.Time  `json:"timestamp"`
//TLSVersion uint16     `json:"tls_version"`
//SNI        []string   `json:"server_name"`
*/
